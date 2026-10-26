use bytes::Buf;
use futures_util::future;
use http::{HeaderMap, Response};
use quic::StreamId;
#[cfg(feature = "tracing")]
use tracing::instrument;

use crate::{
    connection::{self},
    error::{
        connection_error_creators::{CloseStream, HandleFrameStreamErrorOnRequestStream},
        internal_error::InternalConnectionError,
        Code, StreamError,
    },
    proto::{frame::Frame, headers::Header},
    qpack,
    quic::{self},
    shared_state::{ConnectionState, SharedState},
    unbound::{Guard, Unbound},
};
use std::{
    convert::TryFrom,
    task::{Context, Poll},
};

/// Manage request bodies transfer, response and trailers.
///
/// Once a request has been sent via [`crate::client::SendRequest::send_request()`], a response can be awaited by calling
/// [`RequestStream::recv_response()`]. A body for this request can be sent with [`RequestStream::send_data()`], then the request
/// shall be completed by either sending trailers with  [`RequestStream::finish()`].
///
/// After receiving the response's headers, it's body can be read by [`RequestStream::recv_data()`] until it returns
/// `None`. Then the trailers will eventually be available via [`RequestStream::recv_trailers()`].
///
/// TODO: If data is polled before the response has been received, an error will be thrown.
///
/// TODO: If trailers are polled but the body hasn't been fully received, an UNEXPECT_FRAME error will be
/// thrown
///
/// Whenever the client wants to cancel this request, it can call [`RequestStream::stop_sending()`], which will
/// put an end to any transfer concerning it.
///
/// # Examples
///
/// ```rust
/// # use h3::{quic, client::*};
/// # use http::{Request, Response};
/// # use bytes::Buf;
/// # use tokio::io::AsyncWriteExt;
/// # async fn doc<T,B>(mut req_stream: RequestStream<T, B>) -> Result<(), Box<dyn std::error::Error>>
/// # where
/// #     T: quic::RecvStream,
/// # {
/// // Prepare the HTTP request to send to the server
/// let request = Request::get("https://www.example.com/").body(())?;
///
/// // Receive the response
/// let response = req_stream.recv_response().await?;
/// // Receive the body
/// while let Some(mut chunk) = req_stream.recv_data().await? {
///     let mut out = tokio::io::stdout();
///     out.write_all_buf(&mut chunk).await?;
///     out.flush().await?;
/// }
/// # Ok(())
/// # }
/// # pub fn main() {}
/// ```
///
/// [`send_request()`]: struct.SendRequest.html#method.send_request
/// [`recv_response()`]: #method.recv_response
/// [`recv_data()`]: #method.recv_data
/// [`send_data()`]: #method.send_data
/// [`send_trailers()`]: #method.send_trailers
/// [`recv_trailers()`]: #method.recv_trailers
/// [`finish()`]: #method.finish
/// [`stop_sending()`]: #method.stop_sending
pub struct RequestStream<S, B> {
    pub(super) inner: connection::RequestStream<S, B>,
}

impl<S, B> ConnectionState for RequestStream<S, B> {
    fn shared_state(&self) -> &SharedState {
        &self.inner.conn_state
    }
}

impl<S, B> CloseStream for RequestStream<S, B> {}

impl<S, B> RequestStream<S, B>
where
    S: quic::RecvStream,
{
    /// Receive the HTTP/3 response
    ///
    /// This should be called before trying to receive any data with [`recv_data()`].
    ///
    /// [`recv_data()`]: #method.recv_data
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn recv_response(&mut self) -> Result<Response<()>, StreamError> {
        let mut frame = future::poll_fn(|cx| self.inner.stream.poll_next(cx))
            .await
            .map_err(|e| self.handle_frame_stream_error_on_request_stream(e))?
            .ok_or_else(|| {
                //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
                //# Receipt of an invalid sequence of frames MUST be treated as a
                //# connection error of type H3_FRAME_UNEXPECTED.
                self.handle_connection_error_on_stream(InternalConnectionError::new(
                    Code::H3_FRAME_UNEXPECTED,
                    "Stream finished without receiving response headers".to_string(),
                ))
            })?;

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
        //= type=TODO
        //# A client MUST treat
        //# receipt of a PUSH_PROMISE frame that contains a larger push ID than
        //# the client has advertised as a connection error of H3_ID_ERROR.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
        //= type=TODO
        //# If a client
        //# receives a push ID that has already been promised and detects a
        //# mismatch, it MUST respond with a connection error of type
        //# H3_GENERAL_PROTOCOL_ERROR.

        let decoded = if let Frame::Headers(ref mut encoded) = frame {
            match qpack::decode_stateless(encoded, self.inner.max_field_section_size) {
                //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
                //# An HTTP/3 implementation MAY impose a limit on the maximum size of
                //# the message header it will accept on an individual HTTP message.
                Err(qpack::DecoderError::HeaderTooLong(cancel_size)) => {
                    self.inner.stop_sending(Code::H3_REQUEST_CANCELLED);
                    return Err(StreamError::HeaderTooBig {
                        actual_size: cancel_size,
                        max_size: self.inner.max_field_section_size,
                    });
                }
                Ok(decoded) => decoded,
                Err(_e) => {
                    return Err(
                        self.handle_connection_error_on_stream(InternalConnectionError {
                            code: Code::QPACK_DECOMPRESSION_FAILED,
                            message: "Failed to decode headers".to_string(),
                        }),
                    )
                }
            }
        } else {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
            //# Receipt of an invalid sequence of frames MUST be treated as a
            //# connection error of type H3_FRAME_UNEXPECTED.

            return Err(
                self.handle_connection_error_on_stream(InternalConnectionError::new(
                    Code::H3_FRAME_UNEXPECTED,
                    "First response frame is not headers".to_string(),
                )),
            );
        };

        let qpack::Decoded { fields, .. } = decoded;

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.2
        //# Malformed requests or responses that are
        //# detected MUST be treated as a stream error of type H3_MESSAGE_ERROR.
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.2
        //# Clients MUST NOT
        //# accept a malformed response.
        let (status, headers) = Header::try_from(fields)
            .map_err(|_e| {
                self.inner.stream.stop_sending(Code::H3_REQUEST_CANCELLED);
                StreamError::StreamError {
                    code: Code::H3_MESSAGE_ERROR,
                    reason: "Received malformed header".to_string(),
                }
            })?
            .into_response_parts()
            .map_err(|_e| {
                self.inner.stream.stop_sending(Code::H3_REQUEST_CANCELLED);
                StreamError::StreamError {
                    code: Code::H3_MESSAGE_ERROR,
                    reason: "Received malformed header".to_string(),
                }
            })?;
        let mut resp = Response::new(());
        *resp.status_mut() = status;
        *resp.headers_mut() = headers;
        *resp.version_mut() = http::Version::HTTP_3;

        Ok(resp)
    }

    /// Receive some of the response body.
    ///
    /// This returns a chunk of the response body, or `None` if the response body is finished.
    // TODO what if called before recv_response ?
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn recv_data(&mut self) -> Result<Option<impl Buf>, StreamError> {
        future::poll_fn(|cx| self.poll_recv_data(cx)).await
    }

    /// Receive some of the response body.
    ///
    /// This returns a chunk of the response body, or `None` if the response body is finished.
    pub fn poll_recv_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<impl Buf>, StreamError>> {
        self.inner.poll_recv_data(cx)
    }

    /// Receive an optional set of trailers for the response.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn recv_trailers(&mut self) -> Result<Option<HeaderMap>, StreamError> {
        future::poll_fn(|cx| self.poll_recv_trailers(cx)).await
    }

    /// Poll receive an optional set of trailers for the response.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_recv_trailers(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<HeaderMap>, StreamError>> {
        let res = self.inner.poll_recv_trailers(cx);
        if let Poll::Ready(Err(StreamError::HeaderTooBig { .. })) = &res {
            self.inner.stream.stop_sending(Code::H3_REQUEST_CANCELLED);
        }
        res
    }

    /// Tell the peer to stop sending into the underlying QUIC stream
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn stop_sending(&mut self, error_code: Code) {
        // TODO take by value to prevent any further call as this request is cancelled
        // rename `cancel()` ?
        self.inner.stream.stop_sending(error_code)
    }

    /// Returns the underlying stream id
    pub fn id(&self) -> StreamId {
        self.inner.stream.id()
    }

    /// Waits until the server switched its sending side to unbound tunnel data
    ///
    /// Returns as soon as the server's `UNBOUND_DATA` frame arrives; from then on
    /// [`RequestStream::recv_data`] yields plain tunnel bytes until the end of the stream.
    /// Tunnel data which arrives in the meantime is not lost: it is kept for
    /// [`RequestStream::into_unbound`], or returned by [`RequestStream::recv_data`] if the
    /// stream is not handed over.
    ///
    /// Note that a server is never obliged to send `UNBOUND_DATA`, so this can wait for as long
    /// as the tunnel lives. It also returns `Ok(())` when the server ends its sending side
    /// without ever switching, because nothing more can arrive on that direction either;
    /// [`RequestStream::is_recv_unbound`] tells the two outcomes apart.
    ///
    /// Fails immediately if this endpoint did not advertise
    /// [`enable_unbound_data`](crate::client::builder::Builder::enable_unbound_data), since a
    /// server which honours the draft will then never send the frame.
    ///
    /// See [the draft](https://datatracker.ietf.org/doc/draft-rosomakho-httpbis-h3-unbound-data/).
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn recv_unbound_data(&mut self) -> Result<(), StreamError> {
        future::poll_fn(|cx| self.inner.poll_recv_unbound(cx)).await
    }

    /// Whether the server switched its sending side to unbound tunnel data
    pub fn is_recv_unbound(&self) -> bool {
        self.inner.is_recv_unbound()
    }

    /// Hands the receiving half of an unbound CONNECT stream back to the application
    ///
    /// Like [`RequestStream::into_unbound`], but for the receiving half of a
    /// [`RequestStream::split`]: it waits for the server's `UNBOUND_DATA` and leaves this
    /// endpoint's sending direction alone, so the sending half can keep writing `DATA` frames
    /// through h3.
    pub async fn into_unbound_recv(self) -> Result<Unbound<S>, StreamError> {
        let (prefix, stream, fin_received) = self.inner.into_unbound_recv().await?;

        Ok(Unbound {
            prefix,
            stream,
            guard: Guard::none(),
            fin_received,
        })
    }
}

impl<S, B> RequestStream<S, B>
where
    S: quic::SendStream<B>,
    B: Buf,
{
    /// Send some data on the request body.
    ///
    /// Once [`RequestStream::send_unbound_data`] was called, the data is written without a `DATA`
    /// frame header.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn send_data(&mut self, buf: B) -> Result<(), StreamError> {
        self.inner.send_data(buf).await
    }

    /// Stops framing the request body and switches to unbound tunnel data
    ///
    /// Sends an `UNBOUND_DATA` frame, after which every octet this endpoint writes is tunnel data
    /// up to the QUIC FIN. [`RequestStream::send_data`] keeps working and writes the bytes with no
    /// frame header, which is what makes this worthwhile for long-lived tunnels; trailers can no
    /// longer be sent.
    ///
    /// Only CONNECT streams can be switched, and only if the server advertised
    /// `SETTINGS_ENABLE_UNBOUND_DATA`. If it did not — including when its SETTINGS frame has not
    /// arrived yet, which is likely right after the request was sent — this returns
    /// [`StreamError::UnboundDataNotNegotiated`] without writing anything, so the request can
    /// simply continue in `DATA` frames.
    ///
    /// See [the draft](https://datatracker.ietf.org/doc/draft-rosomakho-httpbis-h3-unbound-data/).
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn send_unbound_data(&mut self) -> Result<(), StreamError> {
        self.inner.send_unbound_data().await
    }

    /// Whether this endpoint switched its sending side to unbound tunnel data
    pub fn is_send_unbound(&self) -> bool {
        self.inner.is_send_unbound()
    }

    /// Hands the sending half of an unbound CONNECT stream back to the application
    ///
    /// Like [`RequestStream::into_unbound`], but for the sending half of a
    /// [`RequestStream::split`]: only this endpoint's direction has to be unbound, so the
    /// receiving half can keep reading `DATA` frames through h3.
    pub async fn into_unbound_send(self) -> Result<Unbound<S>, StreamError> {
        let (prefix, stream, fin_received) = self.inner.into_unbound_send().await?;

        Ok(Unbound {
            prefix,
            stream,
            guard: Guard::none(),
            fin_received,
        })
    }

    /// Stop a stream with an error code
    ///
    /// The code can be [`Code::H3_NO_ERROR`].
    pub fn stop_stream(&mut self, error_code: Code) {
        self.inner.stop_stream(error_code);
    }

    /// Send a set of trailers to end the request.
    ///
    /// [`RequestStream::finish()`] must be called to finalize a request.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn send_trailers(&mut self, trailers: HeaderMap) -> Result<(), StreamError> {
        self.inner.send_trailers(trailers).await
    }

    /// End the request without trailers.
    ///
    /// [`RequestStream::finish()`] must be called to finalize a request.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn finish(&mut self) -> Result<(), StreamError> {
        self.inner.finish().await
    }

    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.1
    //= type=TODO
    //# Implementations SHOULD cancel requests by abruptly terminating any
    //# directions of a stream that are still open.  To do so, an
    //# implementation resets the sending parts of streams and aborts reading
    //# on the receiving parts of streams; see Section 2.4 of
    //# [QUIC-TRANSPORT].
}

impl<S, B> RequestStream<S, B>
where
    S: quic::SendStream<B> + quic::RecvStream,
    B: Buf,
{
    /// Hands this CONNECT stream back to the application as a plain QUIC stream
    ///
    /// Switches this endpoint's sending side to unbound data if
    /// [`RequestStream::send_unbound_data`] has not been called yet, waits for the server to do
    /// the same, and then returns the stream itself: h3 stops framing, reading and writing it
    /// altogether, and the application talks to the QUIC implementation directly. With
    /// `h3-quinn`, [`Unbound::stream`] converts into `quinn::SendStream`/`quinn::RecvStream`.
    ///
    /// Two things to keep in mind:
    ///
    /// * [`Unbound::prefix`] holds tunnel data h3 had already read and must be written to the
    ///   tunnel's other end before anything read from the stream.
    /// * The client connection closes once the last [`SendRequest`](crate::client::SendRequest)
    ///   is dropped, which would tear the tunnel down; keep one alive for as long as the tunnel
    ///   is in use. [`Unbound::guard`] cannot do that on the client side.
    ///
    /// This takes the stream by value, so the stream is gone whichever way this ends: dropping
    /// the returned future — a `select!` timeout, for instance — resets the request stream, and
    /// so does an error, including
    /// [`StreamError::UnboundDataNotNegotiated`](crate::error::StreamError::UnboundDataNotNegotiated).
    /// Call [`RequestStream::send_unbound_data`] and [`RequestStream::recv_unbound_data`] first
    /// if the wait needs to be cancellable, or if falling back to `DATA` frames when the server
    /// does not support the extension matters.
    ///
    /// See [the draft](https://datatracker.ietf.org/doc/draft-rosomakho-httpbis-h3-unbound-data/).
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn into_unbound(self) -> Result<Unbound<S>, StreamError> {
        let (prefix, stream, fin_received) = self.inner.into_unbound().await?;

        Ok(Unbound {
            prefix,
            stream,
            guard: Guard::none(),
            fin_received,
        })
    }
}

impl<S, B> RequestStream<S, B>
where
    S: quic::BidiStream<B>,
    B: Buf,
{
    /// Split this stream into two halves that can be driven independently.
    pub fn split(
        self,
    ) -> (
        RequestStream<S::SendStream, B>,
        RequestStream<S::RecvStream, B>,
    ) {
        let (send, recv) = self.inner.split();
        (RequestStream { inner: send }, RequestStream { inner: recv })
    }
}
