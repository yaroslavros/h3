//! Server-side HTTP/3 stream management

use bytes::Buf;

use crate::{
    error::{
        connection_error_creators::CloseStream, internal_error::InternalConnectionError, Code,
        StreamError,
    },
    quic::{self},
    shared_state::{ConnectionState, SharedState},
    unbound::{Guard, Unbound},
};

use super::connection::RequestEnd;
use std::sync::Arc;

use std::{
    option::Option,
    result::Result,
    task::{Context, Poll},
};

use bytes::BytesMut;
use futures_util::future;
use http::{response, HeaderMap, Response};

use quic::StreamId;

use crate::{
    proto::{frame::Frame, headers::Header},
    qpack,
    quic::SendStream as _,
    stream::{self},
};

#[cfg(feature = "tracing")]
use tracing::{error, instrument};

/// Manage request and response transfer for an incoming request
///
/// The [`RequestStream`] struct is used to send and/or receive
/// information from the client.
/// After sending the final response, call [`RequestStream::finish`] to close the stream.
pub struct RequestStream<S, B> {
    pub(super) inner: crate::connection::RequestStream<S, B>,
    pub(super) request_end: Arc<RequestEnd>,
}

impl<S, B> AsMut<crate::connection::RequestStream<S, B>> for RequestStream<S, B> {
    fn as_mut(&mut self) -> &mut crate::connection::RequestStream<S, B> {
        &mut self.inner
    }
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
    B: Buf,
{
    /// Receive data sent from the client.
    ///
    /// This returns a chunk of the request body, or `None` if the request body is finished.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn recv_data(&mut self) -> Result<Option<impl Buf>, StreamError> {
        future::poll_fn(|cx| self.poll_recv_data(cx)).await
    }

    /// Poll for data sent from the client.
    ///
    /// This returns a chunk of the request body, or `None` if the request body is finished.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_recv_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<impl Buf>, StreamError>> {
        self.inner.poll_recv_data(cx)
    }

    /// Receive an optional set of trailers for the request
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn recv_trailers(&mut self) -> Result<Option<HeaderMap>, StreamError> {
        future::poll_fn(|cx| self.poll_recv_trailers(cx)).await
    }

    /// Poll for an optional set of trailers for the request
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_recv_trailers(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<HeaderMap>, StreamError>> {
        self.inner.poll_recv_trailers(cx)
    }

    /// Tell the peer to stop sending into the underlying QUIC stream
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn stop_sending(&mut self, error_code: Code) {
        self.inner.stream.stop_sending(error_code)
    }

    /// Returns the underlying stream id
    pub fn id(&self) -> StreamId {
        self.inner.stream.id()
    }

    /// Check if this stream was opened during 0-RTT.
    ///
    /// See [RFC 8470 Section 5.2](https://www.rfc-editor.org/rfc/rfc8470.html#section-5.2).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use h3::server::RequestStream;
    /// # async fn example(mut stream: RequestStream<impl h3::quic::BidiStream<bytes::Bytes> + h3::quic::Is0rtt, bytes::Bytes>) {
    /// if stream.is_0rtt() {
    ///     // Reject non-idempotent methods (e.g., POST, PUT, DELETE)
    ///     // to prevent replay attacks
    /// }
    /// # }
    /// ```
    pub fn is_0rtt(&self) -> bool
    where
        S: quic::Is0rtt,
    {
        self.inner.stream.is_0rtt()
    }

    /// Waits until the client switched its sending side to unbound tunnel data
    ///
    /// Returns as soon as the client's `UNBOUND_DATA` frame arrives; from then on
    /// [`RequestStream::recv_data`] yields plain tunnel bytes until the end of the stream.
    /// Tunnel data which arrives in the meantime is not lost: it is kept for
    /// [`RequestStream::into_unbound`], or returned by [`RequestStream::recv_data`] if the
    /// stream is not handed over.
    ///
    /// Note that a client is never obliged to send `UNBOUND_DATA`, so this can wait for as long
    /// as the tunnel lives. It also returns `Ok(())` when the client ends its sending side
    /// without ever switching, because nothing more can arrive on that direction either;
    /// [`RequestStream::is_recv_unbound`] tells the two outcomes apart.
    ///
    /// Fails immediately if this endpoint did not advertise
    /// [`enable_unbound_data`](crate::server::builder::Builder::enable_unbound_data), since a
    /// client which honours the draft will then never send the frame.
    ///
    /// See [the draft](https://datatracker.ietf.org/doc/draft-rosomakho-httpbis-h3-unbound-data/).
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn recv_unbound_data(&mut self) -> Result<(), StreamError> {
        future::poll_fn(|cx| self.inner.poll_recv_unbound(cx)).await
    }

    /// Whether the client switched its sending side to unbound tunnel data
    pub fn is_recv_unbound(&self) -> bool {
        self.inner.is_recv_unbound()
    }

    /// Hands the receiving half of an unbound CONNECT stream back to the application
    ///
    /// Like [`RequestStream::into_unbound`], but for the receiving half of a
    /// [`RequestStream::split`]: it waits for the client's `UNBOUND_DATA` and leaves this
    /// endpoint's sending direction alone, so the sending half can keep writing `DATA` frames
    /// through h3.
    pub async fn into_unbound_recv(self) -> Result<Unbound<S>, StreamError> {
        let Self { inner, request_end } = self;
        let (prefix, stream, fin_received) = inner.into_unbound_recv().await?;

        Ok(Unbound {
            prefix,
            stream,
            guard: Guard::new(request_end),
            fin_received,
        })
    }
}

impl<S, B> RequestStream<S, B>
where
    S: quic::SendStream<B> + quic::RecvStream,
    B: Buf,
{
    /// Hands this CONNECT stream back to the application as a plain QUIC stream
    ///
    /// Switches this endpoint's sending side to unbound data if
    /// [`RequestStream::send_unbound_data`] has not been called yet, waits for the client to do
    /// the same, and then returns the stream itself: h3 stops framing, reading and writing it
    /// altogether, and the application talks to the QUIC implementation directly. With
    /// `h3-quinn`, [`Unbound::stream`] converts into `quinn::SendStream`/`quinn::RecvStream`.
    ///
    /// Two things to keep in mind:
    ///
    /// * [`Unbound::prefix`] holds tunnel data h3 had already read and must be written to the
    ///   tunnel's other end before anything read from the stream.
    /// * [`Unbound::guard`] keeps the connection's request bookkeeping alive and should be held
    ///   for as long as the tunnel is in use.
    ///
    /// This takes the stream by value, so the stream is gone whichever way this ends: dropping
    /// the returned future — a `select!` timeout, for instance — resets the request stream, and
    /// so does an error, including
    /// [`StreamError::UnboundDataNotNegotiated`](crate::error::StreamError::UnboundDataNotNegotiated).
    /// Call [`RequestStream::send_unbound_data`] and [`RequestStream::recv_unbound_data`] first
    /// if the wait needs to be cancellable, or if falling back to `DATA` frames when the client
    /// does not support the extension matters.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use bytes::{Buf, Bytes};
    /// # use h3::{quic, server::RequestStream};
    /// # use http::{Method, Request, Response};
    /// # async fn doc<S>(req: Request<()>, mut stream: RequestStream<S, Bytes>)
    /// #     -> Result<(), Box<dyn std::error::Error>>
    /// # where S: quic::SendStream<Bytes> + quic::RecvStream,
    /// # {
    /// if req.method() == Method::CONNECT {
    ///     stream.send_response(Response::new(())).await?;
    ///     let unbound = stream.into_unbound().await?;
    ///     // `unbound.stream` is now the QUIC implementation's own stream; h3 is out of the way.
    ///     // Write `unbound.prefix` to the tunnel first, then copy in both directions, and hold
    ///     // on to `unbound.guard` until the tunnel is done.
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// See [the draft](https://datatracker.ietf.org/doc/draft-rosomakho-httpbis-h3-unbound-data/).
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn into_unbound(self) -> Result<Unbound<S>, StreamError> {
        let Self { inner, request_end } = self;
        let (prefix, stream, fin_received) = inner.into_unbound().await?;

        Ok(Unbound {
            prefix,
            stream,
            guard: Guard::new(request_end),
            fin_received,
        })
    }
}

impl<S, B> RequestStream<S, B>
where
    S: quic::SendStream<B>,
    B: Buf,
{
    /// Send the HTTP/3 response
    ///
    /// This should be called before trying to send any data with
    /// [`RequestStream::send_data`].
    pub async fn send_response(&mut self, resp: Response<()>) -> Result<(), StreamError> {
        let (parts, _) = resp.into_parts();
        let response::Parts {
            status, headers, ..
        } = parts;
        let headers = Header::response(status, headers);

        let mut block = BytesMut::new();
        let mem_size = qpack::encode_stateless(&mut block, headers).map_err(|_e| {
            self.handle_connection_error_on_stream(InternalConnectionError {
                code: Code::H3_INTERNAL_ERROR,
                message: "Failed to encode headers".to_string(),
            })
        })?;

        let max_mem_size = self.inner.settings().max_field_section_size;

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
        //# An implementation that
        //# has received this parameter SHOULD NOT send an HTTP message header
        //# that exceeds the indicated size, as the peer will likely refuse to
        //# process it.
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
        //# An HTTP implementation MUST NOT send frames or requests that would be
        //# invalid based on its current understanding of the peer's settings.

        if mem_size > max_mem_size {
            return Err(StreamError::HeaderTooBig {
                actual_size: mem_size,
                max_size: max_mem_size,
            });
        }

        stream::write(&mut self.inner.stream, Frame::Headers(block.freeze()))
            .await
            .map_err(|e| self.handle_quic_stream_error(e))?;

        Ok(())
    }

    /// Send some data on the response body.
    ///
    /// Once [`RequestStream::send_unbound_data`] was called, the data is written without a `DATA`
    /// frame header.
    pub async fn send_data(&mut self, buf: B) -> Result<(), StreamError> {
        self.inner.send_data(buf).await
    }

    /// Stops framing the response body and switches to unbound tunnel data
    ///
    /// Sends an `UNBOUND_DATA` frame, after which every octet this endpoint writes is tunnel data
    /// up to the QUIC FIN. [`RequestStream::send_data`] keeps working and writes the bytes with no
    /// frame header, which is what makes this worthwhile for long-lived tunnels; trailers can no
    /// longer be sent.
    ///
    /// Only CONNECT streams can be switched, and only if the client advertised
    /// `SETTINGS_ENABLE_UNBOUND_DATA`. If it did not — including when its SETTINGS frame has not
    /// arrived yet — this returns [`StreamError::UnboundDataNotNegotiated`] without writing
    /// anything, so the response can simply continue in `DATA` frames.
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

    /// Stop a stream with an error code
    ///
    /// The code can be [`Code::H3_NO_ERROR`].
    pub fn stop_stream(&mut self, error_code: Code) {
        self.inner.stop_stream(error_code);
    }

    /// Send a set of trailers to end the response.
    ///
    /// [`RequestStream::finish`] must be called to finalize a request.
    pub async fn send_trailers(&mut self, trailers: HeaderMap) -> Result<(), StreamError> {
        self.inner.send_trailers(trailers).await
    }

    /// End the response without trailers.
    ///
    /// [`RequestStream::finish`] must be called to finalize a request.
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

    /// Returns the underlying stream id
    pub fn send_id(&self) -> StreamId {
        self.inner.stream.send_id()
    }

    /// Hands the sending half of an unbound CONNECT stream back to the application
    ///
    /// Like [`RequestStream::into_unbound`], but for the sending half of a
    /// [`RequestStream::split`]: only this endpoint's direction has to be unbound, so the
    /// receiving half can keep reading `DATA` frames through h3.
    pub async fn into_unbound_send(self) -> Result<Unbound<S>, StreamError> {
        let Self { inner, request_end } = self;
        let (prefix, stream, fin_received) = inner.into_unbound_send().await?;

        Ok(Unbound {
            prefix,
            stream,
            guard: Guard::new(request_end),
            fin_received,
        })
    }
}

impl<S, B> RequestStream<S, B>
where
    S: quic::BidiStream<B>,
    B: Buf,
{
    /// Splits the Request-Stream into send and receive.
    /// This can be used the send and receive data on different tasks.
    pub fn split(
        self,
    ) -> (
        RequestStream<S::SendStream, B>,
        RequestStream<S::RecvStream, B>,
    ) {
        let (send, recv) = self.inner.split();
        (
            RequestStream {
                inner: send,
                request_end: self.request_end.clone(),
            },
            RequestStream {
                inner: recv,
                request_end: self.request_end,
            },
        )
    }
}

impl Drop for RequestEnd {
    fn drop(&mut self) {
        if let Err(_error) = self.request_end.send(self.stream_id) {
            #[cfg(feature = "tracing")]
            error!(
                "failed to notify connection of request end: {} {}",
                self.stream_id, _error
            );
        }
    }
}
