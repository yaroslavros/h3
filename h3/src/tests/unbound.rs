//! End-to-end tests for unbound data on CONNECT streams
//!
//! See draft-rosomakho-httpbis-h3-unbound-data-02.

use std::time::Duration;

use assert_matches::assert_matches;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures_util::future;
use http::{request, Method, Request, Response};

use crate::{
    client,
    error::{Code, ConnectionError, LocalError, StreamError},
    proto::{
        coding::Encode,
        frame::{self, Frame, FrameType, SettingId},
        headers::Header,
        stream::StreamType,
        varint::VarInt,
    },
    qpack, server,
    tests::{get_stream_blocking, h3_quinn, init_tracing, Pair},
};

/// Encodes a `HEADERS` frame holding a plain CONNECT request.
fn connect_request_encode<B: BufMut>(buf: &mut B) {
    let (parts, _) = Request::connect("localhost:4433")
        .body(())
        .unwrap()
        .into_parts();
    let request::Parts {
        method,
        uri,
        headers,
        extensions,
        ..
    } = parts;

    let headers = Header::request(method, uri, headers, extensions).unwrap();
    let mut block = BytesMut::new();
    qpack::encode_stateless(&mut block, headers).unwrap();
    Frame::headers(block).encode_with_payload(buf);
}

/// Calls `send_unbound_data`, retrying while the peer's SETTINGS frame has not arrived yet.
///
/// The control stream and the request stream are unordered, so an endpoint can be ready to switch
/// before it knows whether the peer accepts `UNBOUND_DATA`. Retrying is one way to deal with
/// that; a real application may just as well keep using `DATA` frames.
macro_rules! send_unbound_data_when_negotiated {
    ($stream:expr) => {{
        let mut attempts = 0;
        loop {
            match $stream.send_unbound_data().await {
                Ok(()) => break,
                Err(StreamError::UnboundDataNotNegotiated) if attempts < 100 => {
                    attempts += 1;
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                Err(err) => panic!("send_unbound_data failed: {}", err),
            }
        }
    }};
}

/// Both endpoints switch to unbound data, hand the stream back and tunnel over quinn directly.
#[tokio::test]
async fn connect_tunnel_handoff() {
    init_tracing();
    let mut pair = Pair::default();
    let server = pair.server();

    let server_fut = async {
        let conn =
            h3_quinn::Connection::new(server.endpoint.accept().await.unwrap().await.unwrap());
        let mut builder = server::builder();
        builder.enable_unbound_data(true);
        let mut incoming: server::Connection<_, Bytes> = builder.build(conn).await.unwrap();

        let (request, mut stream) = get_stream_blocking(&mut incoming).await.unwrap();
        assert_eq!(request.method(), &Method::CONNECT);

        let tunnel = async {
            stream.send_response(Response::new(())).await.unwrap();
            send_unbound_data_when_negotiated!(stream);

            let mut unbound = stream.into_unbound().await.unwrap();

            // draft-rosomakho-httpbis-h3-unbound-data-02, Section 5:
            // Regular `DATA` frames may be sent prior to `UNBOUND_DATA`. Their payload is tunnel
            // data as well, so h3 hands it over instead of dropping it.
            let buffered = unbound.prefix.remaining();
            assert!(
                buffered > 0,
                "the client's DATA frame payload should have been handed over"
            );
            let prefix = unbound.prefix.copy_to_bytes(buffered);
            assert!(
                prefix.starts_with(b"before"),
                "unexpected prefix: {:?}",
                prefix
            );

            let (mut send, mut recv) = unbound
                .stream
                .into_quinn()
                .unwrap_or_else(|_| panic!("the handoff flushed the stream"));

            // Echo the whole tunnel back, starting with what h3 had already read.
            let mut tunneled = prefix.to_vec();
            tunneled.extend_from_slice(&recv.read_to_end(64 * 1024).await.unwrap());
            send.write_all(&tunneled).await.unwrap();
            send.finish().unwrap();

            // h3 still counts this request as in flight while the guard lives.
            drop(unbound.guard);
        };

        // Keep driving the connection: this is what processes the peer's SETTINGS and keeps the
        // server connection — and with it the QUIC connection — alive while the tunnel runs.
        let driver = async {
            let _ = incoming.accept().await;
        };

        tokio::join!(tunnel, driver);
    };

    let client_fut = async {
        let mut builder = client::builder();
        builder.enable_unbound_data(true);
        let (mut driver, mut send_request) = builder
            .build::<_, _, Bytes>(pair.client().await)
            .await
            .expect("client init");

        let tunnel = async {
            let mut stream = send_request
                .send_request(Request::connect("localhost:4433").body(()).unwrap())
                .await
                .expect("send connect");

            let response = stream.recv_response().await.expect("recv response");
            assert_eq!(response.status(), http::StatusCode::OK);

            // A `DATA` frame first, then the switch, then raw tunnel bytes.
            stream
                .send_data(Bytes::from_static(b"before"))
                .await
                .unwrap();
            send_unbound_data_when_negotiated!(stream);
            stream
                .send_data(Bytes::from_static(b"after"))
                .await
                .unwrap();

            let mut unbound = stream.into_unbound().await.unwrap();
            let buffered = unbound.prefix.remaining();
            let prefix = unbound.prefix.copy_to_bytes(buffered);

            let (mut send, mut recv) = unbound
                .stream
                .into_quinn()
                .unwrap_or_else(|_| panic!("the handoff flushed the stream"));
            send.finish().unwrap();

            let mut echoed = prefix.to_vec();
            echoed.extend_from_slice(&recv.read_to_end(64 * 1024).await.unwrap());
            assert_eq!(echoed, b"beforeafter");
        };

        // The driver must keep running: dropping `send_request` would close the connection and
        // with it the tunnel.
        tokio::select! {
            _ = tunnel => (),
            _ = future::poll_fn(|cx| driver.poll_close(cx)) => panic!("connection closed early"),
        }
    };

    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(server_fut, client_fut);
    })
    .await
    .expect("test timed out");
}

/// A split stream hands its two halves over independently.
#[tokio::test]
async fn connect_tunnel_split_handoff() {
    init_tracing();
    let mut pair = Pair::default();
    let server = pair.server();

    let server_fut = async {
        let conn =
            h3_quinn::Connection::new(server.endpoint.accept().await.unwrap().await.unwrap());
        let mut builder = server::builder();
        builder.enable_unbound_data(true);
        let mut incoming: server::Connection<_, Bytes> = builder.build(conn).await.unwrap();

        let (_, mut stream) = get_stream_blocking(&mut incoming).await.unwrap();

        let tunnel = async {
            stream.send_response(Response::new(())).await.unwrap();
            send_unbound_data_when_negotiated!(stream);

            let (send_stream, recv_stream) = stream.split();

            // The sending side is unbound already, so it can be handed over without waiting for
            // the client.
            let unbound_send = send_stream.into_unbound_send().await.unwrap();
            let mut send = unbound_send
                .stream
                .into_quinn()
                .unwrap_or_else(|_| panic!("the handoff flushed the stream"));

            // The receiving side waits for the client's UNBOUND_DATA.
            let mut unbound_recv = recv_stream.into_unbound_recv().await.unwrap();
            let buffered = unbound_recv.prefix.remaining();
            let prefix = unbound_recv.prefix.copy_to_bytes(buffered);
            let mut recv = unbound_recv.stream.into_quinn();

            let mut tunneled = prefix.to_vec();
            tunneled.extend_from_slice(&recv.read_to_end(64 * 1024).await.unwrap());
            assert_eq!(tunneled, b"ping");

            send.write_all(b"pong").await.unwrap();
            send.finish().unwrap();
        };

        let driver = async {
            let _ = incoming.accept().await;
        };

        tokio::join!(tunnel, driver);
    };

    let client_fut = async {
        let mut builder = client::builder();
        builder.enable_unbound_data(true);
        let (mut driver, mut send_request) = builder
            .build::<_, _, Bytes>(pair.client().await)
            .await
            .expect("client init");

        let tunnel = async {
            let mut stream = send_request
                .send_request(Request::connect("localhost:4433").body(()).unwrap())
                .await
                .expect("send connect");
            stream.recv_response().await.expect("recv response");

            send_unbound_data_when_negotiated!(stream);
            stream.send_data(Bytes::from_static(b"ping")).await.unwrap();

            let mut unbound = stream.into_unbound().await.unwrap();
            let buffered = unbound.prefix.remaining();
            let prefix = unbound.prefix.copy_to_bytes(buffered);

            let (mut send, mut recv) = unbound
                .stream
                .into_quinn()
                .unwrap_or_else(|_| panic!("the handoff flushed the stream"));
            send.finish().unwrap();

            let mut echoed = prefix.to_vec();
            echoed.extend_from_slice(&recv.read_to_end(64 * 1024).await.unwrap());
            assert_eq!(echoed, b"pong");
        };

        tokio::select! {
            _ = tunnel => (),
            _ = future::poll_fn(|cx| driver.poll_close(cx)) => panic!("connection closed early"),
        }
    };

    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(server_fut, client_fut);
    })
    .await
    .expect("test timed out");
}

/// The receiving side keeps working through `recv_data` when the stream is not handed over.
#[tokio::test]
async fn connect_tunnel_received_transparently() {
    init_tracing();
    let mut pair = Pair::default();
    let server = pair.server();

    let server_fut = async {
        let conn =
            h3_quinn::Connection::new(server.endpoint.accept().await.unwrap().await.unwrap());
        let mut builder = server::builder();
        builder.enable_unbound_data(true);
        let mut incoming: server::Connection<_, Bytes> = builder.build(conn).await.unwrap();

        let (_, mut stream) = get_stream_blocking(&mut incoming).await.unwrap();

        let tunnel = async {
            stream.send_response(Response::new(())).await.unwrap();
            send_unbound_data_when_negotiated!(stream);
            // Written with no `DATA` frame header, in two chunks.
            stream
                .send_data(Bytes::from_static(b"tunnel "))
                .await
                .unwrap();
            stream.send_data(Bytes::from_static(b"data")).await.unwrap();
            stream.finish().await.unwrap();
        };

        let driver = async {
            let _ = incoming.accept().await;
        };

        tokio::join!(tunnel, driver);
    };

    let client_fut = async {
        let mut builder = client::builder();
        builder.enable_unbound_data(true);
        let (mut driver, mut send_request) = builder
            .build::<_, _, Bytes>(pair.client().await)
            .await
            .expect("client init");

        let request = async {
            let mut stream = send_request
                .send_request(Request::connect("localhost:4433").body(()).unwrap())
                .await
                .expect("send connect");
            stream.recv_response().await.expect("recv response");

            let mut received = Vec::new();
            while let Some(mut chunk) = stream.recv_data().await.expect("recv data") {
                received.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
            }
            assert_eq!(received, b"tunnel data");
            assert!(stream.is_recv_unbound());

            // CONNECT streams have no trailers, and no frame can follow unbound data: this must
            // answer `None` rather than trying to parse tunnel bytes as a frame.
            assert_matches!(stream.recv_trailers().await, Ok(None));
        };

        tokio::select! {
            _ = request => (),
            _ = future::poll_fn(|cx| driver.poll_close(cx)) => panic!("connection closed early"),
        }
    };

    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(server_fut, client_fut);
    })
    .await
    .expect("test timed out");
}

/// A `DATA` frame which announces more than it delivers ends the wait with a frame error.
///
/// The payload-state side of this is covered by
/// `frame::tests::poll_data_clears_the_payload_state_at_the_end_of_the_stream`, which fails fast;
/// without it, a wait loop here would spin at 100% CPU on five bytes from a peer.
#[tokio::test]
async fn truncated_data_frame_while_waiting_for_unbound_data() {
    init_tracing();
    let mut pair = Pair::default();
    let server = pair.server();

    let client_fut = async {
        let connection = pair.client_inner().await;

        let mut control = connection.open_uni().await.unwrap();
        let mut buf = BytesMut::new();
        StreamType::CONTROL.encode(&mut buf);
        let mut settings = frame::Settings::default();
        settings.insert(SettingId::ENABLE_UNBOUND_DATA, 1).unwrap();
        Frame::Settings::<Bytes>(settings).encode(&mut buf);
        control.write_all(&buf[..]).await.unwrap();

        let (mut send, _recv) = connection.open_bi().await.unwrap();
        let mut buf = BytesMut::new();
        connect_request_encode(&mut buf);
        // Announce five bytes of body, then end the stream without sending any of them.
        FrameType::DATA.encode(&mut buf);
        VarInt::from(5u32).encode(&mut buf);
        send.write_all(&buf[..]).await.unwrap();
        send.finish().unwrap();

        tokio::time::sleep(Duration::from_secs(20)).await;
    };

    let server_fut = async {
        let conn =
            h3_quinn::Connection::new(server.endpoint.accept().await.unwrap().await.unwrap());
        let mut builder = server::builder();
        builder.enable_unbound_data(true);
        let mut incoming: server::Connection<_, Bytes> = builder.build(conn).await.unwrap();

        let (_, mut stream) = get_stream_blocking(&mut incoming).await.unwrap();

        // RFC 9114, Section 7.1: a truncated frame at a clean stream end is a connection error
        // of type H3_FRAME_ERROR.
        assert_matches!(
            stream.recv_unbound_data().await.unwrap_err(),
            StreamError::ConnectionError(ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_FRAME_ERROR,
                    ..
                }
            })
        );
    };

    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            _ = server_fut => (),
            _ = client_fut => panic!("client resolved first"),
        }
    })
    .await
    .expect("timed out: the wait loop never yielded");
}

/// Reading tunnel data through h3 first and handing the stream over afterwards works.
///
/// This is the path which needs `h3-quinn` to keep ownership of its `quinn::RecvStream` across
/// polls: a `recv_data` which returned data while a transport read was still outstanding used to
/// leave the quinn stream parked inside that read.
#[tokio::test]
async fn handoff_after_reading_through_h3() {
    init_tracing();
    let mut pair = Pair::default();
    let server = pair.server();

    let server_fut = async {
        let conn =
            h3_quinn::Connection::new(server.endpoint.accept().await.unwrap().await.unwrap());
        let mut builder = server::builder();
        builder.enable_unbound_data(true);
        let mut incoming: server::Connection<_, Bytes> = builder.build(conn).await.unwrap();

        let (_, mut stream) = get_stream_blocking(&mut incoming).await.unwrap();

        let tunnel = async {
            stream.send_response(Response::new(())).await.unwrap();
            send_unbound_data_when_negotiated!(stream);
            stream
                .send_data(Bytes::from_static(b"first"))
                .await
                .unwrap();
            stream
                .send_data(Bytes::from_static(b"second"))
                .await
                .unwrap();
            stream.finish().await.unwrap();
        };

        let driver = async {
            let _ = incoming.accept().await;
        };

        tokio::join!(tunnel, driver);
    };

    let client_fut = async {
        let mut builder = client::builder();
        builder.enable_unbound_data(true);
        let (mut driver, mut send_request) = builder
            .build::<_, _, Bytes>(pair.client().await)
            .await
            .expect("client init");

        let tunnel = async {
            let mut stream = send_request
                .send_request(Request::connect("localhost:4433").body(()).unwrap())
                .await
                .expect("send connect");
            stream.recv_response().await.expect("recv response");

            // Read part of the tunnel through h3 ...
            let mut received = Vec::new();
            let mut chunk = stream
                .recv_data()
                .await
                .expect("recv data")
                .expect("tunnel data");
            received.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
            assert!(stream.is_recv_unbound());

            // ... then take the stream over for the rest. The switch has to happen before
            // `into_unbound`, which would otherwise fail if the server's SETTINGS frame has not
            // been processed yet.
            send_unbound_data_when_negotiated!(stream);
            let mut unbound = stream.into_unbound().await.unwrap();
            while let Some(chunk) = unbound.prefix.next_chunk() {
                received.extend_from_slice(&chunk);
            }
            let (send, mut recv) = unbound
                .stream
                .into_quinn()
                .unwrap_or_else(|_| panic!("the handoff flushed the stream"));
            drop(send);
            received.extend_from_slice(&recv.read_to_end(64 * 1024).await.unwrap());

            assert_eq!(received, b"firstsecond");
        };

        tokio::select! {
            _ = tunnel => (),
            _ = future::poll_fn(|cx| driver.poll_close(cx)) => panic!("connection closed early"),
        }
    };

    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(server_fut, client_fut);
    })
    .await
    .expect("test timed out");
}

/// The peer may end its sending side without ever switching to unbound data.
///
/// There is then nothing left for h3 to frame on that direction either, so the handoff completes
/// with `fin_received` set instead of destroying a stream which is still writable.
#[tokio::test]
async fn handoff_completes_when_the_peer_ends_without_switching() {
    init_tracing();
    let mut pair = Pair::default();
    let server = pair.server();

    let server_fut = async {
        let conn =
            h3_quinn::Connection::new(server.endpoint.accept().await.unwrap().await.unwrap());
        let mut builder = server::builder();
        builder.enable_unbound_data(true);
        let mut incoming: server::Connection<_, Bytes> = builder.build(conn).await.unwrap();

        let (_, mut stream) = get_stream_blocking(&mut incoming).await.unwrap();

        let tunnel = async {
            stream.send_response(Response::new(())).await.unwrap();
            send_unbound_data_when_negotiated!(stream);

            // The client sends a `DATA` frame and finishes; it never switches.
            let mut unbound = stream.into_unbound().await.unwrap();
            assert!(unbound.fin_received, "the peer's FIN should be reported");
            assert!(!unbound.prefix.is_empty());

            let buffered = unbound.prefix.remaining();
            let prefix = unbound.prefix.copy_to_bytes(buffered);
            assert_eq!(&prefix[..], b"half");

            let (mut send, _recv) = unbound
                .stream
                .into_quinn()
                .unwrap_or_else(|_| panic!("the handoff flushed the stream"));

            // The sending side is still usable.
            send.write_all(&prefix).await.unwrap();
            send.finish().unwrap();
        };

        let driver = async {
            let _ = incoming.accept().await;
        };

        tokio::join!(tunnel, driver);
    };

    let client_fut = async {
        let mut builder = client::builder();
        builder.enable_unbound_data(true);
        let (mut driver, mut send_request) = builder
            .build::<_, _, Bytes>(pair.client().await)
            .await
            .expect("client init");

        let request = async {
            let mut stream = send_request
                .send_request(Request::connect("localhost:4433").body(()).unwrap())
                .await
                .expect("send connect");
            stream.recv_response().await.expect("recv response");

            // Framed, then done: no UNBOUND_DATA in this direction at all.
            stream.send_data(Bytes::from_static(b"half")).await.unwrap();
            stream.finish().await.unwrap();

            let mut received = Vec::new();
            while let Some(mut chunk) = stream.recv_data().await.expect("recv data") {
                received.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
            }
            assert_eq!(received, b"half");
        };

        tokio::select! {
            _ = request => (),
            _ = future::poll_fn(|cx| driver.poll_close(cx)) => panic!("connection closed early"),
        }
    };

    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(server_fut, client_fut);
    })
    .await
    .expect("test timed out");
}

/// Neither endpoint advertises the setting, so both keep using `DATA` frames.
#[tokio::test]
async fn send_unbound_data_falls_back_when_not_negotiated() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let server_fut = async {
        // The default configuration does not advertise SETTINGS_ENABLE_UNBOUND_DATA.
        let conn = server.next().await;
        let mut incoming = server::Connection::<_, Bytes>::new(conn).await.unwrap();

        let (_, mut stream) = get_stream_blocking(&mut incoming).await.unwrap();

        let tunnel = async {
            stream.send_response(Response::new(())).await.unwrap();

            // draft-rosomakho-httpbis-h3-unbound-data-02, Section 3:
            // Endpoints MUST NOT send an `UNBOUND_DATA` frame to a peer that has not advertised
            // `SETTINGS_ENABLE_UNBOUND_DATA` with value 1.
            assert_matches!(
                stream.send_unbound_data().await,
                Err(StreamError::UnboundDataNotNegotiated)
            );
            assert!(!stream.is_send_unbound());

            // Nothing was written, so the response continues as usual.
            stream
                .send_data(Bytes::from_static(b"framed"))
                .await
                .unwrap();
            stream.finish().await.unwrap();
        };

        let driver = async {
            let _ = incoming.accept().await;
        };

        tokio::join!(tunnel, driver);
    };

    let client_fut = async {
        // The default configuration does not advertise SETTINGS_ENABLE_UNBOUND_DATA either.
        let (mut driver, mut send_request) =
            client::new(pair.client().await).await.expect("client init");

        let request = async {
            let mut stream = send_request
                .send_request(Request::connect("localhost:4433").body(()).unwrap())
                .await
                .expect("send connect");
            stream.recv_response().await.expect("recv response");

            assert_matches!(
                stream.send_unbound_data().await,
                Err(StreamError::UnboundDataNotNegotiated)
            );

            let mut received = Vec::new();
            while let Some(mut chunk) = stream.recv_data().await.expect("recv data") {
                received.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
            }
            assert_eq!(received, b"framed");
            assert!(!stream.is_recv_unbound());
        };

        tokio::select! {
            _ = request => (),
            _ = future::poll_fn(|cx| driver.poll_close(cx)) => panic!("connection closed early"),
        }
    };

    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(server_fut, client_fut);
    })
    .await
    .expect("test timed out");
}

/// The setting is directional: it says what its sender is willing to receive.
///
/// Here only the client advertises it, so the server may switch its sending side while the client
/// may not switch its own.
#[tokio::test]
async fn unbound_data_setting_is_directional() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let server_fut = async {
        // The default configuration does not advertise SETTINGS_ENABLE_UNBOUND_DATA, which says
        // nothing about what the server is allowed to send.
        let conn = server.next().await;
        let mut incoming = server::Connection::<_, Bytes>::new(conn).await.unwrap();

        let (_, mut stream) = get_stream_blocking(&mut incoming).await.unwrap();

        let tunnel = async {
            stream.send_response(Response::new(())).await.unwrap();
            send_unbound_data_when_negotiated!(stream);
            assert!(stream.is_send_unbound());
            stream
                .send_data(Bytes::from_static(b"unframed"))
                .await
                .unwrap();
            stream.finish().await.unwrap();
        };

        let driver = async {
            let _ = incoming.accept().await;
        };

        tokio::join!(tunnel, driver);
    };

    let client_fut = async {
        let mut builder = client::builder();
        builder.enable_unbound_data(true);
        let (mut driver, mut send_request) = builder
            .build::<_, _, Bytes>(pair.client().await)
            .await
            .expect("client init");

        let request = async {
            let mut stream = send_request
                .send_request(Request::connect("localhost:4433").body(()).unwrap())
                .await
                .expect("send connect");
            stream.recv_response().await.expect("recv response");

            // The server did not advertise the setting, so this direction stays framed.
            assert_matches!(
                stream.send_unbound_data().await,
                Err(StreamError::UnboundDataNotNegotiated)
            );

            let mut received = Vec::new();
            while let Some(mut chunk) = stream.recv_data().await.expect("recv data") {
                received.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
            }
            assert_eq!(received, b"unframed");
            assert!(stream.is_recv_unbound());
            assert!(!stream.is_send_unbound());
        };

        tokio::select! {
            _ = request => (),
            _ = future::poll_fn(|cx| driver.poll_close(cx)) => panic!("connection closed early"),
        }
    };

    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(server_fut, client_fut);
    })
    .await
    .expect("test timed out");
}

/// Unbound data is not allowed on a stream which did not carry a CONNECT request.
#[tokio::test]
async fn send_unbound_data_rejected_on_non_connect_stream() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let server_fut = async {
        let conn = server.next().await;
        let mut builder = server::builder();
        builder.enable_unbound_data(true);
        let mut incoming: server::Connection<_, Bytes> = builder.build(conn).await.unwrap();

        let (_, mut stream) = get_stream_blocking(&mut incoming).await.unwrap();

        let tunnel = async {
            stream.send_response(Response::new(())).await.unwrap();

            // draft-rosomakho-httpbis-h3-unbound-data-02, Section 4:
            // The `UNBOUND_DATA` frame is only valid on CONNECT streams.
            assert_matches!(
                stream.send_unbound_data().await,
                Err(StreamError::StreamError { .. })
            );
            stream.finish().await.unwrap();
        };

        let driver = async {
            let _ = incoming.accept().await;
        };

        tokio::join!(tunnel, driver);
    };

    let client_fut = async {
        let mut builder = client::builder();
        builder.enable_unbound_data(true);
        let (mut driver, mut send_request) = builder
            .build::<_, _, Bytes>(pair.client().await)
            .await
            .expect("client init");

        let request = async {
            let mut stream = send_request
                .send_request(Request::get("http://localhost/salut").body(()).unwrap())
                .await
                .expect("send request");
            stream.recv_response().await.expect("recv response");

            assert_matches!(
                stream.send_unbound_data().await,
                Err(StreamError::StreamError { .. })
            );

            while stream.recv_data().await.expect("recv data").is_some() {}
        };

        tokio::select! {
            _ = request => (),
            _ = future::poll_fn(|cx| driver.poll_close(cx)) => panic!("connection closed early"),
        }
    };

    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(server_fut, client_fut);
    })
    .await
    .expect("test timed out");
}
