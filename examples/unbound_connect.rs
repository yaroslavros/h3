//! A CONNECT tunnel which drops HTTP/3 framing and hands the QUIC stream to the application.
//!
//! This runs an HTTP/3 server and a client on loopback and tunnels a few bytes between them.
//! Both endpoints advertise `SETTINGS_ENABLE_UNBOUND_DATA`, send an `UNBOUND_DATA` frame once the
//! CONNECT tunnel is up, and then take the stream out of h3 with `into_unbound()`. From that
//! point on neither side writes another frame header: the server echoes the tunnel with plain
//! `tokio::io::copy` over `quinn::SendStream`/`quinn::RecvStream`.
//!
//! See <https://datatracker.ietf.org/doc/draft-rosomakho-httpbis-h3-unbound-data/>.

use std::{
    error::Error,
    future::poll_fn,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use bytes::{Buf, Bytes};
use h3::error::StreamError;
use h3_quinn::quinn::{
    self,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use http::{Method, Request, Response, StatusCode};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::info;

static ALPN: &[u8] = b"h3";

/// What the client asks the server to tunnel to. Nothing connects to it in this example; the
/// server plays the role of the far end itself and echoes.
const TUNNEL_TARGET: &str = "echo.example:443";

const MESSAGE: &[u8] = b"these bytes travel without a single DATA frame header\n";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let (cert, key) = self_signed_cert()?;
    let endpoint = server_endpoint(cert.clone(), key)?;
    let addr = endpoint.local_addr()?;

    let server = tokio::spawn(run_server(endpoint));
    let client = run_client(addr, cert).await;

    // The server returns once its single tunnel is done.
    let server = tokio::time::timeout(Duration::from_secs(5), server).await??;

    client?;
    server?;

    Ok(())
}

async fn run_server(endpoint: quinn::Endpoint) -> Result<(), Box<dyn Error + Send + Sync>> {
    let connection = endpoint.accept().await.ok_or("endpoint closed")?.await?;

    let mut h3_connection: h3::server::Connection<_, Bytes> = h3::server::builder()
        // Tell the client we accept UNBOUND_DATA frames on CONNECT streams.
        .enable_unbound_data(true)
        .build(h3_quinn::Connection::new(connection))
        .await?;

    let resolver = h3_connection.accept().await?.ok_or("connection closed")?;
    let (request, mut stream) = resolver.resolve_request().await?;

    if request.method() != Method::CONNECT {
        stream
            .send_response(
                Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(())?,
            )
            .await?;
        stream.finish().await?;
        return Err("expected a CONNECT request".into());
    }

    info!(target = %request.uri(), "CONNECT accepted");

    let tunnel = async {
        stream.send_response(Response::new(())).await?;

        // Stop framing our sending side. `UnboundDataNotNegotiated` means the client does not
        // accept UNBOUND_DATA — possibly only because its SETTINGS frame has not been processed
        // yet, as the control stream is unordered with respect to this one. A server which does
        // not want to wait would keep the response body in DATA frames instead.
        loop {
            match stream.send_unbound_data().await {
                Ok(()) => break,
                Err(StreamError::UnboundDataNotNegotiated) => {
                    tokio::time::sleep(Duration::from_millis(5)).await
                }
                Err(err) => return Err(err.into()),
            }
        }

        // Wait for the client to stop framing its direction too, then take the stream out of h3.
        let mut unbound = stream.into_unbound().await?;
        info!(
            prefix = unbound.prefix.remaining(),
            "tunnel handed over, h3 is out of the data path"
        );

        let (mut send, mut recv) = unbound
            .stream
            .into_quinn()
            .map_err(|_| "stream still had unflushed data")?;

        // Tunnel data h3 had already read has to go out before anything read from the stream.
        while let Some(chunk) = unbound.prefix.next_chunk() {
            send.write_all(&chunk).await?;
        }

        // From here it is an ordinary QUIC stream pair.
        tokio::io::copy(&mut recv, &mut send).await?;
        send.finish()?;

        // Holding the guard tells h3 the request is still in flight; dropping it ends that.
        drop(unbound.guard);

        Ok::<_, Box<dyn Error + Send + Sync>>(())
    };

    // Keep serving the connection while the tunnel runs. This matters: h3 can no longer see the
    // handed-off stream, and dropping the connection would close the QUIC connection underneath
    // the tunnel. A real server would handle the requests it accepts here; this one only waits
    // for the client to go away.
    let serve = async {
        loop {
            match h3_connection.accept().await {
                Ok(Some(_resolver)) => info!("ignoring an extra request"),
                Ok(None) => break,
                Err(err) if err.is_h3_no_error() => break,
                Err(err) => return Err(err.into()),
            }
        }

        Ok::<_, Box<dyn Error + Send + Sync>>(())
    };

    let (tunnel, serve) = tokio::join!(tunnel, serve);
    tunnel?;
    serve?;

    Ok(())
}

async fn run_client(
    addr: SocketAddr,
    cert: CertificateDer<'static>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let endpoint = client_endpoint(cert)?;
    let connection = endpoint.connect(addr, "localhost")?.await?;

    let (mut driver, mut send_request) = h3::client::builder()
        // Tell the server we accept UNBOUND_DATA frames on CONNECT streams.
        .enable_unbound_data(true)
        .build::<_, _, Bytes>(h3_quinn::Connection::new(connection))
        .await?;

    // The driver processes the control stream, where the server's SETTINGS frame arrives.
    let drive = tokio::spawn(async move { poll_fn(|cx| driver.poll_close(cx)).await });

    let mut stream = send_request
        .send_request(Request::connect(TUNNEL_TARGET).body(())?)
        .await?;

    let response = stream.recv_response().await?;
    info!(status = ?response.status(), "tunnel established");

    // The server's SETTINGS frame travels on the control stream, so it may not have arrived yet
    // when the response does. Waiting for it is one option; an application which does not want
    // to wait can keep using DATA frames instead.
    loop {
        match stream.send_unbound_data().await {
            Ok(()) => break,
            Err(StreamError::UnboundDataNotNegotiated) => {
                tokio::time::sleep(Duration::from_millis(5)).await
            }
            Err(err) => return Err(err.into()),
        }
    }

    let mut unbound = stream.into_unbound().await?;
    let (mut send, mut recv) = unbound
        .stream
        .into_quinn()
        .map_err(|_| "stream still had unflushed data")?;

    send.write_all(MESSAGE).await?;
    send.finish()?;

    let mut echoed = Vec::new();
    while let Some(chunk) = unbound.prefix.next_chunk() {
        echoed.extend_from_slice(&chunk);
    }
    echoed.extend_from_slice(&recv.read_to_end(64 * 1024).await?);

    print!("{}", String::from_utf8_lossy(&echoed));
    assert_eq!(echoed, MESSAGE, "the tunnel did not round-trip");

    // Dropping the last `SendRequest` closes the connection, so it has to outlive the tunnel.
    drop(send_request);
    let _ = drive.await;

    Ok(())
}

fn self_signed_cert(
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), Box<dyn Error + Send + Sync>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let key = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());

    Ok((cert.cert.into(), key))
}

fn server_endpoint(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<quinn::Endpoint, Box<dyn Error + Send + Sync>> {
    let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)?;
    crypto.alpn_protocols = vec![ALPN.to_vec()];

    let config = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));

    Ok(quinn::Endpoint::server(
        config,
        (Ipv4Addr::LOCALHOST, 0).into(),
    )?)
}

fn client_endpoint(
    cert: CertificateDer<'static>,
) -> Result<quinn::Endpoint, Box<dyn Error + Send + Sync>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert)?;

    let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_root_certificates(roots)
    .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];

    let mut endpoint = quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into())?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto)?,
    )));

    Ok(endpoint)
}
