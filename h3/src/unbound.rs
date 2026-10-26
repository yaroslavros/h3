//! Unbound data on CONNECT streams
//!
//! [`UNBOUND_DATA`] turns off HTTP/3 framing for the rest of a CONNECT stream: every octet which
//! follows it, up to the QUIC FIN, is tunneled data. Once that happens in both directions, h3 has
//! nothing left to do on the stream, so it can hand it back to the application with
//! [`RequestStream::into_unbound`](crate::server::RequestStream::into_unbound).
//!
//! The application then owns the stream the QUIC implementation produced, and can use its native
//! API — with [`h3-quinn`] that means `quinn::SendStream`/`quinn::RecvStream`, so a tunnel can be
//! driven with `tokio::io::copy_bidirectional` and h3 is out of the data path entirely.
//!
//! [`UNBOUND_DATA`]: https://datatracker.ietf.org/doc/draft-rosomakho-httpbis-h3-unbound-data/
//! [`h3-quinn`]: https://docs.rs/h3-quinn

use std::fmt;
use std::io::IoSlice;
use std::sync::Arc;

use bytes::{Buf, Bytes};

use crate::buf::BufList;

/// A CONNECT stream which h3 handed back to the application
///
/// Returned by [`RequestStream::into_unbound`](crate::server::RequestStream::into_unbound). h3
/// does not touch the stream any more: closing it, resetting it and reporting its errors are the
/// application's job from here on.
#[must_use = "dropping this resets the stream and ends the tunnel"]
pub struct Unbound<S> {
    /// Tunnel data which h3 had already read from the transport
    ///
    /// These bytes were received before the stream was handed back — they arrived in the same
    /// QUIC chunks as the `UNBOUND_DATA` frame, or in `DATA` frames which preceded it. They
    /// **must** be consumed before reading from `stream`, or the tunnel will deliver bytes out of
    /// order. [`Prefix`] implements [`Buf`], so `write_all_buf(&mut unbound.prefix)` is usually
    /// all that is needed.
    pub prefix: Prefix,
    /// The stream, exactly as the QUIC implementation produced it
    pub stream: S,
    /// Keeps the connection's bookkeeping for this request alive
    ///
    /// h3 can no longer observe when this stream ends, so it counts the request as in-flight for
    /// as long as this guard lives. Drop it when the tunnel is done, otherwise a graceful
    /// shutdown of the connection will wait for it forever.
    pub guard: Guard,
    /// Whether h3 already saw the peer finish its sending side
    ///
    /// The tunnel data in `prefix` is then everything the peer sent. QUIC implementations
    /// generally report the end of the stream again on the next read, so this is only needed by
    /// applications which cannot rely on that.
    pub fin_received: bool,
}

impl<S> fmt::Debug for Unbound<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Unbound")
            .field("prefix", &self.prefix)
            .field("stream", &"...")
            .field("fin_received", &self.fin_received)
            .finish()
    }
}

/// Tunnel data which h3 read from the transport before handing the stream back
///
/// Implements [`Buf`], including [`Buf::chunks_vectored`], so it can be written out without
/// copying it chunk by chunk.
#[derive(Debug)]
pub struct Prefix(BufList<Bytes>);

impl Prefix {
    pub(crate) fn new(bufs: BufList<Bytes>) -> Self {
        Self(bufs)
    }

    /// Returns true if h3 had not buffered any tunnel data
    pub fn is_empty(&self) -> bool {
        !self.0.has_remaining()
    }

    /// Removes and returns the next chunk of buffered tunnel data
    ///
    /// Useful for handing the bytes to an API which takes owned [`Bytes`], such as
    /// `quinn::SendStream::write_chunk`.
    pub fn next_chunk(&mut self) -> Option<Bytes> {
        self.0.take_first_chunk()
    }
}

impl Buf for Prefix {
    fn remaining(&self) -> usize {
        self.0.remaining()
    }

    fn chunk(&self) -> &[u8] {
        self.0.chunk()
    }

    fn advance(&mut self, cnt: usize) {
        self.0.advance(cnt)
    }

    fn chunks_vectored<'a>(&'a self, dst: &mut [IoSlice<'a>]) -> usize {
        self.0.chunks_vectored(dst)
    }
}

/// Keeps the connection's bookkeeping for a handed-off request alive
///
/// See [`Unbound::guard`].
pub struct Guard(#[allow(dead_code)] Option<Arc<dyn Send + Sync>>);

impl Guard {
    /// A guard which keeps `keep_alive` alive for as long as the application holds it
    pub(crate) fn new(keep_alive: Arc<dyn Send + Sync>) -> Self {
        Self(Some(keep_alive))
    }

    /// A guard which tracks nothing, for connections which do not track requests
    pub(crate) fn none() -> Self {
        Self(None)
    }
}

impl fmt::Debug for Guard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Guard").field(&self.0.is_some()).finish()
    }
}
