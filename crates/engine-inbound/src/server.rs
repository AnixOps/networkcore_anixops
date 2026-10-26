//! The serve loop: accept clients, run the protocol handshake, relay through
//! an outbound and charge the bytes to the user.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use engine_outbound::{BoxStream, TargetAddr, TcpOutbound};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::udp::UdpOutbound;
use crate::{Accepted, StreamInbound, UserEntry};

const RELAY_BUFFER_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug)]
pub struct ServeSettings {
    pub max_connections: usize,
    /// Time allowed for the protocol handshake, from accept to target.
    pub handshake_timeout: Duration,
    pub connect_timeout: Duration,
    /// How long a rejected client that the inbound asked to hold is kept open
    /// while its input is discarded.
    pub reject_hold: Duration,
}

impl Default for ServeSettings {
    fn default() -> Self {
        Self {
            max_connections: 4096,
            handshake_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            reject_hold: Duration::from_secs(30),
        }
    }
}

/// Inbound-wide counters; no addresses or user names.
#[derive(Debug, Default)]
pub struct InboundStats {
    pub accepted: AtomicU64,
    /// Refused because `max_connections` were open.
    pub rejected: AtomicU64,
    pub active: AtomicU64,
    pub handshake_failed: AtomicU64,
    pub connect_failed: AtomicU64,
    /// Closed because their user was removed.
    pub revoked: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
}

/// Accepts TCP connections until the listener fails or the task is dropped.
pub async fn serve(
    listener: TcpListener,
    inbound: Arc<dyn StreamInbound>,
    outbound: Arc<dyn TcpOutbound>,
    settings: ServeSettings,
    stats: Arc<InboundStats>,
) -> io::Result<()> {
    serve_with_udp(listener, inbound, outbound, None, settings, stats).await
}

/// [`serve`] with UDP egress for inbounds that relay datagrams.
pub async fn serve_with_udp(
    listener: TcpListener,
    inbound: Arc<dyn StreamInbound>,
    outbound: Arc<dyn TcpOutbound>,
    udp: Option<Arc<dyn UdpOutbound>>,
    settings: ServeSettings,
    stats: Arc<InboundStats>,
) -> io::Result<()> {
    let permits = Arc::new(Semaphore::new(settings.max_connections));
    let settings = Arc::new(settings);
    loop {
        let (stream, peer) = listener.accept().await?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            stats.rejected.fetch_add(1, Ordering::Relaxed);
            drop(stream);
            continue;
        };
        stats.accepted.fetch_add(1, Ordering::Relaxed);
        let inbound = inbound.clone();
        let outbound = outbound.clone();
        let udp = udp.clone();
        let settings = settings.clone();
        let stats = stats.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = stream.set_nodelay(true);
            stats.active.fetch_add(1, Ordering::Relaxed);
            run(
                Box::new(stream),
                peer,
                inbound.as_ref(),
                outbound.as_ref(),
                udp.as_deref(),
                &settings,
                &stats,
            )
            .await;
            stats.active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

/// Runs one client connection to completion. Transports other than plain TCP
/// (TLS, QUIC streams) call this with their own stream.
pub async fn handle_connection(
    stream: BoxStream,
    peer: SocketAddr,
    inbound: &dyn StreamInbound,
    outbound: &dyn TcpOutbound,
    settings: &ServeSettings,
    stats: &Arc<InboundStats>,
) {
    stats.active.fetch_add(1, Ordering::Relaxed);
    run(stream, peer, inbound, outbound, None, settings, stats).await;
    stats.active.fetch_sub(1, Ordering::Relaxed);
}

async fn run(
    stream: BoxStream,
    peer: SocketAddr,
    inbound: &dyn StreamInbound,
    outbound: &dyn TcpOutbound,
    udp: Option<&dyn UdpOutbound>,
    settings: &ServeSettings,
    stats: &Arc<InboundStats>,
) {
    if inbound.serves_connections() {
        let context = ConnectionContext {
            peer,
            settings,
            stats,
            outbound,
            udp,
        };
        inbound.serve_connection(stream, context).await;
        return;
    }
    let handshake = tokio::time::timeout(settings.handshake_timeout, inbound.accept(stream, peer));
    let Accepted {
        user,
        target,
        stream,
    } = match handshake.await {
        Ok(Ok(accepted)) => accepted,
        Ok(Err(rejected)) => {
            stats.handshake_failed.fetch_add(1, Ordering::Relaxed);
            if let Some(stream) = rejected.stream {
                discard(stream, settings.reject_hold).await;
            }
            return;
        }
        Err(_) => {
            stats.handshake_failed.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    relay(
        Accepted {
            user,
            target,
            stream,
        },
        peer,
        outbound,
        settings,
        stats,
    )
    .await;
}

/// Relays a stream whose protocol handshake is already done, such as a QUIC
/// stream of an authenticated connection.
pub async fn relay_accepted(
    accepted: Accepted,
    peer: SocketAddr,
    outbound: &dyn TcpOutbound,
    settings: &ServeSettings,
    stats: &Arc<InboundStats>,
) {
    stats.active.fetch_add(1, Ordering::Relaxed);
    relay(accepted, peer, outbound, settings, stats).await;
    stats.active.fetch_sub(1, Ordering::Relaxed);
}

async fn relay(
    accepted: Accepted,
    peer: SocketAddr,
    outbound: &dyn TcpOutbound,
    settings: &ServeSettings,
    stats: &Arc<InboundStats>,
) {
    let Accepted {
        user,
        target,
        stream,
    } = accepted;
    let _online = user.as_ref().map(|user| user.connect(peer.ip()));
    if user.as_ref().is_some_and(|user| user.is_revoked()) {
        stats.revoked.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let connected = tokio::time::timeout(settings.connect_timeout, outbound.connect(&target)).await;
    let mut remote = match connected {
        Ok(Ok(remote)) => remote,
        Ok(Err(_)) | Err(_) => {
            stats.connect_failed.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    let mut client = Metered {
        inner: stream,
        user: user.clone(),
        stats,
    };
    let relay = tokio::io::copy_bidirectional_with_sizes(
        &mut client,
        &mut remote,
        RELAY_BUFFER_BYTES,
        RELAY_BUFFER_BYTES,
    );
    match user {
        Some(user) => {
            tokio::select! {
                _ = relay => {}
                _ = user.revoked() => {
                    stats.revoked.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        None => {
            let _ = relay.await;
        }
    }
}

/// Reads and drops client input until it closes or `hold` elapses.
async fn discard(mut stream: BoxStream, hold: Duration) {
    let mut sink = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + hold;
    loop {
        match tokio::time::timeout_at(deadline, stream.read(&mut sink)).await {
            Ok(Ok(n)) if n > 0 => {}
            _ => return,
        }
    }
}

/// What a [`StreamInbound::serve_connection`] implementation gets from the
/// serve loop: the outbounds, the limits and the counters.
pub struct ConnectionContext<'a> {
    pub peer: SocketAddr,
    pub settings: &'a ServeSettings,
    pub stats: &'a Arc<InboundStats>,
    outbound: &'a dyn TcpOutbound,
    udp: Option<&'a dyn UdpOutbound>,
}

impl<'a> ConnectionContext<'a> {
    /// Counts a client that failed the protocol handshake.
    pub fn handshake_failed(&self) {
        self.stats.handshake_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts a session closed because its user was removed.
    pub fn revoked(&self) {
        self.stats.revoked.fetch_add(1, Ordering::Relaxed);
    }

    /// Reads and drops client input for [`ServeSettings::reject_hold`].
    pub async fn hold(&self, stream: BoxStream) {
        discard(stream, self.settings.reject_hold).await;
    }

    /// Connects to `target` within [`ServeSettings::connect_timeout`];
    /// failures are counted.
    pub async fn connect(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        let connected =
            tokio::time::timeout(self.settings.connect_timeout, self.outbound.connect(target))
                .await
                .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()));
        if connected.is_err() {
            self.stats.connect_failed.fetch_add(1, Ordering::Relaxed);
        }
        connected
    }

    /// UDP egress, when the node provides one.
    pub fn udp(&self) -> Option<&'a dyn UdpOutbound> {
        self.udp
    }

    /// Charges relayed bytes (client to target, and back) to the inbound
    /// and the user; for datagrams, which do not go through
    /// [`ConnectionContext::relay`].
    pub fn count(&self, user: Option<&Arc<UserEntry>>, up: u64, down: u64) {
        self.stats.bytes_up.fetch_add(up, Ordering::Relaxed);
        self.stats.bytes_down.fetch_add(down, Ordering::Relaxed);
        if let Some(user) = user {
            user.add_up(up);
            user.add_down(down);
        }
    }

    /// Copies both directions between `client` and `remote` until both
    /// ended, charging the bytes. Fails with `PermissionDenied` when the
    /// user is removed meanwhile. The streams stay usable afterwards, so a
    /// protocol can carry the next request on the same client connection.
    pub async fn relay<S>(
        &self,
        user: Option<&Arc<UserEntry>>,
        client: &mut S,
        remote: &mut BoxStream,
    ) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + ?Sized,
    {
        let mut client = Metered {
            inner: client,
            user: user.cloned(),
            stats: self.stats,
        };
        let relay = tokio::io::copy_bidirectional_with_sizes(
            &mut client,
            remote,
            RELAY_BUFFER_BYTES,
            RELAY_BUFFER_BYTES,
        );
        match user {
            Some(user) => {
                tokio::select! {
                    copied = relay => copied.map(|_| ()),
                    _ = user.revoked() => {
                        self.revoked();
                        Err(io::Error::new(io::ErrorKind::PermissionDenied, "user removed"))
                    }
                }
            }
            None => relay.await.map(|_| ()),
        }
    }
}

/// The client side of a relay; counts bytes as they move.
struct Metered<'s, S> {
    inner: S,
    user: Option<Arc<UserEntry>>,
    stats: &'s InboundStats,
}

impl<S: AsyncRead + Unpin> AsyncRead for Metered<'_, S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.inner).poll_read(cx, buf);
        let read = (buf.filled().len() - before) as u64;
        if read > 0 {
            this.stats.bytes_up.fetch_add(read, Ordering::Relaxed);
            if let Some(user) = &this.user {
                user.add_up(read);
            }
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Metered<'_, S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = &polled {
            let written = *written as u64;
            this.stats.bytes_down.fetch_add(written, Ordering::Relaxed);
            if let Some(user) = &this.user {
                user.add_down(written);
            }
        }
        polled
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
