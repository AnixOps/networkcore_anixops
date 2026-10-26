//! UDP egress and relays for inbounds that carry datagrams.
//!
//! [`UdpOutbound`] opens the node-side sockets; the node's direct outbound
//! implements it with the same private-target policy as TCP.
//!
//! Clients that carry datagrams inside their connection, such as Trojan
//! `UDP ASSOCIATE` or VLESS/VMess UDP commands, are relayed by
//! [`relay_datagrams`].
//! A protocol returns an [`Accepted`](crate::Accepted) whose `udp` field
//! holds the [`DatagramCodec`] that reads and frames datagrams on the client
//! stream. The serve loop then opens a [`UdpSession`] from its
//! [`UdpOutbound`] (see [`serve_with_udp`](crate::server::serve_with_udp))
//! and relays in both directions, charging payload bytes to the user, until
//! the client closes, the session is idle for [`UDP_IDLE_TIMEOUT`] or the user
//! is removed.
//!
//! QUIC protocols that carry many UDP sessions per connection, keyed by a
//! session id, use a [`SessionRelay`] instead: one socket per session id,
//! replies handed to the protocol's [`ReplySink`].

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use engine_outbound::{BoxFuture, BoxStream, TargetAddr};
use tokio::io::{AsyncRead, AsyncWriteExt};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::server::InboundStats;
use crate::UserEntry;

/// A session with no datagram in either direction for this long ends.
pub const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Largest datagram relayed.
pub const MAX_DATAGRAM: usize = 65_535;

/// Reader half of a client stream, as handed to [`DatagramCodec::read`].
pub type DatagramReader = dyn AsyncRead + Unpin + Send;

/// How a protocol carries datagrams on an accepted client stream.
pub trait DatagramCodec: Send + Sync {
    /// Reads the next client datagram; `None` when the client closed.
    fn read<'a>(
        &'a self,
        reader: &'a mut DatagramReader,
    ) -> BoxFuture<'a, io::Result<Option<(TargetAddr, Vec<u8>)>>>;

    /// Appends a reply datagram from `source` in the protocol's framing.
    fn encode(&self, source: SocketAddr, payload: &[u8], out: &mut Vec<u8>) -> io::Result<()>;
}

/// Opens UDP sessions toward targets; the node's direct outbound implements
/// it with the same private-target policy as TCP.
pub trait UdpOutbound: Send + Sync {
    /// A socket for one client's UDP session.
    fn bind(&self) -> BoxFuture<'_, io::Result<Arc<dyn UdpSession>>>;
}

/// One client's UDP socket. Sources are reported as plain IPv4 or IPv6
/// addresses (never IPv4-mapped IPv6). A refused or unreachable target fails
/// that datagram only; relays drop it and keep the session.
pub trait UdpSession: Send + Sync {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        target: &'a TargetAddr,
    ) -> BoxFuture<'a, io::Result<()>>;

    fn recv_from<'a>(&'a self, buf: &'a mut [u8])
        -> BoxFuture<'a, io::Result<(usize, SocketAddr)>>;
}

/// Relays datagrams between `stream` (framed by `codec`) and a session of
/// `outbound`. Returns when either side ends, the session idles out or the
/// user is removed.
pub async fn relay_datagrams(
    stream: BoxStream,
    codec: &dyn DatagramCodec,
    outbound: &dyn UdpOutbound,
    user: Option<Arc<UserEntry>>,
    stats: &Arc<InboundStats>,
) {
    let Ok(session) = outbound.bind().await else {
        stats.connect_failed.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let started = Instant::now();
    let last_active = AtomicU64::new(0);
    let touch = || {
        last_active.store(started.elapsed().as_millis() as u64, Ordering::Relaxed);
    };
    let (mut reader, mut writer) = tokio::io::split(stream);

    let uplink = async {
        while let Ok(Some((target, payload))) = codec.read(&mut reader).await {
            touch();
            let bytes = payload.len() as u64;
            stats.bytes_up.fetch_add(bytes, Ordering::Relaxed);
            if let Some(user) = &user {
                user.add_up(bytes);
            }
            // A refused target drops this datagram only.
            let _ = session.send_to(&payload, &target).await;
        }
    };
    let downlink = async {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let mut frame = Vec::new();
        while let Ok((n, source)) = session.recv_from(&mut buf).await {
            touch();
            frame.clear();
            if codec.encode(source, &buf[..n], &mut frame).is_err() {
                continue;
            }
            if writer.write_all(&frame).await.is_err() || writer.flush().await.is_err() {
                return;
            }
            let bytes = n as u64;
            stats.bytes_down.fetch_add(bytes, Ordering::Relaxed);
            if let Some(user) = &user {
                user.add_down(bytes);
            }
        }
    };
    let idle = async {
        loop {
            let last = Duration::from_millis(last_active.load(Ordering::Relaxed));
            let deadline = started + last + UDP_IDLE_TIMEOUT;
            if Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep_until(deadline).await;
        }
    };
    let revoked = async {
        match &user {
            Some(user) => user.revoked().await,
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        _ = uplink => {}
        _ = downlink => {}
        _ = idle => {}
        _ = revoked => {
            stats.revoked.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// UDP served on the same port as a [`StreamInbound`](crate::StreamInbound),
/// as Shadowsocks does; see [`StreamInbound::datagram`](crate::StreamInbound::datagram).
pub trait DatagramInbound: Send + Sync {
    /// Serves on `socket` until the socket fails or the future is dropped.
    fn serve(
        self: Arc<Self>,
        socket: std::net::UdpSocket,
        outbound: Arc<dyn UdpOutbound>,
        stats: Arc<InboundStats>,
    ) -> BoxFuture<'static, io::Result<()>>;
}

/// Sessions one [`SessionRelay`] keeps open at once.
pub const MAX_SESSIONS: usize = 1024;

/// Sends the replies of a [`SessionRelay`] to the client.
pub trait ReplySink: Send + Sync {
    /// Sends one reply of `session` from `source`. Returns `false` when the
    /// session cannot reach the client any more and should end.
    fn reply<'a>(
        &'a self,
        session: u64,
        source: SocketAddr,
        payload: &'a [u8],
    ) -> BoxFuture<'a, bool>;
}

/// Many UDP sessions keyed by the protocol's session id, each with its own
/// socket from a [`UdpOutbound`]: the sessions of one QUIC connection, or of
/// every client of a Shadowsocks UDP port.
///
/// A session opens with its first datagram and ends after
/// [`UDP_IDLE_TIMEOUT`] without traffic, when its user is removed, on
/// [`dissociate`](Self::dissociate) or [`close`](Self::close). Payload bytes
/// are charged to the session's user.
pub struct SessionRelay {
    outbound: Arc<dyn UdpOutbound>,
    sink: Arc<dyn ReplySink>,
    stats: Arc<InboundStats>,
    started: Instant,
    sessions: Mutex<HashMap<u64, RelayEntry>>,
}

struct RelayEntry {
    socket: Arc<dyn UdpSession>,
    last_active: Arc<AtomicU64>,
    downlink: JoinHandle<()>,
}

impl Drop for RelayEntry {
    fn drop(&mut self) {
        self.downlink.abort();
    }
}

impl SessionRelay {
    pub fn new(
        outbound: Arc<dyn UdpOutbound>,
        sink: Arc<dyn ReplySink>,
        stats: Arc<InboundStats>,
    ) -> Arc<Self> {
        Arc::new(Self {
            outbound,
            sink,
            stats,
            started: Instant::now(),
            sessions: Mutex::default(),
        })
    }

    /// Sends one client datagram of `session` to `target`, opening the
    /// session for `user` first if needed. A removed user's datagram ends its
    /// session instead.
    pub async fn send(
        self: &Arc<Self>,
        session: u64,
        user: Option<&Arc<UserEntry>>,
        target: &TargetAddr,
        payload: &[u8],
    ) {
        if user.is_some_and(|user| user.is_revoked()) {
            self.dissociate(session);
            return;
        }
        let existing = self.lock().get(&session).map(|entry| {
            entry.last_active.store(self.now(), Ordering::Relaxed);
            entry.socket.clone()
        });
        let socket = match existing {
            Some(socket) => socket,
            None => match self.open(session, user.cloned()).await {
                Some(socket) => socket,
                None => return,
            },
        };
        let bytes = payload.len() as u64;
        self.stats.bytes_up.fetch_add(bytes, Ordering::Relaxed);
        if let Some(user) = user {
            user.add_up(bytes);
        }
        // A refused target drops this datagram only.
        let _ = socket.send_to(payload, target).await;
    }

    /// Ends one session.
    pub fn dissociate(&self, session: u64) {
        let removed = self.lock().remove(&session);
        drop(removed);
    }

    /// Ends every session. Call it when the client connection ends: the
    /// sessions' reply tasks keep the relay alive until then.
    pub fn close(&self) {
        let removed = std::mem::take(&mut *self.lock());
        drop(removed);
    }

    /// True while `session` is open.
    pub fn contains(&self, session: u64) -> bool {
        self.lock().contains_key(&session)
    }

    async fn open(
        self: &Arc<Self>,
        session: u64,
        user: Option<Arc<UserEntry>>,
    ) -> Option<Arc<dyn UdpSession>> {
        if self.lock().len() >= MAX_SESSIONS {
            return None;
        }
        let Ok(socket) = self.outbound.bind().await else {
            self.stats.connect_failed.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        let last_active = Arc::new(AtomicU64::new(self.now()));
        let downlink =
            tokio::spawn(
                self.clone()
                    .downlink(session, socket.clone(), user, last_active.clone()),
            );
        let previous = self.lock().insert(
            session,
            RelayEntry {
                socket: socket.clone(),
                last_active,
                downlink,
            },
        );
        drop(previous);
        Some(socket)
    }

    async fn downlink(
        self: Arc<Self>,
        session: u64,
        socket: Arc<dyn UdpSession>,
        user: Option<Arc<UserEntry>>,
        last_active: Arc<AtomicU64>,
    ) {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            let idle_for = Duration::from_millis(
                self.now()
                    .saturating_sub(last_active.load(Ordering::Relaxed)),
            );
            let Some(left) = UDP_IDLE_TIMEOUT
                .checked_sub(idle_for)
                .filter(|left| !left.is_zero())
            else {
                break;
            };
            let revoked = async {
                match &user {
                    Some(user) => user.revoked().await,
                    None => std::future::pending().await,
                }
            };
            let received = tokio::select! {
                received = tokio::time::timeout(left, socket.recv_from(&mut buf)) => received,
                _ = revoked => {
                    self.stats.revoked.fetch_add(1, Ordering::Relaxed);
                    break;
                }
            };
            let (n, source) = match received {
                Err(_) => continue,
                Ok(Err(_)) => break,
                Ok(Ok(received)) => received,
            };
            last_active.store(self.now(), Ordering::Relaxed);
            if !self.sink.reply(session, source, &buf[..n]).await {
                break;
            }
            let bytes = n as u64;
            self.stats.bytes_down.fetch_add(bytes, Ordering::Relaxed);
            if let Some(user) = &user {
                user.add_down(bytes);
            }
        }
        // Only this session's own entry: a newer one under the same id
        // has another socket.
        let mut sessions = self.lock();
        if sessions
            .get(&session)
            .is_some_and(|entry| Arc::ptr_eq(&entry.socket, &socket))
        {
            let removed = sessions.remove(&session);
            drop(sessions);
            drop(removed);
        }
    }

    fn now(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<u64, RelayEntry>> {
        self.sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Unfiltered UDP outbound with one socket per session on a fixed local
/// address, such as `127.0.0.1:0` in tests. A node uses its filtered direct
/// outbound instead.
pub struct BoundUdpOutbound {
    local: SocketAddr,
}

impl BoundUdpOutbound {
    pub fn new(local: SocketAddr) -> Self {
        Self { local }
    }
}

impl UdpOutbound for BoundUdpOutbound {
    fn bind(&self) -> BoxFuture<'_, io::Result<Arc<dyn UdpSession>>> {
        Box::pin(async move {
            let socket = tokio::net::UdpSocket::bind(self.local).await?;
            Ok(Arc::new(BoundUdpSession(socket)) as Arc<dyn UdpSession>)
        })
    }
}

struct BoundUdpSession(tokio::net::UdpSocket);

impl UdpSession for BoundUdpSession {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        target: &'a TargetAddr,
    ) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            self.0
                .send_to(payload, (target.host(), target.port()))
                .await
                .map(|_| ())
        })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, io::Result<(usize, SocketAddr)>> {
        Box::pin(self.0.recv_from(buf))
    }
}
