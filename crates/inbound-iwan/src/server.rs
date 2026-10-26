//! The serve loop of one inbound: sessions (spec §12.1), the shared
//! userspace stack (§12.3) and the packet paths between them.
//!
//! - The UDP socket's datagrams are handled in place: OPEN, ECHOREQ and
//!   CLOSE answer at once; DATA is unmasked, checked against the session's
//!   address and goes to the gateway (ping, DNS), another user (when
//!   allowed) or the stack.
//! - The stack's TCP connections are relayed like proxy streams; its UDP
//!   datagrams go to a per-session queue whose worker relays them through a
//!   [`SessionRelay`] keyed by the client's port, and replies come back
//!   through the stack. Packets the stack emits are sent to the session that
//!   owns their destination address, fragmented to its MTU.
//! - A sweep each second ends sessions that were idle for a minute or whose
//!   user was removed, and reclaims addresses.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use engine_inbound::server::{relay_accepted, InboundStats, ServeSettings};
use engine_inbound::udp::{ReplySink, SessionRelay, UdpOutbound};
use engine_inbound::users::OnlineGuard;
use engine_inbound::{Accepted, UserEntry};
use engine_outbound::{BoxFuture, TargetAddr, TcpOutbound};
use futures::{SinkExt, StreamExt};
use netstack_smoltcp::udp::UdpMsg;
use netstack_smoltcp::StackBuilder;
use outbound_iwan::crypto::{self, XorKey, PASSWORD_BLOCK};
use outbound_iwan::packet::{self, kind, reject, tlv, Header, HEADER_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::{JoinHandle, JoinSet};

use crate::ip::{self, Ipv4};
use crate::pool::Pool;
use crate::IwanInbound;

/// A session that sends nothing for this long ends; clients ECHO every two
/// seconds.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const SWEEP_EVERY: Duration = Duration::from_secs(1);
const DEFAULT_CLIENT_MTU: u16 = 1400;
const MIN_CLIENT_MTU: u16 = 46;
const MAX_CLIENT_MTU: u16 = 1600;
/// Packets waiting to enter the stack; more are dropped like on a busy link.
const STACK_QUEUE: usize = 1024;
/// Datagrams waiting for one session's UDP worker.
const UDP_QUEUE: usize = 256;
/// TCP window of the stack, each direction of each connection.
const TCP_BUFFER_BYTES: u32 = 128 * 1024;
/// Larger than any DATA a client sends (MTU at most 1600).
const RECV_BUFFER: usize = 4096;
const DNS_PORT: u16 = 53;
/// Relay key bit of DNS queries to the gateway, whose replies must come
/// from the gateway rather than the upstream resolver.
const DNS_KEY: u64 = 1 << 16;

/// Runs the inbound on `socket` until it fails or the future is dropped.
pub(crate) async fn serve(
    inbound: Arc<IwanInbound>,
    socket: std::net::UdpSocket,
    outbound: Arc<dyn TcpOutbound>,
    udp: Option<Arc<dyn UdpOutbound>>,
    settings: ServeSettings,
    stats: Arc<InboundStats>,
) -> io::Result<()> {
    socket.set_nonblocking(true)?;
    let socket = Arc::new(UdpSocket::from_std(socket)?);
    let (stack, runner, stack_udp, tcp_listener) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .enable_icmp(false)
        .mtu(usize::from(inbound.config.mtu))
        .tcp_recv_buffer_size(TCP_BUFFER_BYTES)
        .tcp_send_buffer_size(TCP_BUFFER_BYTES)
        .build()?;
    let runner = runner.ok_or_else(|| io::Error::other("userspace TCP runner is unavailable"))?;
    let stack_udp =
        stack_udp.ok_or_else(|| io::Error::other("userspace UDP socket is unavailable"))?;
    let mut tcp_listener =
        tcp_listener.ok_or_else(|| io::Error::other("userspace TCP listener is unavailable"))?;
    let (mut stack_sink, mut stack_stream) = stack.split();
    let (mut udp_in, mut udp_out) = stack_udp.split();
    let (to_stack, mut stack_queue) = mpsc::channel::<Vec<u8>>(STACK_QUEUE);
    let (udp_replies, mut reply_queue) = mpsc::channel::<UdpMsg>(STACK_QUEUE);

    let server = Arc::new(Server {
        state: Mutex::new(State::new(Pool::new(inbound.config.pool))),
        inbound,
        socket: socket.clone(),
        stats: stats.clone(),
        udp,
        to_stack,
        udp_replies,
        random: SystemRandom::new(),
        started: Instant::now(),
    });

    // Dropping the set (the inbound was removed) stops every task.
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        let _ = runner.await;
    });
    tasks.spawn(async move {
        while let Some(packet) = stack_queue.recv().await {
            // A packet the stack refuses is skipped.
            let _ = stack_sink.send(packet).await;
        }
    });
    tasks.spawn({
        let server = server.clone();
        async move {
            while let Some(packet) = stack_stream.next().await {
                if let Ok(packet) = packet {
                    server.deliver(&packet).await;
                }
            }
        }
    });
    tasks.spawn(async move {
        while let Some(reply) = reply_queue.recv().await {
            if udp_out.send(reply).await.is_err() {
                break;
            }
        }
    });
    tasks.spawn({
        let server = server.clone();
        async move {
            while let Some((payload, src, dst)) = udp_in.next().await {
                server.stack_datagram(payload, src, dst);
            }
        }
    });
    tasks.spawn({
        let server = server.clone();
        async move {
            let permits = Arc::new(Semaphore::new(settings.max_connections));
            let settings = Arc::new(settings);
            while let Some((stream, client, target)) = tcp_listener.next().await {
                let Some(session) = server.session_of(client.ip()) else {
                    continue;
                };
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    stats.rejected.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                let accepted = Accepted {
                    user: Some(session.user.clone()),
                    target: TargetAddr::Ip(target),
                    stream: Box::new(stream),
                    udp: None,
                    mux: false,
                };
                let (outbound, settings, stats) =
                    (outbound.clone(), settings.clone(), stats.clone());
                tokio::spawn(async move {
                    let _permit = permit;
                    relay_accepted(accepted, session.peer, outbound.as_ref(), &settings, &stats)
                        .await;
                });
            }
        }
    });
    tasks.spawn({
        let server = server.clone();
        async move {
            let mut ticks = tokio::time::interval(SWEEP_EVERY);
            loop {
                ticks.tick().await;
                server.sweep();
            }
        }
    });

    let mut buffer = vec![0u8; RECV_BUFFER];
    loop {
        let (len, peer) = match socket.recv_from(&mut buffer).await {
            Ok(received) => received,
            // Windows reports an earlier send's ICMP port unreachable here.
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => continue,
            Err(error) => return Err(error),
        };
        server.datagram(&buffer[..len], peer).await;
    }
}

/// One logged-in client.
struct Session {
    peer: SocketAddr,
    header: packet::Session,
    user: Arc<UserEntry>,
    address: Ipv4Addr,
    mtu: usize,
    xor: Option<XorKey>,
    /// Milliseconds since the server started.
    last_seen: AtomicU64,
    udp: Option<UdpSide>,
    _online: OnlineGuard,
}

struct UdpSide {
    queue: mpsc::Sender<(Vec<u8>, u16, SocketAddrV4)>,
    relay: Arc<SessionRelay>,
    worker: JoinHandle<()>,
}

impl Session {
    fn close(&self) {
        if let Some(udp) = &self.udp {
            udp.worker.abort();
            udp.relay.close();
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.close();
    }
}

struct State {
    by_peer: HashMap<SocketAddr, Arc<Session>>,
    by_address: HashMap<Ipv4Addr, Arc<Session>>,
    /// The peer of each user's session, by user name.
    by_user: HashMap<String, SocketAddr>,
    pool: Pool,
}

impl State {
    fn new(pool: Pool) -> Self {
        Self {
            by_peer: HashMap::new(),
            by_address: HashMap::new(),
            by_user: HashMap::new(),
            pool,
        }
    }

    fn remove(&mut self, peer: SocketAddr, now: Instant) {
        let Some(session) = self.by_peer.remove(&peer) else {
            return;
        };
        if self
            .by_address
            .get(&session.address)
            .is_some_and(|owner| Arc::ptr_eq(owner, &session))
        {
            self.by_address.remove(&session.address);
        }
        if self.by_user.get(session.user.name()) == Some(&peer) {
            self.by_user.remove(session.user.name());
        }
        self.pool.release(session.user.name(), now);
        session.close();
    }
}

struct Server {
    inbound: Arc<IwanInbound>,
    socket: Arc<UdpSocket>,
    stats: Arc<InboundStats>,
    udp: Option<Arc<dyn UdpOutbound>>,
    to_stack: mpsc::Sender<Vec<u8>>,
    udp_replies: mpsc::Sender<UdpMsg>,
    state: Mutex<State>,
    random: SystemRandom,
    started: Instant,
}

impl Server {
    async fn datagram(&self, datagram: &[u8], peer: SocketAddr) {
        let Some(header) = Header::decode(datagram) else {
            return;
        };
        match header.kind {
            kind::OPEN => {
                let reply = match self.open(datagram, peer) {
                    Ok(ack) => ack,
                    Err(reason) => {
                        self.stats.handshake_failed.fetch_add(1, Ordering::Relaxed);
                        packet::encode_open_rej_with(reason.as_bytes())
                    }
                };
                let _ = self.socket.send_to(&reply, peer).await;
            }
            kind::DATA | kind::DATA_ENC => self.data(header, &datagram[HEADER_LEN..], peer).await,
            kind::ECHOREQ => {
                let Some((header, payload)) = packet::verify_signed(datagram) else {
                    return;
                };
                let Some(session) = self.session(peer, &header) else {
                    return;
                };
                self.touch(&session);
                let reply = packet::signed(Header::new(kind::ECHORESP, 0, session.header), payload);
                let _ = self.socket.send_to(&reply, peer).await;
            }
            kind::CLOSE => {
                let Some((header, _)) = packet::verify_signed(datagram) else {
                    return;
                };
                if self.session(peer, &header).is_some() {
                    self.lock().remove(peer, Instant::now());
                }
            }
            _ => {}
        }
    }

    /// Authenticates an OPEN and starts its session; the OPENACK, or the
    /// reason sent in the OPENREJ.
    fn open(&self, datagram: &[u8], peer: SocketAddr) -> Result<Vec<u8>, &'static str> {
        // Malformed requests get the same answer as a wrong password, like
        // the Panabit server.
        let invalid = reject::INVALID_PASSWORD;
        let open = packet::decode_open(datagram).ok_or(invalid)?;
        let login = open.username.ok_or(invalid)?;
        let block = open.password_block.ok_or(invalid)?;
        let client_mtu = match open.mtu {
            None => DEFAULT_CLIENT_MTU,
            Some(mtu) if (MIN_CLIENT_MTU..=MAX_CLIENT_MTU).contains(&mtu) => mtu,
            Some(_) => return Err(invalid),
        };
        let user = self.inbound.logins.get(&login).ok_or(invalid)?;
        let password = user.user().password.as_deref().ok_or(invalid)?.as_bytes();
        if !same_block(&crypto::encrypt_password(&login, password), &block) {
            return Err(invalid);
        }
        let encrypt = (open.flags != 0 || open.encrypt.unwrap_or(0) != 0)
            && self.inbound.config.allow_encrypt;
        let xor = encrypt.then(|| XorKey::new(&login, password));
        let mut token = [0u8; 2];
        let mut id = [0u8; 4];
        self.random.fill(&mut token).map_err(|_| invalid)?;
        self.random.fill(&mut id).map_err(|_| invalid)?;
        let header = packet::Session { token, id };
        let mtu = client_mtu.min(self.inbound.config.mtu);
        let fixed = match user.user().address {
            Some(IpAddr::V4(address)) => Some(address),
            _ => None,
        };
        let gateway = self.inbound.config.pool.gateway();
        let name = user.name().to_owned();
        let now = Instant::now();

        let mut state = self.lock();
        // A new login from this source or of this user replaces the old
        // session; clients reconnect from a new port after a reset.
        state.remove(peer, now);
        if let Some(previous) = state.by_user.get(&name).copied() {
            state.remove(previous, now);
        }
        let fixed_index = &self.inbound.fixed;
        let (address, evicted) = state
            .pool
            .acquire(
                &name,
                fixed,
                |candidate| fixed_index.get(&candidate).is_some(),
                now,
            )
            .ok_or(reject::NO_FREE_ADDRESS)?;
        if let Some(evicted) = evicted {
            if let Some(holder) = state.by_user.get(&evicted).copied() {
                state.remove(holder, now);
            }
        }
        let udp = self.udp.as_ref().map(|outbound| {
            let sink = Arc::new(Replies {
                address,
                gateway,
                writer: self.udp_replies.clone(),
            });
            let relay = SessionRelay::new(outbound.clone(), sink, self.stats.clone());
            let (queue, receiver) = mpsc::channel(UDP_QUEUE);
            let worker = tokio::spawn(udp_worker(
                receiver,
                relay.clone(),
                user.clone(),
                gateway,
                self.inbound.config.dns_upstream,
            ));
            UdpSide {
                queue,
                relay,
                worker,
            }
        });
        let session = Arc::new(Session {
            peer,
            header,
            _online: user.connect(peer.ip()),
            user,
            address,
            mtu: usize::from(mtu),
            xor,
            last_seen: AtomicU64::new(self.now_ms()),
            udp,
        });
        state.by_peer.insert(peer, session.clone());
        state.by_address.insert(address, session);
        state.by_user.insert(name, peer);
        drop(state);
        self.stats.accepted.fetch_add(1, Ordering::Relaxed);

        let encrypt = u8::from(encrypt);
        Ok(packet::encode_open_ack(
            header,
            encrypt,
            &[
                (tlv::MTU, &mtu.to_be_bytes()),
                (tlv::ADDRESS, &address.octets()),
                (tlv::DNS0, &gateway.octets()),
                (tlv::ENCRYPT, &[encrypt]),
            ],
        ))
    }

    async fn data(&self, header: Header, payload: &[u8], peer: SocketAddr) {
        let Some(session) = self.session(peer, &header) else {
            return;
        };
        if (header.kind == kind::DATA_ENC) != session.xor.is_some() {
            return;
        }
        let mut packet = payload.to_vec();
        if let Some(xor) = &session.xor {
            xor.apply(&mut packet);
        }
        let Some(ip) = Ipv4::parse(&packet) else {
            return;
        };
        if ip.src != session.address {
            return;
        }
        self.touch(&session);
        let pool = self.inbound.config.pool;
        if ip.dst == pool.gateway() {
            if let Some(reply) = ip::echo_reply(&packet) {
                self.transmit(&session, &reply).await;
                return;
            }
            // DNS is the gateway's only service.
            if ip.protocol != ip::UDP {
                return;
            }
        } else if pool.contains(ip.dst) {
            self.forward(&session, ip.dst, &packet).await;
            return;
        }
        if !matches!(ip.protocol, ip::TCP | ip::UDP)
            || ip.dst.is_broadcast()
            || ip.dst.is_multicast()
            || ip.dst.is_unspecified()
        {
            return;
        }
        // A full queue drops the packet; TCP retransmits.
        let _ = self.to_stack.try_send(packet);
    }

    /// A packet from one user to another's address.
    async fn forward(&self, from: &Session, to: Ipv4Addr, packet: &[u8]) {
        if !self.inbound.config.allow_client_to_client {
            return;
        }
        let Some(target) = self.lock().by_address.get(&to).cloned() else {
            return;
        };
        let bytes = packet.len() as u64;
        from.user.add_up(bytes);
        target.user.add_down(bytes);
        self.stats.bytes_up.fetch_add(bytes, Ordering::Relaxed);
        self.stats.bytes_down.fetch_add(bytes, Ordering::Relaxed);
        self.transmit(&target, packet).await;
    }

    /// A packet the stack emitted, to the session owning its destination.
    async fn deliver(&self, packet: &[u8]) {
        let Some(ip) = Ipv4::parse(packet) else {
            return;
        };
        if let Some(session) = self.session_of(IpAddr::V4(ip.dst)) {
            self.transmit(&session, packet).await;
        }
    }

    /// A datagram the stack terminated, to its session's UDP worker.
    fn stack_datagram(&self, payload: Vec<u8>, src: SocketAddr, dst: SocketAddr) {
        let (SocketAddr::V4(src), SocketAddr::V4(dst)) = (src, dst) else {
            return;
        };
        let Some(session) = self.session_of(IpAddr::V4(*src.ip())) else {
            return;
        };
        if let Some(udp) = &session.udp {
            let _ = udp.queue.try_send((payload, src.port(), dst));
        }
    }

    async fn transmit(&self, session: &Session, packet: &[u8]) {
        for piece in ip::fragment(packet, session.mtu) {
            let datagram = packet::encode_data(session.header, session.xor.as_ref(), &piece);
            let _ = self.socket.send_to(&datagram, session.peer).await;
        }
    }

    fn sweep(&self) {
        let now_ms = self.now_ms();
        let idle_ms = IDLE_TIMEOUT.as_millis() as u64;
        let now = Instant::now();
        let mut state = self.lock();
        let stale: Vec<SocketAddr> = state
            .by_peer
            .iter()
            .filter(|(_, session)| {
                session.user.is_revoked()
                    || now_ms.saturating_sub(session.last_seen.load(Ordering::Relaxed)) >= idle_ms
            })
            .map(|(peer, _)| *peer)
            .collect();
        for peer in stale {
            state.remove(peer, now);
        }
        state.pool.expire(now);
    }

    /// The session of `peer` when the header carries its identifiers.
    fn session(&self, peer: SocketAddr, header: &Header) -> Option<Arc<Session>> {
        self.lock()
            .by_peer
            .get(&peer)
            .filter(|session| session.header == header.session)
            .cloned()
    }

    fn session_of(&self, address: IpAddr) -> Option<Arc<Session>> {
        let IpAddr::V4(address) = address else {
            return None;
        };
        self.lock().by_address.get(&address).cloned()
    }

    fn touch(&self, session: &Session) {
        session.last_seen.store(self.now_ms(), Ordering::Relaxed);
    }

    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Compares password blocks in constant time.
fn same_block(a: &[u8; PASSWORD_BLOCK], b: &[u8; PASSWORD_BLOCK]) -> bool {
    let difference = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(difference) == 0
}

/// Relays one session's UDP datagrams: queries to the gateway's port 53 go
/// to the upstream resolver, everything else to its destination.
async fn udp_worker(
    mut queue: mpsc::Receiver<(Vec<u8>, u16, SocketAddrV4)>,
    relay: Arc<SessionRelay>,
    user: Arc<UserEntry>,
    gateway: Ipv4Addr,
    dns_upstream: SocketAddr,
) {
    while let Some((payload, port, dst)) = queue.recv().await {
        let (key, target) = if *dst.ip() == gateway {
            if dst.port() != DNS_PORT {
                continue;
            }
            (DNS_KEY | u64::from(port), TargetAddr::Ip(dns_upstream))
        } else {
            (u64::from(port), TargetAddr::Ip(SocketAddr::V4(dst)))
        };
        relay.send(key, Some(&user), &target, &payload).await;
    }
}

/// Sends a session's UDP replies back through the stack.
struct Replies {
    address: Ipv4Addr,
    gateway: Ipv4Addr,
    writer: mpsc::Sender<UdpMsg>,
}

impl ReplySink for Replies {
    fn reply<'a>(
        &'a self,
        session: u64,
        source: SocketAddr,
        payload: &'a [u8],
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            let source = if session & DNS_KEY != 0 {
                SocketAddr::new(self.gateway.into(), DNS_PORT)
            } else {
                match source.ip().to_canonical() {
                    IpAddr::V4(ip) => SocketAddr::new(ip.into(), source.port()),
                    // The tunnel carries IPv4 only.
                    IpAddr::V6(_) => return true,
                }
            };
            let client = SocketAddr::new(self.address.into(), session as u16);
            self.writer
                .send((payload.to_vec(), source, client))
                .await
                .is_ok()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_blocks() {
        let a = [7u8; PASSWORD_BLOCK];
        let mut b = a;
        assert!(same_block(&a, &b));
        b[15] ^= 1;
        assert!(!same_block(&a, &b));
    }
}
