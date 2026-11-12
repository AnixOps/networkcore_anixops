//! One WireGuard node at run time: the Noise session (boringtun's `Tunn`) on
//! one connected UDP socket, and the node's private userspace TCP/IP stack
//! (smoltcp) that owns the interface addresses.
//!
//! The driver task starts with the first connection and stops after the
//! node has had no connection for [`IDLE_RELEASE`]. The stack and the Noise
//! state outlive the driver, so a restart only resolves the endpoint again.
//!
//! AllowedIPs is applied in both directions: the outbound
//! refuses connections to other addresses, and packets that come out of the
//! tunnel with a source outside it are dropped before the stack sees them.

use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::Poll as TaskPoll;
use std::time::{Duration, Instant};

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp, AnySocket};
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use tokio::net::UdpSocket;
use tokio::sync::Notify;

use crate::config::WireGuardSettings;
use crate::dns;

/// boringtun's timers have a 250 ms granularity.
const TIMER_TICK: Duration = Duration::from_millis(250);
/// The driver stops after this long without connections.
pub const IDLE_RELEASE: Duration = Duration::from_secs(60);
/// A closed TCP socket is removed after this long even without a final ACK.
const LINGER: Duration = Duration::from_secs(30);
/// Packets out of the tunnel queued for the stack between two polls.
const STACK_QUEUE: usize = 1024;
/// A UDP datagram is at most 64 KiB; boringtun needs 148 bytes at least.
const DATAGRAM_BYTES: usize = 65_536 + 148;
const UDP_PACKETS: usize = 32;
pub(crate) const UDP_BUFFER: usize = 16 * 1024;
const DNS_TIMEOUT: Duration = Duration::from_secs(2);
const DNS_ATTEMPTS: usize = 2;
const DNS_MIN_TTL: u32 = 30;
const DNS_MAX_TTL: u32 = 600;
const DNS_CACHE_ENTRIES: usize = 256;
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
/// Back-off after a socket error such as ICMP port unreachable.
const ERROR_BACKOFF: Duration = Duration::from_millis(250);
const FIRST_LOCAL_PORT: u16 = 49152;

/// Packet queues between the stack and the Noise session.
struct QueueDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl Device for QueueDevice {
    type RxToken<'a> = QueueRx;
    type TxToken<'a> = QueueTx<'a>;

    fn receive(&mut self, _now: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((QueueRx(packet), QueueTx(&mut self.tx)))
    }

    fn transmit(&mut self, _now: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(QueueTx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities
    }
}

struct QueueRx(Vec<u8>);

impl RxToken for QueueRx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct QueueTx<'a>(&'a mut VecDeque<Vec<u8>>);

impl TxToken for QueueTx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0u8; len];
        let result = f(&mut packet);
        self.0.push_back(packet);
        result
    }
}

/// The private stack with the interface addresses.
struct Stack {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: QueueDevice,
    /// TCP sockets whose stream was dropped, waiting for the close to finish.
    closing: Vec<(SocketHandle, Instant)>,
}

impl Stack {
    fn new(settings: &WireGuardSettings, now: SmolInstant, seed: u64) -> Self {
        let mut device = QueueDevice {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu: usize::from(settings.mtu),
        };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = seed;
        let mut iface = Interface::new(config, &mut device, now);
        iface.update_ip_addrs(|addrs| {
            if let Some(v4) = settings.local_v4 {
                let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(v4), 32));
            }
            if let Some(v6) = settings.local_v6 {
                let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(v6), 128));
            }
        });
        // Every destination is behind the tunnel; an IP medium needs no
        // neighbor, so the gateway is only a placeholder.
        if let Some(v4) = settings.local_v4 {
            let _ = iface.routes_mut().add_default_ipv4_route(v4);
        }
        if let Some(v6) = settings.local_v6 {
            let _ = iface.routes_mut().add_default_ipv6_route(v6);
        }
        Self {
            iface,
            sockets: SocketSet::new(Vec::new()),
            device,
            closing: Vec::new(),
        }
    }

    fn has_sockets(&self) -> bool {
        self.sockets.iter().next().is_some()
    }

    /// Ends every connection, waking their tasks.
    fn abort_all(&mut self) {
        for (_, socket) in self.sockets.iter_mut() {
            match socket {
                smoltcp::socket::Socket::Tcp(socket) => socket.abort(),
                smoltcp::socket::Socket::Udp(socket) => socket.close(),
                #[allow(unreachable_patterns)]
                _ => {}
            }
        }
        self.device.rx.clear();
        self.device.tx.clear();
    }

    fn sweep(&mut self, now: Instant) {
        let sockets = &mut self.sockets;
        self.closing.retain(|(handle, since)| {
            let socket = sockets.get_mut::<tcp::Socket>(*handle);
            let done = matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait);
            if done || now.saturating_duration_since(*since) > LINGER {
                socket.abort();
                sockets.remove(*handle);
                false
            } else {
                true
            }
        });
    }
}

struct Core {
    tunn: Tunn,
    stack: Stack,
    running: bool,
    /// Identifies the current driver task.
    run: u64,
    /// Why the last driver could not run, for connections that failed.
    failure: Option<&'static str>,
    /// Connections being set up that hold no socket yet.
    pending: usize,
    idle_since: Option<Instant>,
    next_port: u16,
    dns_cache: HashMap<String, (IpAddr, Instant)>,
}

impl Core {
    fn next_port(&mut self) -> u16 {
        let port = self.next_port;
        self.next_port = if port == u16::MAX {
            FIRST_LOCAL_PORT
        } else {
            port + 1
        };
        port
    }
}

pub(crate) struct Node {
    settings: WireGuardSettings,
    core: Mutex<Core>,
    wake: Notify,
    epoch: Instant,
}

impl Node {
    pub(crate) fn new(settings: WireGuardSettings) -> Arc<Self> {
        let epoch = Instant::now();
        let tunn = Tunn::new(
            StaticSecret::from(settings.private_key),
            PublicKey::from(settings.peer_public_key),
            settings.preshared_key,
            settings.persistent_keepalive_secs,
            // boringtun shifts the index left by 8 bits.
            (random() as u32) >> 8,
            None,
        );
        let stack = Stack::new(&settings, SmolInstant::from_micros(0), random());
        let next_port = FIRST_LOCAL_PORT + (random() % 16384) as u16;
        Arc::new(Self {
            settings,
            core: Mutex::new(Core {
                tunn,
                stack,
                running: false,
                run: 0,
                failure: None,
                pending: 0,
                idle_since: None,
                next_port,
                dns_cache: HashMap::new(),
            }),
            wake: Notify::new(),
            epoch,
        })
    }

    pub(crate) fn settings(&self) -> &WireGuardSettings {
        &self.settings
    }

    fn lock(&self) -> MutexGuard<'_, Core> {
        // The lock is never held across an await; a poisoned lock only means
        // a panic in smoltcp or boringtun, and the state is still usable.
        self.core
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn now(&self) -> SmolInstant {
        let micros = Instant::now()
            .saturating_duration_since(self.epoch)
            .as_micros();
        SmolInstant::from_micros(i64::try_from(micros).unwrap_or(i64::MAX))
    }

    /// Asks the driver to poll the stack, after a socket changed.
    pub(crate) fn wake(&self) {
        self.wake.notify_one();
    }

    /// Why the last driver stopped on an error, if it did.
    pub(crate) fn failure(&self) -> Option<&'static str> {
        self.lock().failure
    }

    /// Seconds since the last completed handshake, and whether the driver
    /// runs; for the outbound's health.
    pub(crate) fn health(&self) -> (Option<Duration>, bool) {
        let core = self.lock();
        (core.tunn.time_since_last_handshake(), core.running)
    }

    fn ensure_running(self: &Arc<Self>) {
        let run = {
            let mut core = self.lock();
            if core.running {
                return;
            }
            core.running = true;
            core.run += 1;
            core.failure = None;
            core.idle_since = None;
            core.run
        };
        tokio::spawn(drive(self.clone(), run));
    }

    /// Runs `f` on a socket of the stack.
    pub(crate) fn with_socket<T, R>(&self, handle: SocketHandle, f: impl FnOnce(&mut T) -> R) -> R
    where
        T: AnySocket<'static>,
    {
        let mut core = self.lock();
        f(core.stack.sockets.get_mut::<T>(handle))
    }

    /// Whether the interface has an address of `address`'s family.
    pub(crate) fn has_family(&self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(_) => self.settings.local_v4.is_some(),
            IpAddr::V6(_) => self.settings.local_v6.is_some(),
        }
    }

    /// Starts a TCP connection to `remote`.
    pub(crate) fn open_tcp(&self, remote: SocketAddr) -> io::Result<SocketHandle> {
        let buffer = self.settings.tcp_buffer_bytes as usize;
        let mut core = self.lock();
        let port = core.next_port();
        let mut socket = new_tcp_socket(buffer);
        socket
            .connect(core.stack.iface.context(), endpoint(remote), port)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "wireguard cannot reach this address",
                )
            })?;
        Ok(core.stack.sockets.add(socket))
    }

    /// Listens for one TCP connection on `port`.
    pub(crate) fn listen_tcp(&self, port: u16) -> io::Result<SocketHandle> {
        let buffer = self.settings.tcp_buffer_bytes as usize;
        let mut core = self.lock();
        let mut socket = new_tcp_socket(buffer);
        socket.listen(port).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "wireguard cannot listen there")
        })?;
        Ok(core.stack.sockets.add(socket))
    }

    /// Binds a UDP socket on `port` or an ephemeral one.
    pub(crate) fn open_udp(&self, port: Option<u16>) -> io::Result<SocketHandle> {
        let mut core = self.lock();
        let port = match port {
            Some(port) => port,
            None => core.next_port(),
        };
        let buffer = || {
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_PACKETS],
                vec![0u8; UDP_BUFFER],
            )
        };
        let mut socket = udp::Socket::new(buffer(), buffer());
        socket.bind(port).map_err(|_| {
            io::Error::new(
                io::ErrorKind::AddrInUse,
                "wireguard udp port is unavailable",
            )
        })?;
        Ok(core.stack.sockets.add(socket))
    }

    /// Closes a TCP socket gracefully; it is removed once the close finishes.
    pub(crate) fn release_tcp(&self, handle: SocketHandle) {
        {
            let mut core = self.lock();
            core.stack.sockets.get_mut::<tcp::Socket>(handle).close();
            core.stack.closing.push((handle, Instant::now()));
        }
        self.wake();
    }

    pub(crate) fn release_udp(&self, handle: SocketHandle) {
        self.lock().stack.sockets.remove(handle);
    }

    /// An address of `host` that the interface can reach and AllowedIPs
    /// permits: through the tunnel DNS when the config has one, else the
    /// system resolver.
    pub(crate) async fn resolve(self: &Arc<Self>, host: &str) -> io::Result<IpAddr> {
        let key = host.trim_end_matches('.').to_ascii_lowercase();
        {
            let core = self.lock();
            if let Some((address, expires)) = core.dns_cache.get(&key) {
                if *expires > Instant::now() {
                    return Ok(*address);
                }
            }
        }
        let (address, ttl) = if self.settings.dns.is_empty() {
            (self.resolve_system(&key).await?, DNS_MIN_TTL)
        } else {
            self.resolve_tunnel(&key).await?
        };
        let ttl = ttl.clamp(DNS_MIN_TTL, DNS_MAX_TTL);
        let mut core = self.lock();
        if core.dns_cache.len() >= DNS_CACHE_ENTRIES {
            core.dns_cache.clear();
        }
        core.dns_cache.insert(
            key,
            (
                address,
                Instant::now() + Duration::from_secs(u64::from(ttl)),
            ),
        );
        Ok(address)
    }

    fn usable(&self, address: IpAddr) -> bool {
        self.has_family(address) && self.settings.allowed_ips.contains(address)
    }

    async fn resolve_system(&self, host: &str) -> io::Result<IpAddr> {
        let lookup = tokio::net::lookup_host((host, 0));
        let addresses = tokio::time::timeout(RESOLVE_TIMEOUT, lookup)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "domain did not resolve"))??;
        addresses
            .map(|address| address.ip())
            .find(|address| self.usable(*address))
            .ok_or_else(no_usable_address)
    }

    async fn resolve_tunnel(self: &Arc<Self>, host: &str) -> io::Result<(IpAddr, u32)> {
        let mut kinds = Vec::with_capacity(2);
        if self.settings.local_v4.is_some() {
            kinds.push(dns::TYPE_A);
        }
        if self.settings.local_v6.is_some() {
            kinds.push(dns::TYPE_AAAA);
        }
        let socket = UdpHandle::open(self, None)?;
        'kinds: for kind in kinds {
            for _ in 0..DNS_ATTEMPTS {
                for server in &self.settings.dns {
                    let id = random() as u16;
                    let query = dns::query(id, host, kind).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "invalid domain name")
                    })?;
                    socket.send_to(&query, SocketAddr::new(*server, 53)).await?;
                    let answer = tokio::time::timeout(DNS_TIMEOUT, async {
                        loop {
                            let response = socket.recv().await?;
                            if let Some(answer) = dns::parse_response(id, &response) {
                                return Ok::<_, io::Error>(answer);
                            }
                        }
                    })
                    .await;
                    let answer = match answer {
                        Ok(answer) => answer?,
                        Err(_) => continue,
                    };
                    if let Some(address) = answer
                        .addresses
                        .iter()
                        .copied()
                        .find(|address| self.usable(*address))
                    {
                        return Ok((address, answer.ttl));
                    }
                    // A server answered without a usable record of this type.
                    continue 'kinds;
                }
            }
        }
        Err(no_usable_address())
    }

    /// Seals the stack's outgoing packets and runs the timers when due.
    /// Returns the datagrams to send, how long the driver may sleep, and
    /// whether it should stop.
    fn poll(&self, run: u64, timers_due: bool) -> Poll {
        let now = Instant::now();
        let timestamp = self.now();
        let reserved = self.settings.reserved;
        let mut guard = self.lock();
        let core = &mut *guard;
        if core.run != run || !core.running {
            return Poll::stop(Vec::new());
        }
        let mut datagrams = Vec::new();
        let mut delay = TIMER_TICK;
        let stack = &mut core.stack;
        stack
            .iface
            .poll(timestamp, &mut stack.device, &mut stack.sockets);
        stack.sweep(now);
        let mut buffer = vec![0u8; DATAGRAM_BYTES];
        while let Some(packet) = stack.device.tx.pop_front() {
            if let TunnResult::WriteToNetwork(datagram) =
                core.tunn.encapsulate(&packet, &mut buffer)
            {
                datagrams.push(seal(datagram, reserved));
            }
        }
        if timers_due {
            if let TunnResult::WriteToNetwork(datagram) = core.tunn.update_timers(&mut buffer) {
                datagrams.push(seal(datagram, reserved));
            }
        }
        if let Some(next) = stack.iface.poll_delay(timestamp, &stack.sockets) {
            delay = delay.min(Duration::from_micros(next.total_micros()));
        }
        let busy = core.pending > 0 || stack.has_sockets();
        if busy {
            core.idle_since = None;
        } else {
            let since = *core.idle_since.get_or_insert(now);
            if now.saturating_duration_since(since) >= IDLE_RELEASE {
                core.running = false;
                core.idle_since = None;
                return Poll::stop(datagrams);
            }
        }
        Poll {
            datagrams,
            delay,
            stop: false,
        }
    }

    /// Opens one datagram from the peer. Packets go to the stack when their
    /// source is inside AllowedIPs; replies (handshake responses, packets
    /// queued behind the handshake) are returned to send.
    fn receive(&self, datagram: &mut [u8], peer: IpAddr) -> Vec<Vec<u8>> {
        let reserved = self.settings.reserved;
        if reserved.is_some() && datagram.len() >= 4 {
            datagram[1..4].fill(0);
        }
        let mut replies = Vec::new();
        let mut buffer = vec![0u8; DATAGRAM_BYTES];
        let mut core = self.lock();
        let core = &mut *core;
        let mut input: &[u8] = datagram;
        loop {
            match core.tunn.decapsulate(Some(peer), input, &mut buffer) {
                // Handshake replies and queued packets: keep draining with an
                // empty datagram until boringtun reports it is done.
                TunnResult::WriteToNetwork(reply) => {
                    replies.push(seal(reply, reserved));
                    input = &[];
                }
                TunnResult::WriteToTunnelV4(packet, source) => {
                    deliver(&mut core.stack, &self.settings, packet, IpAddr::V4(source));
                    break;
                }
                TunnResult::WriteToTunnelV6(packet, source) => {
                    deliver(&mut core.stack, &self.settings, packet, IpAddr::V6(source));
                    break;
                }
                TunnResult::Done | TunnResult::Err(_) => break,
            }
        }
        replies
    }

    /// Stops the driver `run` after it could not start, failing every
    /// connection with `reason`.
    fn fail(&self, run: u64, reason: &'static str) {
        let mut core = self.lock();
        if core.run != run {
            return;
        }
        core.running = false;
        core.failure = Some(reason);
        core.stack.abort_all();
    }

    /// The first handshake initiation, sent when the driver starts.
    fn initiation(&self) -> Option<Vec<u8>> {
        let mut buffer = vec![0u8; 256];
        let mut core = self.lock();
        match core.tunn.format_handshake_initiation(&mut buffer, false) {
            TunnResult::WriteToNetwork(datagram) => Some(seal(datagram, self.settings.reserved)),
            _ => None,
        }
    }
}

/// Queues a packet from the tunnel for the stack, by cryptokey routing.
fn deliver(stack: &mut Stack, settings: &WireGuardSettings, packet: &[u8], source: IpAddr) {
    // A keepalive decrypts to an empty packet.
    if packet.is_empty() || !settings.allowed_ips.contains(source) {
        return;
    }
    if stack.device.rx.len() < STACK_QUEUE {
        stack.device.rx.push_back(packet.to_vec());
    }
}

/// Copies a sealed message out of the work buffer, with the reserved bytes.
fn seal(datagram: &[u8], reserved: Option<[u8; 3]>) -> Vec<u8> {
    let mut datagram = datagram.to_vec();
    if let Some(reserved) = reserved {
        if datagram.len() >= 4 {
            datagram[1..4].copy_from_slice(&reserved);
        }
    }
    datagram
}

struct Poll {
    datagrams: Vec<Vec<u8>>,
    delay: Duration,
    stop: bool,
}

impl Poll {
    fn stop(datagrams: Vec<Vec<u8>>) -> Self {
        Self {
            datagrams,
            delay: Duration::ZERO,
            stop: true,
        }
    }
}

/// Counts a connection being set up, which keeps the driver alive.
pub(crate) struct Pending<'a>(&'a Node);

impl<'a> Pending<'a> {
    pub(crate) fn new(node: &'a Arc<Node>) -> Self {
        node.lock().pending += 1;
        node.ensure_running();
        Self(node)
    }
}

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        self.0.lock().pending -= 1;
    }
}

/// Marks the driver stopped if its task ends without deciding to, such as
/// when the runtime shuts down.
struct RunGuard {
    node: Arc<Node>,
    run: u64,
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        let mut core = self.node.lock();
        if core.run == self.run && core.running {
            core.running = false;
            core.stack.abort_all();
        }
    }
}

async fn drive(node: Arc<Node>, run: u64) {
    let _guard = RunGuard {
        node: node.clone(),
        run,
    };
    let Some(server) = resolve_server(node.settings()).await else {
        node.fail(run, "wireguard endpoint did not resolve");
        return;
    };
    let Ok(socket) = connect_udp(server) else {
        node.fail(run, "wireguard endpoint is unreachable");
        return;
    };
    if let Some(initiation) = node.initiation() {
        let _ = socket.send(&initiation).await;
    }
    let mut datagram = vec![0u8; DATAGRAM_BYTES];
    let mut next_tick = Instant::now() + TIMER_TICK;
    let mut replies: Vec<Vec<u8>> = Vec::new();
    loop {
        for reply in replies.drain(..) {
            let _ = socket.send(&reply).await;
        }
        let now = Instant::now();
        let timers_due = now >= next_tick;
        if timers_due {
            next_tick = now + TIMER_TICK;
        }
        let poll = node.poll(run, timers_due);
        for sealed in &poll.datagrams {
            let _ = socket.send(sealed).await;
        }
        if poll.stop {
            return;
        }
        let wait = poll
            .delay
            .min(next_tick.saturating_duration_since(Instant::now()));
        tokio::select! {
            received = socket.recv(&mut datagram) => match received {
                Ok(len) => replies = node.receive(&mut datagram[..len], server.ip()),
                Err(_) => tokio::time::sleep(ERROR_BACKOFF).await,
            },
            _ = node.wake.notified() => {}
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

/// A connected UDP socket: the kernel then drops datagrams from any other
/// source.
fn connect_udp(server: SocketAddr) -> io::Result<UdpSocket> {
    let socket = engine_outbound::protect::bind_std_udp(
        engine_outbound::protect::unspecified_for(server),
        server,
    )?;
    socket.connect(server)?;
    UdpSocket::from_std(socket)
}

/// The endpoint address. The engine's own sockets never route through a
/// tunnel, so the system resolver is safe to use for it.
async fn resolve_server(settings: &WireGuardSettings) -> Option<SocketAddr> {
    if let Ok(address) = settings.server.parse::<IpAddr>() {
        return Some(SocketAddr::new(address, settings.port));
    }
    let lookup = tokio::net::lookup_host((settings.server.as_str(), settings.port));
    let addresses: Vec<SocketAddr> = tokio::time::timeout(RESOLVE_TIMEOUT, lookup)
        .await
        .ok()?
        .ok()?
        .collect();
    addresses
        .iter()
        .find(|address| address.is_ipv4())
        .or_else(|| addresses.first())
        .copied()
}

fn endpoint(address: SocketAddr) -> IpEndpoint {
    let ip = match address.ip() {
        IpAddr::V4(v4) => IpAddress::Ipv4(v4),
        IpAddr::V6(v6) => IpAddress::Ipv6(v6),
    };
    IpEndpoint::new(ip, address.port())
}

fn new_tcp_socket(buffer: usize) -> tcp::Socket<'static> {
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; buffer]),
        tcp::SocketBuffer::new(vec![0u8; buffer]),
    );
    socket.set_nagle_enabled(false);
    socket.set_keep_alive(Some(SmolDuration::from_secs(30)));
    socket.set_timeout(Some(SmolDuration::from_secs(120)));
    socket
}

pub(crate) fn closed() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionReset,
        "wireguard connection was closed",
    )
}

fn no_usable_address() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        "domain has no address the wireguard peer allows",
    )
}

/// Process-local randomness for DNS ids, ports, the session index and the
/// stack seed; none of it needs to be unpredictable.
fn random() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    hasher.finish()
}

/// A UDP socket of the private stack; removed when dropped.
pub(crate) struct UdpHandle {
    node: Arc<Node>,
    handle: SocketHandle,
}

impl UdpHandle {
    pub(crate) fn open(node: &Arc<Node>, port: Option<u16>) -> io::Result<Self> {
        let handle = node.open_udp(port)?;
        Ok(Self {
            node: node.clone(),
            handle,
        })
    }

    pub(crate) async fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<()> {
        if payload.len() > UDP_BUFFER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram is too large",
            ));
        }
        let target = endpoint(target);
        std::future::poll_fn(|cx| {
            self.node
                .with_socket::<udp::Socket, _>(self.handle, |socket| {
                    if !socket.is_open() {
                        return TaskPoll::Ready(Err(closed()));
                    }
                    match socket.send_slice(payload, target) {
                        Ok(()) => TaskPoll::Ready(Ok(())),
                        Err(udp::SendError::BufferFull) => {
                            socket.register_send_waker(cx.waker());
                            TaskPoll::Pending
                        }
                        Err(_) => TaskPoll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "wireguard cannot reach this address",
                        ))),
                    }
                })
        })
        .await?;
        self.node.wake();
        Ok(())
    }

    pub(crate) async fn recv(&self) -> io::Result<Vec<u8>> {
        std::future::poll_fn(|cx| {
            self.node
                .with_socket::<udp::Socket, _>(self.handle, |socket| {
                    if !socket.is_open() {
                        return TaskPoll::Ready(Err(closed()));
                    }
                    match socket.recv() {
                        Ok((payload, _)) => TaskPoll::Ready(Ok(payload.to_vec())),
                        Err(_) => {
                            socket.register_recv_waker(cx.waker());
                            TaskPoll::Pending
                        }
                    }
                })
        })
        .await
    }
}

impl Drop for UdpHandle {
    fn drop(&mut self) {
        self.node.release_udp(self.handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_bytes_are_written_into_the_header() {
        let message = [4u8, 0, 0, 0, 9, 9];
        assert_eq!(seal(&message, None), message);
        assert_eq!(seal(&message, Some([1, 2, 3])), [4, 1, 2, 3, 9, 9]);
        assert_eq!(seal(&[4, 0], Some([1, 2, 3])), [4, 0]);
    }
}
