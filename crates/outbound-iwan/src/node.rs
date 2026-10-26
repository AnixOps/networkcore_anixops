//! One iWAN node at run time: the UDP session driven by [`Client`] and the
//! node's private userspace TCP/IP stack (smoltcp) whose address is the one
//! from OPENACK (spec §11).
//!
//! The driver task starts with the first connection and stops after the
//! node has had no connection for [`IDLE_RELEASE`], sending CLOSE. The stack
//! exists while a session is up; if a reconnect hands out another address,
//! the stack is replaced and its connections fail.

use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp, AnySocket};
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::net::UdpSocket;
use tokio::sync::{watch, Notify};

use crate::client::{Client, Network, Output};
use crate::config::IwanSettings;
use crate::dns;
use crate::packet::{reject, MAX_DATAGRAM};

/// Timer granularity of the session state machine (spec §5).
const TICK: Duration = Duration::from_secs(1);
/// How long a connection waits for the first session.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// The session is released after this long without connections.
pub const IDLE_RELEASE: Duration = Duration::from_secs(60);
/// A closed TCP socket is removed after this long even without a final ACK.
const LINGER: Duration = Duration::from_secs(30);
/// Packets from the server queued for the stack between two polls.
const STACK_QUEUE: usize = 1024;
const UDP_PACKETS: usize = 32;
const UDP_BUFFER: usize = 16 * 1024;
const DNS_TIMEOUT: Duration = Duration::from_secs(2);
const DNS_ATTEMPTS: usize = 2;
const DNS_MIN_TTL: u32 = 30;
const DNS_MAX_TTL: u32 = 600;
const DNS_CACHE_ENTRIES: usize = 256;
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
/// Back-off after a socket error such as ICMP port unreachable.
const ERROR_BACKOFF: Duration = Duration::from_millis(250);
const FIRST_LOCAL_PORT: u16 = 49152;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    /// No driver is running.
    Idle,
    Connecting,
    Up {
        generation: u64,
    },
    Rejected,
    /// OPENACK handed out an address the stack cannot use.
    Unusable,
}

/// Packet queues between the stack and the session.
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

/// The private stack of one session address.
struct Stack {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: QueueDevice,
    address: Ipv4Addr,
    /// TCP sockets whose stream was dropped, waiting for the close to finish.
    closing: Vec<(SocketHandle, Instant)>,
}

impl Stack {
    fn new(network: &Network, now: SmolInstant, seed: u64) -> Self {
        let mut device = QueueDevice {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu: usize::from(network.mtu),
        };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = seed;
        let mut iface = Interface::new(config, &mut device, now);
        let address = network.address;
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(address), 32));
        });
        // Every destination is behind the tunnel; an IP medium needs no
        // neighbor, so the gateway is only a placeholder.
        let _ = iface.routes_mut().add_default_ipv4_route(address);
        Self {
            iface,
            sockets: SocketSet::new(Vec::new()),
            device,
            address,
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
    client: Client,
    running: bool,
    /// Identifies the current driver task.
    run: u64,
    stack: Option<Stack>,
    /// Bumped whenever the stack is replaced; sockets of an older stack fail.
    generation: u64,
    dns: Vec<Ipv4Addr>,
    dns_cache: HashMap<String, (Ipv4Addr, Instant)>,
    /// Connections waiting for a session.
    waiters: usize,
    idle_since: Option<Instant>,
    next_port: u16,
}

impl Core {
    fn stack_for(&mut self, generation: u64) -> io::Result<&mut Stack> {
        if self.generation != generation {
            return Err(reset());
        }
        self.stack.as_mut().ok_or_else(reset)
    }

    fn next_port(&mut self) -> u16 {
        let port = self.next_port;
        self.next_port = if port == u16::MAX {
            FIRST_LOCAL_PORT
        } else {
            port + 1
        };
        port
    }

    fn stop(&mut self, settings: &IwanSettings) {
        self.running = false;
        self.stack = None;
        self.generation += 1;
        self.idle_since = None;
        self.client = Client::new(settings.client.clone(), Instant::now());
    }
}

pub(crate) struct Node {
    settings: IwanSettings,
    core: Mutex<Core>,
    wake: Notify,
    phase: watch::Sender<Phase>,
    epoch: Instant,
    rtt_us: AtomicU32,
    /// The reason text of the last OPENREJ.
    reject_reason: Mutex<Option<String>>,
}

impl Node {
    pub(crate) fn new(settings: IwanSettings) -> Arc<Self> {
        let now = Instant::now();
        let client = Client::new(settings.client.clone(), now);
        let next_port = FIRST_LOCAL_PORT + (random() % 16384) as u16;
        Arc::new(Self {
            settings,
            core: Mutex::new(Core {
                client,
                running: false,
                run: 0,
                stack: None,
                generation: 0,
                dns: Vec::new(),
                dns_cache: HashMap::new(),
                waiters: 0,
                idle_since: None,
                next_port,
            }),
            wake: Notify::new(),
            phase: watch::channel(Phase::Idle).0,
            epoch: now,
            rtt_us: AtomicU32::new(0),
            reject_reason: Mutex::new(None),
        })
    }

    /// The last ECHO round trip in microseconds, 0 before the first one.
    pub(crate) fn rtt_us(&self) -> u32 {
        self.rtt_us.load(Ordering::Relaxed)
    }

    fn lock(&self) -> MutexGuard<'_, Core> {
        // The lock is never held across an await; a poisoned lock only means
        // a panic in smoltcp, and the state is still usable.
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

    /// Waits for a session, starting the driver if needed, and returns the
    /// generation of its stack.
    pub(crate) async fn session(self: &Arc<Self>) -> io::Result<u64> {
        let _waiter = Waiter::new(self);
        let mut phase = self.phase.subscribe();
        let waited = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            phase.wait_for(|phase| !matches!(phase, Phase::Idle | Phase::Connecting)),
        )
        .await;
        let phase = match waited {
            Ok(Ok(phase)) => *phase,
            Ok(Err(_)) => return Err(reset()),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "iwan server did not answer",
                ))
            }
        };
        match phase {
            Phase::Up { generation } => Ok(generation),
            Phase::Rejected => Err(self.rejection()),
            _ => Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "iwan server assigned an unusable address",
            )),
        }
    }

    /// The error for a rejected login, by the server's reason.
    fn rejection(&self) -> io::Error {
        let reason = self
            .reject_reason
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        match reason.as_deref() {
            Some(reject::NO_FREE_ADDRESS) => io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "iwan server has no free address in its pool (NO_FREEIP_INPOOL)",
            ),
            Some(reject::INVALID_PASSWORD) => io::Error::new(
                io::ErrorKind::PermissionDenied,
                "iwan server rejected the user name or password (INVPASS)",
            ),
            Some(other) => io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("iwan server rejected the login ({other})"),
            ),
            None => io::Error::new(
                io::ErrorKind::PermissionDenied,
                "iwan server rejected the login",
            ),
        }
    }

    fn ensure_running(self: &Arc<Self>) {
        let run = {
            let mut core = self.lock();
            if core.running {
                return;
            }
            core.running = true;
            core.run += 1;
            core.idle_since = None;
            core.run
        };
        self.phase.send_replace(Phase::Connecting);
        tokio::spawn(drive(self.clone(), run));
    }

    /// Runs `f` on a socket of the stack `generation`; `None` once that
    /// stack is gone.
    pub(crate) fn with_socket<T, R>(
        &self,
        handle: SocketHandle,
        generation: u64,
        f: impl FnOnce(&mut T) -> R,
    ) -> Option<R>
    where
        T: AnySocket<'static>,
    {
        let mut core = self.lock();
        let stack = core.stack_for(generation).ok()?;
        Some(f(stack.sockets.get_mut::<T>(handle)))
    }

    /// Starts a TCP connection to `remote` in the stack `generation`.
    pub(crate) fn open_tcp(
        &self,
        generation: u64,
        remote: SocketAddrV4,
    ) -> io::Result<SocketHandle> {
        let buffer = self.settings.tcp_buffer_bytes as usize;
        let mut core = self.lock();
        let port = core.next_port();
        let stack = core.stack_for(generation)?;
        let mut socket = new_tcp_socket(buffer);
        socket
            .connect(stack.iface.context(), remote, port)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "iwan cannot reach this address",
                )
            })?;
        Ok(stack.sockets.add(socket))
    }

    /// Listens for one TCP connection on `port` in the stack `generation`.
    pub(crate) fn listen_tcp(&self, generation: u64, port: u16) -> io::Result<SocketHandle> {
        let buffer = self.settings.tcp_buffer_bytes as usize;
        let mut core = self.lock();
        let stack = core.stack_for(generation)?;
        let mut socket = new_tcp_socket(buffer);
        socket
            .listen(port)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "iwan cannot listen there"))?;
        Ok(stack.sockets.add(socket))
    }

    /// Binds a UDP socket in the stack `generation`, on `port` or an
    /// ephemeral one.
    pub(crate) fn open_udp(&self, generation: u64, port: Option<u16>) -> io::Result<SocketHandle> {
        let mut core = self.lock();
        let port = match port {
            Some(port) => port,
            None => core.next_port(),
        };
        let stack = core.stack_for(generation)?;
        let buffer = || {
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_PACKETS],
                vec![0u8; UDP_BUFFER],
            )
        };
        let mut socket = udp::Socket::new(buffer(), buffer());
        socket.bind(port).map_err(|_| {
            io::Error::new(io::ErrorKind::AddrInUse, "iwan udp port is unavailable")
        })?;
        Ok(stack.sockets.add(socket))
    }

    /// Closes a TCP socket gracefully; it is removed once the close finishes.
    pub(crate) fn release_tcp(&self, handle: SocketHandle, generation: u64) {
        {
            let mut core = self.lock();
            let Ok(stack) = core.stack_for(generation) else {
                return;
            };
            stack.sockets.get_mut::<tcp::Socket>(handle).close();
            stack.closing.push((handle, Instant::now()));
        }
        self.wake();
    }

    pub(crate) fn release_udp(&self, handle: SocketHandle, generation: u64) {
        let mut core = self.lock();
        if let Ok(stack) = core.stack_for(generation) {
            stack.sockets.remove(handle);
        }
    }

    /// The IPv4 address of `host`, through the tunnel DNS for names.
    pub(crate) async fn resolve(
        self: &Arc<Self>,
        generation: u64,
        host: &str,
    ) -> io::Result<Ipv4Addr> {
        if let Ok(address) = host.parse::<Ipv4Addr>() {
            return Ok(address);
        }
        let key = host.trim_end_matches('.').to_ascii_lowercase();
        let servers = {
            let core = self.lock();
            let now = Instant::now();
            if let Some((address, expires)) = core.dns_cache.get(&key) {
                if *expires > now {
                    return Ok(*address);
                }
            }
            core.dns.clone()
        };
        if servers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "iwan node has no dns server",
            ));
        }
        let socket = UdpHandle::open(self, generation, None)?;
        for _ in 0..DNS_ATTEMPTS {
            for server in &servers {
                let id = random() as u16;
                let query = dns::query(id, &key).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid domain name")
                })?;
                socket
                    .send_to(&query, SocketAddrV4::new(*server, 53))
                    .await?;
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
                let Some(address) = answer.addresses.first().copied() else {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "domain has no IPv4 address",
                    ));
                };
                let ttl = answer.ttl.clamp(DNS_MIN_TTL, DNS_MAX_TTL);
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
                return Ok(address);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "iwan dns server did not answer",
        ))
    }

    /// Performs the client outputs in order; more outputs may be queued.
    async fn perform(
        &self,
        work: &mut VecDeque<Output>,
        socket: &mut Option<UdpSocket>,
        endpoint: &mut Option<SocketAddr>,
    ) {
        while let Some(output) = work.pop_front() {
            match output {
                Output::Transmit(datagram) => {
                    if let Some(socket) = socket.as_ref() {
                        let _ = socket.send(&datagram).await;
                    }
                }
                Output::ResetSocket => {
                    *socket = None;
                    if self.settings.client.resolve {
                        *endpoint = None;
                    } else if let Some(server) = *endpoint {
                        *socket = connect_udp(server).ok();
                    }
                }
                Output::Resolve => {
                    let Some(server) = resolve_server(&self.settings).await else {
                        continue;
                    };
                    let Ok(connected) = connect_udp(server) else {
                        continue;
                    };
                    *endpoint = Some(server);
                    *socket = Some(connected);
                    let mut out = Vec::new();
                    self.lock().client.resolved(Instant::now(), &mut out);
                    work.extend(out);
                }
                Output::Deliver(packet) => {
                    let mut core = self.lock();
                    if let Some(stack) = core.stack.as_mut() {
                        if stack.device.rx.len() < STACK_QUEUE {
                            stack.device.rx.push_back(packet);
                        }
                    }
                }
                Output::Established(network) => self.established(network),
                Output::Disconnected => {
                    self.phase.send_replace(Phase::Connecting);
                }
                Output::Rejected { reason } => {
                    *self
                        .reject_reason
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = reason;
                    self.phase.send_replace(Phase::Rejected);
                }
                Output::Rtt { current_us } => self.rtt_us.store(current_us, Ordering::Relaxed),
            }
        }
    }

    /// Keeps the stack when the address and MTU are unchanged, so connections
    /// survive a reconnect; otherwise replaces it.
    fn established(&self, network: Network) {
        let now = self.now();
        let phase = {
            let mut core = self.lock();
            core.dns = if self.settings.dns.is_empty() {
                network.dns.clone()
            } else {
                self.settings.dns.clone()
            };
            let same = core.stack.as_ref().is_some_and(|stack| {
                stack.address == network.address && stack.device.mtu == usize::from(network.mtu)
            });
            if !same {
                if let Some(old) = core.stack.as_mut() {
                    old.abort_all();
                }
                core.generation += 1;
                core.dns_cache.clear();
                let address = network.address;
                let usable =
                    !(address.is_unspecified() || address.is_broadcast() || address.is_multicast());
                core.stack = usable.then(|| Stack::new(&network, now, random()));
            }
            match core.stack {
                Some(_) => Phase::Up {
                    generation: core.generation,
                },
                None => Phase::Unusable,
            }
        };
        self.phase.send_replace(phase);
    }

    /// Polls the stack and returns the datagrams to send, how long the driver
    /// may sleep, and whether it should stop (with the CLOSE to send).
    fn poll(&self, run: u64) -> Poll {
        let now = Instant::now();
        let timestamp = self.now();
        let mut guard = self.lock();
        let core = &mut *guard;
        if core.run != run || !core.running {
            return Poll::stop(Vec::new(), None);
        }
        let mut datagrams = Vec::new();
        let mut delay = TICK;
        if let Some(stack) = core.stack.as_mut() {
            stack
                .iface
                .poll(timestamp, &mut stack.device, &mut stack.sockets);
            stack.sweep(now);
            while let Some(packet) = stack.device.tx.pop_front() {
                if let Some(datagram) = core.client.encapsulate(&packet) {
                    datagrams.push(datagram);
                }
            }
            if let Some(next) = stack.iface.poll_delay(timestamp, &stack.sockets) {
                delay = delay.min(Duration::from_micros(next.total_micros()));
            }
        }
        let busy = core.waiters > 0 || core.stack.as_ref().is_some_and(Stack::has_sockets);
        if busy {
            core.idle_since = None;
        } else {
            let since = *core.idle_since.get_or_insert(now);
            if now.saturating_duration_since(since) >= IDLE_RELEASE {
                let close = core.client.close_datagram();
                core.stop(&self.settings);
                drop(guard);
                self.phase.send_replace(Phase::Idle);
                return Poll::stop(datagrams, close);
            }
        }
        Poll {
            datagrams,
            delay,
            stop: None,
        }
    }
}

struct Poll {
    datagrams: Vec<Vec<u8>>,
    delay: Duration,
    /// `Some` to stop, with the CLOSE to send if a session was up.
    stop: Option<Option<Vec<u8>>>,
}

impl Poll {
    fn stop(datagrams: Vec<Vec<u8>>, close: Option<Vec<u8>>) -> Self {
        Self {
            datagrams,
            delay: Duration::ZERO,
            stop: Some(close),
        }
    }
}

/// Counts a connection waiting for a session, which keeps the driver alive.
struct Waiter<'a>(&'a Node);

impl<'a> Waiter<'a> {
    fn new(node: &'a Arc<Node>) -> Self {
        node.lock().waiters += 1;
        node.ensure_running();
        Self(node)
    }
}

impl Drop for Waiter<'_> {
    fn drop(&mut self) {
        self.0.lock().waiters -= 1;
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
            core.stop(&self.node.settings);
            drop(core);
            self.node.phase.send_replace(Phase::Idle);
        }
    }
}

async fn drive(node: Arc<Node>, run: u64) {
    let _guard = RunGuard {
        node: node.clone(),
        run,
    };
    let mut endpoint = None;
    let mut socket = None;
    if !node.settings.client.resolve {
        if let Ok(address) = node.settings.server.parse::<Ipv4Addr>() {
            let server = SocketAddr::V4(SocketAddrV4::new(address, node.settings.port));
            endpoint = Some(server);
            socket = connect_udp(server).ok();
        }
    }
    let mut work = VecDeque::new();
    {
        let mut out = Vec::new();
        node.lock().client.start(Instant::now(), &mut out);
        work.extend(out);
    }
    let mut datagram = vec![0u8; MAX_DATAGRAM];
    let mut next_tick = Instant::now() + TICK;
    loop {
        node.perform(&mut work, &mut socket, &mut endpoint).await;
        let poll = node.poll(run);
        if let Some(sender) = socket.as_ref() {
            for datagram in &poll.datagrams {
                let _ = sender.send(datagram).await;
            }
        }
        if let Some(close) = poll.stop {
            if let (Some(sender), Some(close)) = (socket.as_ref(), close) {
                let _ = sender.send(&close).await;
            }
            return;
        }
        let wait = poll
            .delay
            .min(next_tick.saturating_duration_since(Instant::now()));
        tokio::select! {
            received = recv(socket.as_ref(), &mut datagram) => match received {
                Ok(len) => {
                    let mut out = Vec::new();
                    node.lock().client.receive(Instant::now(), &datagram[..len], &mut out);
                    work.extend(out);
                }
                Err(_) => tokio::time::sleep(ERROR_BACKOFF).await,
            },
            _ = node.wake.notified() => {}
            _ = tokio::time::sleep(wait) => {}
        }
        let now = Instant::now();
        if now >= next_tick {
            next_tick = now + TICK;
            let mut out = Vec::new();
            node.lock().client.tick(now, &mut out);
            work.extend(out);
        }
    }
}

async fn recv(socket: Option<&UdpSocket>, buffer: &mut [u8]) -> io::Result<usize> {
    match socket {
        Some(socket) => socket.recv(buffer).await,
        None => std::future::pending().await,
    }
}

/// A connected UDP socket: the kernel then drops datagrams from any other
/// source, which is the receive filter of spec §5.
fn connect_udp(server: SocketAddr) -> io::Result<UdpSocket> {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.connect(server)?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket)
}

/// The first IPv4 address of the server name.
async fn resolve_server(settings: &IwanSettings) -> Option<SocketAddr> {
    let lookup = tokio::net::lookup_host((settings.server.as_str(), settings.port));
    let addresses = tokio::time::timeout(RESOLVE_TIMEOUT, lookup)
        .await
        .ok()?
        .ok()?;
    addresses.into_iter().find(SocketAddr::is_ipv4)
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

fn reset() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, "iwan session was replaced")
}

/// Process-local randomness for DNS ids, ports and the stack seed; none of
/// it needs to be unpredictable.
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
    generation: u64,
}

impl UdpHandle {
    pub(crate) fn open(node: &Arc<Node>, generation: u64, port: Option<u16>) -> io::Result<Self> {
        let handle = node.open_udp(generation, port)?;
        Ok(Self {
            node: node.clone(),
            handle,
            generation,
        })
    }

    pub(crate) async fn send_to(&self, payload: &[u8], target: SocketAddrV4) -> io::Result<()> {
        if payload.len() > UDP_BUFFER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram is too large",
            ));
        }
        std::future::poll_fn(|cx| {
            self.node
                .with_socket::<udp::Socket, _>(self.handle, self.generation, |socket| {
                    if !socket.is_open() {
                        return std::task::Poll::Ready(Err(reset()));
                    }
                    match socket.send_slice(payload, target) {
                        Ok(()) => std::task::Poll::Ready(Ok(())),
                        Err(udp::SendError::BufferFull) => {
                            socket.register_send_waker(cx.waker());
                            std::task::Poll::Pending
                        }
                        Err(_) => std::task::Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "iwan cannot reach this address",
                        ))),
                    }
                })
                .unwrap_or_else(|| std::task::Poll::Ready(Err(reset())))
        })
        .await?;
        self.node.wake();
        Ok(())
    }

    pub(crate) async fn recv(&self) -> io::Result<Vec<u8>> {
        std::future::poll_fn(|cx| {
            self.node
                .with_socket::<udp::Socket, _>(self.handle, self.generation, |socket| {
                    if !socket.is_open() {
                        return std::task::Poll::Ready(Err(reset()));
                    }
                    match socket.recv() {
                        Ok((payload, _)) => std::task::Poll::Ready(Ok(payload.to_vec())),
                        Err(_) => {
                            socket.register_recv_waker(cx.waker());
                            std::task::Poll::Pending
                        }
                    }
                })
                .unwrap_or_else(|| std::task::Poll::Ready(Err(reset())))
        })
        .await
    }
}

impl Drop for UdpHandle {
    fn drop(&mut self) {
        self.node.release_udp(self.handle, self.generation);
    }
}
