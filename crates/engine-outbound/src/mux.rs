//! Client multiplexing for stream protocols: many proxied connections over
//! a few connections to the server, in the sing-mux format that sing-box,
//! mihomo and our own `engine-inbound` servers accept (the `multiplex` of an
//! outbound; `smux` in Clash configs).
//!
//! A multiplexed connection is an ordinary connection of the node's
//! protocol to the name `sp.mux.sing-box.arpa:444`. It starts with the
//! session request `VERSION(0) PROTOCOL(1 = yamux)` and then carries yamux
//! frames (`VERSION(0) TYPE FLAGS(2) STREAM(4) LENGTH(4)`, big endian; Data,
//! WindowUpdate, Ping and GoAway; flags SYN, ACK, FIN, RST). Each stream
//! starts with `FLAGS(2) ATYP ADDR PORT` and is answered with a status byte
//! (0, or 1 and a message) ahead of its first data. This client always runs
//! yamux, whatever protocol a subscription names: sing-mux servers accept
//! every protocol a client asks for, and yamux is the one with a window per
//! stream, so a stream whose reader is slow never stops the others.
//!
//! What keeps a bulk transfer from raising the latency of small requests on
//! the same connection:
//!
//! - every stream has its own 256 KiB window in both directions, so data
//!   that one stream has not read yet never blocks the connection;
//! - outgoing frames go through a [`fair::FairQueue`]: at most two frames
//!   per stream wait, and the stream that sent the fewest bytes lately goes
//!   first;
//! - new streams go to the connection with the fewest open streams and the
//!   least queued data, spread over up to `max_connections` connections.
//!
//! What it cannot remove is the loss recovery of the TCP connection below:
//! a lost packet delays every stream behind it. Nodes that need that gone
//! use a QUIC protocol (TUIC, Hysteria 2, ANX over QUIC).
//!
//! Connections are pooled: a stream opens on a live connection when one has
//! room, and a connection with no streams closes after `idle_timeout_secs`.
//! Pings every [`KEEPALIVE`] find connections that died (a network change);
//! a connection that answers nothing for [`DEAD_AFTER`] closes, and no new
//! stream goes to one that has been silent for [`STALE_AFTER`].
//!
//! UDP is not multiplexed: [`TcpOutbound::open_udp`] goes to the wrapped
//! outbound. Padding and TCP Brutal are not negotiated.

pub mod fair;

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use self::fair::{Discipline, FairQueue};
use crate::{BoxFuture, BoxStream, TargetAddr, TcpOutbound, UdpFlow};

/// The name a client connects to for a multiplexed connection.
pub const DESTINATION: &str = "sp.mux.sing-box.arpa";
pub const DESTINATION_PORT: u16 = 444;

const SESSION_VERSION: u8 = 0;
const SESSION_YAMUX: u8 = 1;

const YAMUX_DATA: u8 = 0;
const YAMUX_WINDOW_UPDATE: u8 = 1;
const YAMUX_PING: u8 = 2;
const YAMUX_GO_AWAY: u8 = 3;
const FLAG_SYN: u16 = 1;
const FLAG_ACK: u16 = 2;
const FLAG_FIN: u16 = 4;
const FLAG_RST: u16 = 8;

/// The yamux window of each direction of a new stream.
pub const WINDOW: u32 = 256 * 1024;
/// Payload bytes per data frame.
const MAX_FRAME: usize = 16 * 1024;
/// Bytes the writer takes from the queue per write.
const BATCH: usize = 16 * 1024;

const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

/// How often a connection is pinged.
pub const KEEPALIVE: Duration = Duration::from_secs(10);
/// A connection that has sent nothing for this long gets no new streams.
pub const STALE_AFTER: Duration = Duration::from_secs(15);
/// A connection that has sent nothing for this long closes.
pub const DEAD_AFTER: Duration = Duration::from_secs(25);
/// A stream the server has not acknowledged for this long closes its
/// connection.
const OPEN_TIMEOUT: Duration = Duration::from_secs(10);
const WATCH: Duration = Duration::from_secs(1);

const DEFAULT_MAX_CONNECTIONS: usize = 4;
const DEFAULT_MIN_STREAMS: usize = 4;
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Connections at most, whatever the settings say.
const CONNECTION_LIMIT: usize = 32;

/// The `multiplex` of an outbound, in sing-box's terms. Clash's `smux`
/// imports into the same shape.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MuxConfig {
    #[serde(default = "enabled")]
    pub enabled: bool,
    /// `smux`, `yamux` or `h2mux`; yamux is run for all of them.
    #[serde(default)]
    pub protocol: Option<String>,
    /// Connections at most (default 4). Not with `max_streams`.
    #[serde(default)]
    pub max_connections: Option<usize>,
    /// Streams a connection takes before another opens (default 4). Not
    /// with `max_streams`.
    #[serde(default)]
    pub min_streams: Option<usize>,
    /// Streams per connection at most; connections open as needed.
    #[serde(default)]
    pub max_streams: Option<usize>,
    /// Accepted and not applied.
    #[serde(default)]
    pub padding: bool,
    /// Accepted and not applied.
    #[serde(default)]
    pub brutal: Option<Value>,
    /// Seconds a connection without streams stays open (default 60).
    #[serde(default)]
    pub idle_timeout_secs: Option<u64>,
    /// `fair` (default) or `fifo`, for comparison.
    #[serde(default)]
    pub scheduler: Option<String>,
}

fn enabled() -> bool {
    true
}

/// Checked multiplexing settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MuxSettings {
    pub max_connections: usize,
    pub min_streams: usize,
    /// 0: no limit per connection.
    pub max_streams: usize,
    pub idle_timeout: Duration,
    pub discipline: Discipline,
}

impl Default for MuxSettings {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            min_streams: DEFAULT_MIN_STREAMS,
            max_streams: 0,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            discipline: Discipline::Fair,
        }
    }
}

impl MuxConfig {
    /// Parses a `multiplex` value. `Ok(None)` when it is turned off.
    pub fn parse(value: &Value) -> Result<Option<MuxSettings>, &'static str> {
        let config: MuxConfig =
            serde_json::from_value(value.clone()).map_err(|_| "multiplex settings are invalid")?;
        config.settings()
    }

    pub fn settings(&self) -> Result<Option<MuxSettings>, &'static str> {
        if !self.enabled {
            return Ok(None);
        }
        match self.protocol.as_deref() {
            None | Some("") | Some("smux") | Some("yamux") | Some("h2mux") => {}
            Some(_) => return Err("multiplex protocol must be smux, yamux or h2mux"),
        }
        let mut settings = MuxSettings::default();
        match self.max_streams.filter(|streams| *streams > 0) {
            Some(streams) => {
                if self.max_connections.is_some_and(|n| n > 0)
                    || self.min_streams.is_some_and(|n| n > 0)
                {
                    return Err(
                        "multiplex max_streams cannot be used with max_connections or min_streams",
                    );
                }
                settings.max_streams = streams;
                settings.max_connections = CONNECTION_LIMIT;
            }
            None => {
                if let Some(connections) = self.max_connections.filter(|n| *n > 0) {
                    settings.max_connections = connections.min(CONNECTION_LIMIT);
                }
                if let Some(streams) = self.min_streams.filter(|n| *n > 0) {
                    settings.min_streams = streams;
                }
            }
        }
        if let Some(secs) = self.idle_timeout_secs {
            if !(1..=3600).contains(&secs) {
                return Err("multiplex idle_timeout_secs must be between 1 and 3600");
            }
            settings.idle_timeout = Duration::from_secs(secs);
        }
        if let Some(name) = &self.scheduler {
            settings.discipline =
                Discipline::from_name(name).ok_or("multiplex scheduler must be fair or fifo")?;
        }
        Ok(Some(settings))
    }
}

/// Counters of a [`MuxOutbound`].
#[derive(Debug, Default)]
pub struct MuxStats {
    /// Connections dialed, and dials that failed.
    pub sessions_opened: AtomicU64,
    pub session_failures: AtomicU64,
    /// Connections closed because they stopped answering.
    pub sessions_dead: AtomicU64,
    /// Streams opened, and those that went to a connection that already
    /// carried an earlier stream.
    pub streams_opened: AtomicU64,
    pub streams_reused: AtomicU64,
}

impl MuxStats {
    /// Share of streams that reused a pooled connection, 0 to 1.
    pub fn reuse_rate(&self) -> f64 {
        let opened = self.streams_opened.load(Ordering::Relaxed);
        if opened == 0 {
            return 0.0;
        }
        self.streams_reused.load(Ordering::Relaxed) as f64 / opened as f64
    }
}

/// An outbound whose connections run as streams of pooled multiplexed
/// connections of the wrapped outbound.
pub struct MuxOutbound {
    inner: Arc<dyn TcpOutbound>,
    settings: MuxSettings,
    sessions: Mutex<Vec<Arc<Session>>>,
    /// Held while a connection is dialed, so that a burst of streams does
    /// not dial one connection each.
    dialing: tokio::sync::Mutex<()>,
    stats: Arc<MuxStats>,
}

impl MuxOutbound {
    pub fn new(inner: Arc<dyn TcpOutbound>, settings: MuxSettings) -> Self {
        Self {
            inner,
            settings,
            sessions: Mutex::new(Vec::new()),
            dialing: tokio::sync::Mutex::new(()),
            stats: Arc::new(MuxStats::default()),
        }
    }

    pub fn stats(&self) -> &Arc<MuxStats> {
        &self.stats
    }

    pub fn settings(&self) -> &MuxSettings {
        &self.settings
    }

    /// Live pooled connections.
    pub fn sessions(&self) -> usize {
        let mut sessions = lock(&self.sessions);
        sessions.retain(|session| !session.is_closed());
        sessions.len()
    }

    /// Closes every pooled connection; their streams fail. For a network
    /// change, when the connections are known to be gone.
    pub fn reset(&self) {
        let sessions = std::mem::take(&mut *lock(&self.sessions));
        for session in sessions {
            session.shutdown();
        }
    }

    /// The pooled connection a new stream should use, if any.
    fn pick(&self) -> Option<Arc<Session>> {
        let mut sessions = lock(&self.sessions);
        sessions.retain(|session| !session.is_closed());
        let now = Instant::now();
        let usable = sessions.iter().filter(|session| session.usable(now));
        let best = usable
            .filter(|session| {
                self.settings.max_streams == 0 || session.active() < self.settings.max_streams
            })
            .min_by_key(|session| (session.active(), session.queue.queued()))?;
        if self.settings.max_streams > 0
            || best.active() < self.settings.min_streams
            || sessions.len() >= self.settings.max_connections
        {
            Some(best.clone())
        } else {
            None
        }
    }

    async fn dial(&self) -> io::Result<Arc<Session>> {
        let target = TargetAddr::Domain(DESTINATION.to_string(), DESTINATION_PORT);
        let stream = match self.inner.connect(&target).await {
            Ok(stream) => stream,
            Err(error) => {
                self.stats.session_failures.fetch_add(1, Ordering::Relaxed);
                return Err(error);
            }
        };
        self.stats.sessions_opened.fetch_add(1, Ordering::Relaxed);
        let session = Session::start(stream, &self.settings, self.stats.clone());
        lock(&self.sessions).push(session.clone());
        Ok(session)
    }

    async fn open(&self, target: &TargetAddr) -> io::Result<MuxStream> {
        // A target no stream can carry fails before any dial.
        stream_request(target)?;
        if let Some(session) = self.pick() {
            if let Ok(stream) = session.open(target) {
                return Ok(self.opened(stream));
            }
        }
        let _dialing = self.dialing.lock().await;
        // Another stream may have dialed while this one waited.
        if let Some(session) = self.pick() {
            if let Ok(stream) = session.open(target) {
                return Ok(self.opened(stream));
            }
        }
        let session = self.dial().await?;
        let stream = session.open(target)?;
        Ok(self.opened(stream))
    }

    fn opened(&self, stream: MuxStream) -> MuxStream {
        self.stats.streams_opened.fetch_add(1, Ordering::Relaxed);
        if stream.reused {
            self.stats.streams_reused.fetch_add(1, Ordering::Relaxed);
        }
        stream
    }

    /// The counters as JSON, for [`TcpOutbound::health`].
    pub fn health_json(&self) -> Value {
        let stats = &self.stats;
        json!({
            "protocol": "yamux",
            "scheduler": self.settings.discipline.name(),
            "sessions": self.sessions(),
            "sessions_opened": stats.sessions_opened.load(Ordering::Relaxed),
            "session_failures": stats.session_failures.load(Ordering::Relaxed),
            "sessions_dead": stats.sessions_dead.load(Ordering::Relaxed),
            "streams_opened": stats.streams_opened.load(Ordering::Relaxed),
            "streams_reused": stats.streams_reused.load(Ordering::Relaxed),
            "reuse_rate": (stats.reuse_rate() * 1000.0).round() / 1000.0,
        })
    }
}

impl TcpOutbound for MuxOutbound {
    fn protocol(&self) -> &'static str {
        self.inner.protocol()
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move { Ok(Box::new(self.open(target).await?) as BoxStream) })
    }

    fn open_udp<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
        self.inner.open_udp(target)
    }

    fn health(&self) -> Option<Value> {
        self.inner.health()
    }

    /// The wrapped outbound's counters with the pool's under `mux`.
    fn reuse_stats(&self) -> Option<Value> {
        let mut stats = match self.inner.reuse_stats() {
            Some(Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        };
        stats.insert("mux".to_string(), self.health_json());
        Some(Value::Object(stats))
    }

    fn resume(&self) -> bool {
        self.inner.resume()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn header(kind: u8, flags: u16, stream: u32, length: u32) -> [u8; 12] {
    let mut header = [0u8; 12];
    header[1] = kind;
    header[2..4].copy_from_slice(&flags.to_be_bytes());
    header[4..8].copy_from_slice(&stream.to_be_bytes());
    header[8..12].copy_from_slice(&length.to_be_bytes());
    header
}

fn data_frame(flags: u16, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(12 + payload.len());
    frame.extend_from_slice(&header(YAMUX_DATA, flags, stream, payload.len() as u32));
    frame.extend_from_slice(payload);
    frame
}

/// `FLAGS(2) ATYP ADDR PORT` for a TCP stream to `target`.
fn stream_request(target: &TargetAddr) -> io::Result<Vec<u8>> {
    let mut request = vec![0, 0];
    match target {
        TargetAddr::Ip(addr) => {
            match addr.ip() {
                std::net::IpAddr::V4(ip) => {
                    request.push(ATYP_IPV4);
                    request.extend_from_slice(&ip.octets());
                }
                std::net::IpAddr::V6(ip) => {
                    request.push(ATYP_IPV6);
                    request.extend_from_slice(&ip.octets());
                }
            }
            request.extend_from_slice(&addr.port().to_be_bytes());
        }
        TargetAddr::Domain(domain, port) => {
            let length = u8::try_from(domain.len())
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "domain is too long"))?;
            request.push(ATYP_DOMAIN);
            request.push(length);
            request.extend_from_slice(domain.as_bytes());
            request.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(request)
}

/// One multiplexed connection.
struct Session {
    queue: FairQueue,
    streams: Mutex<HashMap<u32, Arc<Mutex<StreamState>>>>,
    next_id: AtomicU32,
    /// Streams open now, and whether any stream was ever opened.
    active: AtomicUsize,
    used: AtomicBool,
    closed: AtomicBool,
    /// The server sent GoAway: no new streams.
    draining: AtomicBool,
    times: Mutex<Times>,
}

struct Times {
    last_recv: Instant,
    idle_since: Instant,
    ping_sent: Option<Instant>,
}

impl Session {
    fn start(stream: BoxStream, settings: &MuxSettings, stats: Arc<MuxStats>) -> Arc<Self> {
        let now = Instant::now();
        let session = Arc::new(Self {
            queue: FairQueue::new(settings.discipline),
            streams: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(1),
            active: AtomicUsize::new(0),
            used: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            draining: AtomicBool::new(false),
            times: Mutex::new(Times {
                last_recv: now,
                idle_since: now,
                ping_sent: None,
            }),
        });
        session
            .queue
            .push_control(vec![SESSION_VERSION, SESSION_YAMUX]);
        tokio::spawn(run(session.clone(), stream, settings.idle_timeout, stats));
        session
    }

    fn active(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    fn usable(&self, now: Instant) -> bool {
        !self.is_closed()
            && !self.draining.load(Ordering::Relaxed)
            && now.saturating_duration_since(lock(&self.times).last_recv) < STALE_AFTER
    }

    fn open(self: &Arc<Self>, target: &TargetAddr) -> io::Result<MuxStream> {
        if self.is_closed() || self.draining.load(Ordering::Relaxed) {
            return Err(io::ErrorKind::NotConnected.into());
        }
        let request = stream_request(target)?;
        let id = self.next_id.fetch_add(2, Ordering::Relaxed);
        if id > u32::MAX - 2 {
            self.draining.store(true, Ordering::Relaxed);
            return Err(io::ErrorKind::NotConnected.into());
        }
        let state = Arc::new(Mutex::new(StreamState::new()));
        lock(&self.streams).insert(id, state.clone());
        let reused = self.used.swap(true, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::Relaxed);
        // SYN, then the request; both ahead of the stream's data.
        let mut opening = header(YAMUX_WINDOW_UPDATE, FLAG_SYN, id, 0).to_vec();
        opening.extend_from_slice(&data_frame(0, id, &request));
        if !self.queue.push(id, opening) {
            let stream = MuxStream {
                session: self.clone(),
                id,
                state,
                reused,
            };
            drop(stream);
            return Err(io::ErrorKind::NotConnected.into());
        }
        Ok(MuxStream {
            session: self.clone(),
            id,
            state,
            reused,
        })
    }

    fn stream(&self, id: u32) -> Option<Arc<Mutex<StreamState>>> {
        lock(&self.streams).get(&id).cloned()
    }

    /// Applies a frame's flags, window credit and data to its stream.
    fn on_frame(&self, id: u32, flags: u16, credit: u32, data: Vec<u8>) {
        let Some(state) = self.stream(id) else {
            // A stream the server opens, or one already gone.
            if flags & FLAG_SYN != 0 {
                self.queue
                    .push_control(header(YAMUX_WINDOW_UPDATE, FLAG_RST, id, 0).to_vec());
            }
            return;
        };
        let mut state = lock(&state);
        if flags & FLAG_ACK != 0 {
            state.acked = true;
        }
        if !data.is_empty() {
            if data.len() > state.recv_window as usize {
                // More than the window: the stream is broken.
                state.reset = true;
                self.queue
                    .push_control(header(YAMUX_WINDOW_UPDATE, FLAG_RST, id, 0).to_vec());
            } else {
                state.recv_window -= data.len() as u32;
                state.buffered += data.len();
                state.recv.push_back(data);
            }
        }
        state.send_window = state.send_window.saturating_add(credit);
        if flags & FLAG_FIN != 0 {
            state.remote_fin = true;
        }
        if flags & FLAG_RST != 0 {
            state.reset = true;
        }
        state.wake();
    }

    fn shutdown(&self) {
        if self.closed.swap(true, Ordering::Relaxed) {
            return;
        }
        self.queue.close();
        let streams: Vec<_> = lock(&self.streams).values().cloned().collect();
        for state in streams {
            let mut state = lock(&state);
            state.reset = true;
            state.wake();
        }
    }

    /// Whether the connection should close now.
    fn check(&self, now: Instant, idle_timeout: Duration) -> Option<&'static str> {
        let mut times = lock(&self.times);
        if self.active() == 0 && now.saturating_duration_since(times.idle_since) >= idle_timeout {
            return Some("idle");
        }
        if let Some(sent) = times.ping_sent {
            if times.last_recv >= sent {
                times.ping_sent = None;
            }
        }
        let silent = now.saturating_duration_since(times.last_recv);
        if silent >= DEAD_AFTER {
            return Some("dead");
        }
        if times.ping_sent.is_none() && silent >= KEEPALIVE {
            times.ping_sent = Some(now);
            drop(times);
            self.queue
                .push_control(header(YAMUX_PING, FLAG_SYN, 0, 1).to_vec());
        } else {
            drop(times);
        }
        let streams: Vec<_> = lock(&self.streams).values().cloned().collect();
        let unanswered = streams.iter().any(|state| {
            let state = lock(state);
            !state.acked && now.saturating_duration_since(state.opened_at) >= OPEN_TIMEOUT
        });
        unanswered.then_some("dead")
    }

    fn touch(&self) {
        lock(&self.times).last_recv = Instant::now();
    }

    /// A stream handle is gone.
    fn release(&self, id: u32) {
        lock(&self.streams).remove(&id);
        if self.active.fetch_sub(1, Ordering::Relaxed) == 1 {
            lock(&self.times).idle_since = Instant::now();
            if self.draining.load(Ordering::Relaxed) {
                self.shutdown();
            }
        }
    }
}

/// Runs a connection: its writer, its reader and its watchdog.
async fn run(
    session: Arc<Session>,
    stream: BoxStream,
    idle_timeout: Duration,
    stats: Arc<MuxStats>,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let write = async {
        while let Some(batch) = session.queue.next_batch(BATCH).await {
            if writer.write_all(&batch).await.is_err() || writer.flush().await.is_err() {
                return;
            }
        }
    };
    let read = read_loop(&session, &mut reader);
    let watch = async {
        let mut ticker = tokio::time::interval(WATCH);
        loop {
            ticker.tick().await;
            if let Some(reason) = session.check(Instant::now(), idle_timeout) {
                if reason == "dead" {
                    stats.sessions_dead.fetch_add(1, Ordering::Relaxed);
                }
                return;
            }
        }
    };
    tokio::select! {
        _ = write => {}
        _ = read => {}
        _ = watch => {}
    }
    session.shutdown();
    let _ = writer.shutdown().await;
}

async fn read_loop<R: AsyncRead + Unpin>(session: &Session, reader: &mut R) -> io::Result<()> {
    let mut head = [0u8; 12];
    loop {
        reader.read_exact(&mut head).await?;
        session.touch();
        let kind = head[1];
        let flags = u16::from_be_bytes([head[2], head[3]]);
        let id = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
        let length = u32::from_be_bytes([head[8], head[9], head[10], head[11]]);
        if head[0] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a yamux frame",
            ));
        }
        match kind {
            YAMUX_DATA => {
                if length > WINDOW {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "yamux frame too large",
                    ));
                }
                let mut data = vec![0u8; length as usize];
                reader.read_exact(&mut data).await?;
                session.on_frame(id, flags, 0, data);
            }
            YAMUX_WINDOW_UPDATE => session.on_frame(id, flags, length, Vec::new()),
            YAMUX_PING => {
                if flags & FLAG_SYN != 0 {
                    session
                        .queue
                        .push_control(header(YAMUX_PING, FLAG_ACK, 0, length).to_vec());
                }
            }
            YAMUX_GO_AWAY => {
                session.draining.store(true, Ordering::Relaxed);
                if session.active() == 0 {
                    return Ok(());
                }
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unknown yamux frame",
                ))
            }
        }
    }
}

struct StreamState {
    recv: std::collections::VecDeque<Vec<u8>>,
    /// Bytes of the front chunk already read.
    offset: usize,
    buffered: usize,
    /// Bytes the server may still send.
    recv_window: u32,
    /// Bytes read since the window was last reopened.
    consumed: u32,
    send_window: u32,
    acked: bool,
    status_read: bool,
    remote_fin: bool,
    local_fin: bool,
    reset: bool,
    opened_at: Instant,
    reader: Option<Waker>,
    writer: Option<Waker>,
}

impl StreamState {
    fn new() -> Self {
        Self {
            recv: std::collections::VecDeque::new(),
            offset: 0,
            buffered: 0,
            recv_window: WINDOW,
            consumed: 0,
            send_window: WINDOW,
            acked: false,
            status_read: false,
            remote_fin: false,
            local_fin: false,
            reset: false,
            opened_at: Instant::now(),
            reader: None,
            writer: None,
        }
    }

    fn wake(&mut self) {
        if let Some(waker) = self.reader.take() {
            waker.wake();
        }
        if let Some(waker) = self.writer.take() {
            waker.wake();
        }
    }

    /// Copies up to `out.len()` buffered bytes.
    fn take(&mut self, out: &mut [u8]) -> usize {
        let mut copied = 0;
        while copied < out.len() {
            let Some(front) = self.recv.front() else {
                break;
            };
            let n = (front.len() - self.offset).min(out.len() - copied);
            out[copied..copied + n].copy_from_slice(&front[self.offset..self.offset + n]);
            copied += n;
            self.offset += n;
            if self.offset == front.len() {
                self.recv.pop_front();
                self.offset = 0;
            }
        }
        self.buffered -= copied;
        self.consumed += copied as u32;
        copied
    }

    /// The window update to send after reading, once half a window is read.
    fn grant(&mut self) -> Option<u32> {
        if self.consumed >= WINDOW / 2 {
            let credit = self.consumed;
            self.recv_window += credit;
            self.consumed = 0;
            Some(credit)
        } else {
            None
        }
    }
}

/// One proxied connection on a multiplexed connection.
pub struct MuxStream {
    session: Arc<Session>,
    id: u32,
    state: Arc<Mutex<StreamState>>,
    /// The connection carried a stream before this one.
    reused: bool,
}

impl MuxStream {
    fn send_credit(&self, credit: Option<u32>) {
        if let Some(credit) = credit {
            self.session
                .queue
                .push_control(header(YAMUX_WINDOW_UPDATE, 0, self.id, credit).to_vec());
        }
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut state = lock(&this.state);
        if !state.status_read && state.buffered > 0 {
            let mut status = [0u8; 1];
            state.take(&mut status);
            state.status_read = true;
            if status[0] != 0 {
                state.reset = true;
                drop(state);
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "the server refused the multiplexed stream",
                )));
            }
        }
        if state.status_read && state.buffered > 0 {
            let out = buf.initialize_unfilled();
            let n = state.take(out);
            buf.advance(n);
            let credit = state.grant();
            drop(state);
            this.send_credit(credit);
            return Poll::Ready(Ok(()));
        }
        if state.remote_fin {
            let credit = state.grant();
            drop(state);
            this.send_credit(credit);
            return Poll::Ready(Ok(()));
        }
        if state.reset {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        state.reader = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let window = {
            let mut state = lock(&this.state);
            if state.reset || state.local_fin {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            if state.send_window == 0 {
                state.writer = Some(cx.waker().clone());
                return Poll::Pending;
            }
            state.send_window as usize
        };
        match this.session.queue.poll_room(cx, this.id) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(false) => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Ready(true) => {}
        }
        let n = buf.len().min(window).min(MAX_FRAME);
        lock(&this.state).send_window -= n as u32;
        if !this
            .session
            .queue
            .push(this.id, data_frame(0, this.id, &buf[..n]))
        {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        {
            let state = lock(&this.state);
            if state.local_fin {
                return Poll::Ready(Ok(()));
            }
            if state.reset {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
        }
        match this.session.queue.poll_room(cx, this.id) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(false) => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Ready(true) => {}
        }
        lock(&this.state).local_fin = true;
        let fin = header(YAMUX_WINDOW_UPDATE, FLAG_FIN, this.id, 0).to_vec();
        if !this.session.queue.push(this.id, fin) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        let finished = {
            let state = lock(&self.state);
            state.reset || (state.local_fin && state.remote_fin)
        };
        if finished {
            self.session.queue.retire(self.id);
        } else {
            // Dropped half way: what it queued is dropped too.
            self.session.queue.discard(self.id);
            self.session
                .queue
                .push_control(header(YAMUX_WINDOW_UPDATE, FLAG_RST, self.id, 0).to_vec());
        }
        self.session.release(self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_follow_sing_box() {
        let parse = |value: Value| MuxConfig::parse(&value);
        assert_eq!(parse(json!({"enabled": false})), Ok(None));
        assert_eq!(parse(json!({})), Ok(Some(MuxSettings::default())));
        let settings = parse(json!({"protocol": "h2mux", "max_connections": 2, "min_streams": 8}))
            .unwrap()
            .unwrap();
        assert_eq!((settings.max_connections, settings.min_streams), (2, 8));
        let settings = parse(json!({"protocol": "smux", "max_streams": 16, "padding": true}))
            .unwrap()
            .unwrap();
        assert_eq!(
            (settings.max_streams, settings.max_connections),
            (16, CONNECTION_LIMIT)
        );
        let fifo = parse(json!({"scheduler": "fifo", "idle_timeout_secs": 5}))
            .unwrap()
            .unwrap();
        assert_eq!(fifo.discipline, Discipline::Fifo);
        assert_eq!(fifo.idle_timeout, Duration::from_secs(5));

        for bad in [
            json!({"protocol": "quic"}),
            json!({"max_streams": 4, "max_connections": 2}),
            json!({"scheduler": "lifo"}),
            json!({"idle_timeout_secs": 0}),
            json!({"unknown": 1}),
        ] {
            assert!(parse(bad.clone()).is_err(), "{bad}");
        }
    }

    #[test]
    fn stream_requests_are_socks_addresses() {
        let domain = TargetAddr::Domain("a.b".into(), 443);
        assert_eq!(
            stream_request(&domain).unwrap(),
            [0, 0, 3, 3, b'a', b'.', b'b', 1, 187]
        );
        let ip = TargetAddr::Ip("10.0.0.1:53".parse().unwrap());
        assert_eq!(stream_request(&ip).unwrap(), [0, 0, 1, 10, 0, 0, 1, 0, 53]);
        let v6 = TargetAddr::Ip("[::1]:80".parse().unwrap());
        assert_eq!(stream_request(&v6).unwrap().len(), 2 + 1 + 16 + 2);
        assert!(stream_request(&TargetAddr::Domain(String::new(), 1)).is_err());
    }

    #[test]
    fn frames_are_big_endian_yamux() {
        assert_eq!(
            header(YAMUX_WINDOW_UPDATE, FLAG_SYN, 1, 0),
            [0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0]
        );
        assert_eq!(
            data_frame(0, 3, b"hi"),
            [0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 2, b'h', b'i']
        );
    }

    #[test]
    fn reading_reopens_the_window_by_halves() {
        let mut state = StreamState::new();
        state.recv_window -= WINDOW / 2;
        state.buffered = (WINDOW / 2) as usize;
        state.recv.push_back(vec![0; (WINDOW / 2) as usize]);
        let mut out = vec![0; (WINDOW / 2 - 1) as usize];
        assert_eq!(state.take(&mut out), out.len());
        assert_eq!(state.grant(), None);
        assert_eq!(state.take(&mut [0u8; 8]), 1);
        assert_eq!(state.grant(), Some(WINDOW / 2));
        assert_eq!(state.recv_window, WINDOW);
        assert_eq!(state.buffered, 0);
    }
}
