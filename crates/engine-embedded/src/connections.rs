//! Connection tracking: the client's connection list and live traffic.
//!
//! Every TCP connection and UDP flow the tunnel or the local proxy opens goes
//! through a [`Dispatcher`], which routes it, registers it with the
//! [`ConnectionTracker`] and wraps its stream so the bytes are counted per
//! connection. A closed connection moves to a short list of recent ones.
//!
//! The list holds destinations (host names and addresses) and which rule and
//! node carried them: data the user asks for to see what their device does.
//! It lives in memory only, is returned only to an explicit `connections`
//! request and is never written to status, logs or errors. Payloads and
//! outbound settings never reach it.

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use engine_outbound::{
    BoxFuture, BoxStream, DatagramRecv, DatagramSend, TargetAddr, TcpDialer, TcpOutbound, UdpFlow,
};
use futures::task::AtomicWaker;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

use crate::direct::DirectOutbound;
use crate::routing::{RouteInfo, RoutedOutbound};

/// Closed connections kept for the list, newest first.
pub const MAX_CLOSED_CONNECTIONS: usize = 128;
/// Shortest interval the traffic rates are measured over; calls closer
/// together report the previous rates.
const RATE_MIN_INTERVAL: Duration = Duration::from_millis(500);

/// How flows are routed, switchable while the engine runs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// The config's rules and policy groups.
    #[default]
    Rule,
    /// Every flow to the global target of a routing config (its outbound for
    /// a config with one outbound).
    Global,
    /// Every flow direct.
    Direct,
}

impl Mode {
    const ALL: [Self; 3] = [Self::Rule, Self::Global, Self::Direct];

    fn from_code(code: u8) -> Self {
        Self::ALL
            .into_iter()
            .find(|mode| *mode as u8 == code)
            .unwrap_or_default()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    Tcp,
    Udp,
}

/// One connection as the list shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConnectionSnapshot {
    pub id: u64,
    pub network: Network,
    /// The destination's host name: the requested domain, or the TLS SNI or
    /// HTTP `Host` sniffed from an address target.
    pub host: Option<String>,
    /// The destination as requested, `address:port` or `domain:port`.
    pub destination: String,
    pub rule: String,
    pub chain: Vec<String>,
    pub outbound: String,
    /// Unix time in milliseconds.
    pub started_at_ms: u64,
    pub ended_at_ms: Option<u64>,
    pub upload: u64,
    pub download: u64,
    /// `rejected` (a REJECT rule) or `connect_failed`.
    pub error: Option<&'static str>,
}

/// Totals since the tunnel started and the current rates in bytes per second.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct TrafficSnapshot {
    pub upload_total: u64,
    pub download_total: u64,
    pub upload_rate: u64,
    pub download_rate: u64,
    pub active: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConnectionsSnapshot {
    pub traffic: TrafficSnapshot,
    /// Oldest first.
    pub active: Vec<ConnectionSnapshot>,
    /// Newest first.
    pub closed: Vec<ConnectionSnapshot>,
}

struct Entry {
    id: u64,
    network: Network,
    host: Option<String>,
    destination: String,
    started_at_ms: u64,
    route: Mutex<RouteInfo>,
    upload: AtomicU64,
    download: AtomicU64,
    connected: AtomicBool,
    error: Mutex<Option<&'static str>>,
    aborted: AtomicBool,
    abort: Notify,
    read_waker: AtomicWaker,
    write_waker: AtomicWaker,
}

impl Entry {
    fn snapshot(&self, ended_at_ms: Option<u64>) -> ConnectionSnapshot {
        let route = lock(&self.route).clone();
        ConnectionSnapshot {
            id: self.id,
            network: self.network,
            host: self.host.clone(),
            destination: self.destination.clone(),
            rule: route.rule,
            chain: route.chain,
            outbound: route.outbound,
            started_at_ms: self.started_at_ms,
            ended_at_ms,
            upload: self.upload.load(Ordering::Relaxed),
            download: self.download.load(Ordering::Relaxed),
            error: *lock(&self.error),
        }
    }

    fn is_aborted(&self) -> bool {
        self.aborted.load(Ordering::Acquire)
    }

    fn abort(&self) {
        self.aborted.store(true, Ordering::Release);
        self.abort.notify_waiters();
        self.read_waker.wake();
        self.write_waker.wake();
    }

    /// Completes once the connection is closed from the list.
    async fn aborted(&self) {
        loop {
            let notified = self.abort.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_aborted() {
                return;
            }
            notified.await;
        }
    }
}

struct RateSample {
    at: Instant,
    upload: u64,
    download: u64,
    upload_rate: u64,
    download_rate: u64,
}

/// Open and recently closed connections, with traffic totals.
pub struct ConnectionTracker {
    next_id: AtomicU64,
    active: Mutex<BTreeMap<u64, Arc<Entry>>>,
    closed: Mutex<VecDeque<ConnectionSnapshot>>,
    upload_total: AtomicU64,
    download_total: AtomicU64,
    sample: Mutex<RateSample>,
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            active: Mutex::default(),
            closed: Mutex::default(),
            upload_total: AtomicU64::new(0),
            download_total: AtomicU64::new(0),
            sample: Mutex::new(RateSample {
                at: Instant::now(),
                upload: 0,
                download: 0,
                upload_rate: 0,
                download_rate: 0,
            }),
        }
    }
}

impl ConnectionTracker {
    /// Registers a new connection. It stays active until the returned guard
    /// and every stream holding it are dropped.
    pub(crate) fn open(
        self: &Arc<Self>,
        network: Network,
        target: &TargetAddr,
        host: Option<&str>,
    ) -> Arc<ConnectionGuard> {
        let host = match target {
            TargetAddr::Domain(domain, _) => Some(domain.clone()),
            TargetAddr::Ip(_) => host.map(str::to_string),
        };
        let entry = Arc::new(Entry {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            network,
            host,
            destination: target.to_string(),
            started_at_ms: unix_millis(),
            route: Mutex::default(),
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
            connected: AtomicBool::new(false),
            error: Mutex::new(None),
            aborted: AtomicBool::new(false),
            abort: Notify::new(),
            read_waker: AtomicWaker::new(),
            write_waker: AtomicWaker::new(),
        });
        lock(&self.active).insert(entry.id, entry.clone());
        Arc::new(ConnectionGuard {
            tracker: self.clone(),
            entry,
        })
    }

    pub fn traffic(&self) -> TrafficSnapshot {
        let upload = self.upload_total.load(Ordering::Relaxed);
        let download = self.download_total.load(Ordering::Relaxed);
        let now = Instant::now();
        let mut sample = lock(&self.sample);
        let elapsed = now.duration_since(sample.at);
        if elapsed >= RATE_MIN_INTERVAL {
            let millis = elapsed.as_millis().max(1);
            let rate = |now: u64, then: u64| {
                u64::try_from(u128::from(now.saturating_sub(then)) * 1000 / millis)
                    .unwrap_or(u64::MAX)
            };
            sample.upload_rate = rate(upload, sample.upload);
            sample.download_rate = rate(download, sample.download);
            sample.at = now;
            sample.upload = upload;
            sample.download = download;
        }
        TrafficSnapshot {
            upload_total: upload,
            download_total: download,
            upload_rate: sample.upload_rate,
            download_rate: sample.download_rate,
            active: lock(&self.active).len(),
        }
    }

    pub fn connections(&self) -> ConnectionsSnapshot {
        let traffic = self.traffic();
        let active = lock(&self.active)
            .values()
            .map(|entry| entry.snapshot(None))
            .collect();
        let closed = lock(&self.closed).iter().cloned().collect();
        ConnectionsSnapshot {
            traffic,
            active,
            closed,
        }
    }

    /// Closes one active connection; `false` when it is not active.
    pub fn close(&self, id: u64) -> bool {
        let entry = lock(&self.active).get(&id).cloned();
        match entry {
            Some(entry) => {
                entry.abort();
                true
            }
            None => false,
        }
    }

    /// Closes every active connection and returns how many there were.
    pub fn close_all(&self) -> usize {
        let entries: Vec<_> = lock(&self.active).values().cloned().collect();
        for entry in &entries {
            entry.abort();
        }
        entries.len()
    }

    fn finish(&self, entry: &Entry) {
        if !entry.connected.load(Ordering::Relaxed) {
            let mut error = lock(&entry.error);
            if error.is_none() {
                *error = Some("connect_failed");
            }
        }
        let removed = lock(&self.active).remove(&entry.id);
        if removed.is_none() {
            return;
        }
        let snapshot = entry.snapshot(Some(unix_millis()));
        let mut closed = lock(&self.closed);
        closed.push_front(snapshot);
        closed.truncate(MAX_CLOSED_CONNECTIONS);
    }
}

/// Keeps a connection in the active list; dropping the last one moves it to
/// the closed list.
pub(crate) struct ConnectionGuard {
    tracker: Arc<ConnectionTracker>,
    entry: Arc<Entry>,
}

impl ConnectionGuard {
    fn set_route(&self, route: RouteInfo) {
        *lock(&self.entry.route) = route;
    }

    fn fail(&self, error: &'static str) {
        *lock(&self.entry.error) = Some(error);
    }

    fn connected(&self) {
        self.entry.connected.store(true, Ordering::Relaxed);
    }

    fn count_upload(&self, bytes: usize) {
        let bytes = bytes as u64;
        self.entry.upload.fetch_add(bytes, Ordering::Relaxed);
        self.tracker
            .upload_total
            .fetch_add(bytes, Ordering::Relaxed);
    }

    fn count_download(&self, bytes: usize) {
        let bytes = bytes as u64;
        self.entry.download.fetch_add(bytes, Ordering::Relaxed);
        self.tracker
            .download_total
            .fetch_add(bytes, Ordering::Relaxed);
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.tracker.finish(&self.entry);
    }
}

fn closed_from_list() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "connection closed from the connection list",
    )
}

/// A connected stream counted into its connection.
struct TrackedStream {
    inner: BoxStream,
    guard: Arc<ConnectionGuard>,
}

impl AsyncRead for TrackedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let entry = &this.guard.entry;
        entry.read_waker.register(cx.waker());
        if entry.is_aborted() {
            return Poll::Ready(Err(closed_from_list()));
        }
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        let read = buf.filled().len() - before;
        if read > 0 {
            this.guard.count_download(read);
        }
        result
    }
}

impl AsyncWrite for TrackedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let entry = &this.guard.entry;
        entry.write_waker.register(cx.waker());
        if entry.is_aborted() {
            return Poll::Ready(Err(closed_from_list()));
        }
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = &result {
            this.guard.count_upload(*written);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

struct TrackedSend {
    inner: Box<dyn DatagramSend>,
    guard: Arc<ConnectionGuard>,
}

impl DatagramSend for TrackedSend {
    fn send<'a>(&'a mut self, payload: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            if self.guard.entry.is_aborted() {
                return Err(closed_from_list());
            }
            self.inner.send(payload).await?;
            self.guard.count_upload(payload.len());
            Ok(())
        })
    }
}

struct TrackedRecv {
    inner: Box<dyn DatagramRecv>,
    guard: Arc<ConnectionGuard>,
}

impl DatagramRecv for TrackedRecv {
    fn recv(&mut self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        Box::pin(async move {
            let guard = self.guard.clone();
            let datagram = tokio::select! {
                datagram = self.inner.recv() => datagram?,
                _ = guard.entry.aborted() => return Err(closed_from_list()),
            };
            guard.count_download(datagram.len());
            Ok(datagram)
        })
    }
}

/// Routes, tracks and connects every flow of a running tunnel or local proxy.
///
/// It is itself a [`TcpOutbound`], so inbounds that take one (the local
/// proxy, HTTPS decryption) need no change; the packet tunnel calls
/// [`Dispatcher::connect_flow`] to add the host it sniffed.
pub struct Dispatcher {
    outbound: Arc<dyn TcpOutbound>,
    routed: Option<Arc<RoutedOutbound>>,
    /// The outbound of the direct mode.
    direct: Arc<dyn TcpOutbound>,
    mode: AtomicU8,
    tracker: Arc<ConnectionTracker>,
}

impl Dispatcher {
    /// Every flow through `outbound`, as a config with one outbound runs. The
    /// direct mode uses the system's sockets; see [`Dispatcher::with_direct`].
    pub fn single(outbound: Arc<dyn TcpOutbound>) -> Self {
        Self {
            outbound,
            routed: None,
            direct: Arc::new(DirectOutbound::new(Arc::new(TcpDialer))),
            mode: AtomicU8::new(Mode::Rule as u8),
            tracker: Arc::default(),
        }
    }

    /// Flows routed by the rules and groups of `routed`; the direct mode uses
    /// its DIRECT outbound.
    pub fn routed(routed: Arc<RoutedOutbound>) -> Self {
        Self {
            outbound: routed.clone(),
            direct: routed.direct().clone(),
            routed: Some(routed),
            mode: AtomicU8::new(Mode::Rule as u8),
            tracker: Arc::default(),
        }
    }

    /// Replaces the outbound of the direct mode.
    pub fn with_direct(mut self, direct: Arc<dyn TcpOutbound>) -> Self {
        self.direct = direct;
        self
    }

    pub fn mode(&self) -> Mode {
        Mode::from_code(self.mode.load(Ordering::Relaxed))
    }

    /// Switches the mode for every later flow; open connections keep their
    /// route.
    pub fn set_mode(&self, mode: Mode) {
        self.mode.store(mode as u8, Ordering::Relaxed);
    }

    /// The rule-based outbound of a routing config, for its policy groups.
    pub fn routed_outbound(&self) -> Option<&Arc<RoutedOutbound>> {
        self.routed.as_ref()
    }

    pub fn tracker(&self) -> &Arc<ConnectionTracker> {
        &self.tracker
    }

    /// The untracked outbound of the direct mode, for DNS servers reached
    /// directly.
    pub fn direct(&self) -> &Arc<dyn TcpOutbound> {
        &self.direct
    }

    /// The untracked outbound, for the tunnel's own DNS queries.
    pub fn outbound(&self) -> &Arc<dyn TcpOutbound> {
        &self.outbound
    }

    /// Picks the outbound for one flow and records the decision.
    async fn route(
        &self,
        target: &TargetAddr,
        host: Option<&str>,
        guard: &ConnectionGuard,
    ) -> io::Result<Arc<dyn TcpOutbound>> {
        let (route, outbound) = match (self.mode(), &self.routed) {
            (Mode::Direct, _) => (direct_route(), Some(self.direct.clone())),
            (Mode::Global, Some(routed)) => routed.route_global(),
            (Mode::Rule, Some(routed)) => routed.route_flow(target, host).await,
            (_, None) => (single_route(&*self.outbound), Some(self.outbound.clone())),
        };
        guard.set_route(route);
        outbound.ok_or_else(|| {
            guard.fail("rejected");
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "connection rejected by routing rule",
            )
        })
    }

    /// Opens a TCP connection to `target`. For an address target, `host` is
    /// the name sniffed from the flow, used for domain rules and the list.
    pub async fn connect_flow(
        &self,
        target: &TargetAddr,
        host: Option<&str>,
    ) -> io::Result<BoxStream> {
        let guard = self.tracker.open(Network::Tcp, target, host);
        let outbound = self.route(target, host, &guard).await?;
        let stream = outbound.connect(target).await?;
        guard.connected();
        Ok(Box::new(TrackedStream {
            inner: stream,
            guard,
        }))
    }

    /// Opens a UDP flow to `target`.
    pub async fn open_udp_flow(
        &self,
        target: &TargetAddr,
        host: Option<&str>,
    ) -> io::Result<UdpFlow> {
        let guard = self.tracker.open(Network::Udp, target, host);
        let outbound = self.route(target, host, &guard).await?;
        let flow = outbound.open_udp(target).await?;
        guard.connected();
        Ok(UdpFlow::new(
            Box::new(TrackedSend {
                inner: flow.send,
                guard: guard.clone(),
            }),
            Box::new(TrackedRecv {
                inner: flow.recv,
                guard,
            }),
        ))
    }

    /// A [`TcpOutbound`] view that adds `host` to every connection, for a
    /// flow handed to the HTTPS decryption interceptor.
    pub fn with_host<'a>(&'a self, host: &'a str) -> HostedDispatcher<'a> {
        HostedDispatcher {
            dispatcher: self,
            host,
        }
    }
}

impl TcpOutbound for Dispatcher {
    fn protocol(&self) -> &'static str {
        self.outbound.protocol()
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(self.connect_flow(target, None))
    }

    fn open_udp<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(self.open_udp_flow(target, None))
    }
}

/// See [`Dispatcher::with_host`].
pub struct HostedDispatcher<'a> {
    dispatcher: &'a Dispatcher,
    host: &'a str,
}

impl TcpOutbound for HostedDispatcher<'_> {
    fn protocol(&self) -> &'static str {
        self.dispatcher.protocol()
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(self.dispatcher.connect_flow(target, Some(self.host)))
    }

    fn open_udp<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(self.dispatcher.open_udp_flow(target, Some(self.host)))
    }
}

/// The route of a config with one outbound.
fn single_route(outbound: &dyn TcpOutbound) -> RouteInfo {
    let name = match outbound.protocol() {
        crate::direct::PROTOCOL => "DIRECT".to_string(),
        protocol => protocol.to_string(),
    };
    RouteInfo {
        rule: "DEFAULT".to_string(),
        chain: vec![name.clone()],
        outbound: name,
    }
}

/// The route of the direct mode.
fn direct_route() -> RouteInfo {
    RouteInfo {
        rule: "MODE,direct".to_string(),
        chain: vec!["DIRECT".to_string()],
        outbound: "DIRECT".to_string(),
    }
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Locks `mutex`, recovering the data when a panic poisoned it: every value
/// behind these locks stays consistent between statements.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
