//! Domain egress routes: what a node's users open on chosen domains leaves
//! through another node instead of this node's own address.
//!
//! This is anix-control's 「转发 → 分流」, which reaches the node as the
//! kernel-neutral desired-config member `egress` ([`EgressConfig`]):
//!
//! - `routes` (this node is the source): the domains of a route are sent to
//!   the exit node's relay, a Shadowsocks-2022 server, instead of directly;
//! - `relays` (this node is the exit): Shadowsocks-2022 inbounds the source
//!   nodes connect to; their traffic always leaves directly from here.
//!
//! Every inbound of the node relays through one [`Router`], so the routes
//! apply to all protocols, including future layer-3 inbounds. The router
//! finds a connection's domain in this order:
//!
//! 1. the target the client asked for, when it is a name;
//! 2. for an address target, the TLS SNI or HTTP `Host` of the first bytes
//!    the client sends (waiting at most [`SNIFF_WAIT`] for them);
//! 3. the name a DNS answer relayed through the node mapped the address to
//!    ([`DomainCache`]).
//!
//! UDP datagrams use 1 and 3. Without routes the router is the direct
//! outbound and adds nothing.

use std::collections::{BTreeSet, HashMap};
use std::future::Future;
use std::io;
use std::net::{Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::task::{ready, Context, Poll};
use std::time::Duration;

use engine_inbound::udp::{UdpOutbound, UdpSession};
use engine_outbound::{
    sniff, BoxFuture, BoxStream, DatagramSend, TargetAddr, TcpDialer, TcpOutbound,
};
use outbound_shadowsocks::{Method, Ss2022Outbound};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::direct::DirectOutbound;
use crate::domains::{normalize, DomainCache};

/// The only relay protocol today; an empty `protocol` means it.
pub const RELAY_PROTOCOL: &str = "shadowsocks";
/// How long an address-only connection waits for the client's first bytes
/// before it is routed by address (server-first protocols send nothing).
pub const SNIFF_WAIT: Duration = Duration::from_millis(300);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_ROUTES: usize = 256;
const MAX_DOMAINS: usize = 10_000;
/// Routed UDP flows one client session keeps at once.
const MAX_ROUTED_FLOWS: usize = 64;

/// The member `egress` of a node's desired configuration, as anix-agent
/// passes it on. Unknown fields are ignored so a newer Control can add
/// some. Has no `Debug`: it carries relay keys.
#[derive(Clone, Default, Deserialize, Serialize)]
pub struct EgressConfig {
    #[serde(default)]
    pub routes: Vec<EgressRoute>,
    #[serde(default)]
    pub relays: Vec<EgressRelay>,
}

/// One route of a source node.
#[derive(Clone, Deserialize, Serialize)]
pub struct EgressRoute {
    pub id: u64,
    /// Control's matchers: a bare name (the domain and its subdomains),
    /// `domain:`, `full:`, `keyword:` or `regexp:`.
    pub domains: Vec<String>,
    /// The exit node's relay.
    pub server: EgressServer,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct EgressServer {
    #[serde(default)]
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub method: String,
    pub password: String,
}

/// One relay inbound of an exit node.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct EgressRelay {
    pub id: u64,
    #[serde(default)]
    pub protocol: String,
    pub port: u16,
    pub method: String,
    pub password: String,
}

/// A domain matcher of a route.
enum DomainMatcher {
    /// The domain and its subdomains.
    Domain(String),
    Full(String),
    Keyword(String),
    Regexp(Regex),
}

impl DomainMatcher {
    fn parse(entry: &str) -> Result<Self, String> {
        let entry = entry.trim();
        let (kind, value) = entry.split_once(':').unwrap_or(("domain", entry));
        let name = || {
            normalize(value.trim_start_matches('.'))
                .ok_or_else(|| format!("{value:?} is not a domain name"))
        };
        match kind.to_ascii_lowercase().as_str() {
            "domain" => name().map(DomainMatcher::Domain),
            "full" => name().map(DomainMatcher::Full),
            "keyword" if !value.is_empty() => Ok(DomainMatcher::Keyword(value.to_lowercase())),
            "regexp" => RegexBuilder::new(value)
                .size_limit(1 << 20)
                .build()
                .map(DomainMatcher::Regexp)
                .map_err(|_| format!("regexp {value:?} does not compile")),
            other => Err(format!(
                "unknown matcher {other:?} (domain, full, keyword or regexp)"
            )),
        }
    }

    /// `host` is lowercase without a final dot.
    fn matches(&self, host: &str) -> bool {
        match self {
            DomainMatcher::Domain(domain) => {
                host == domain
                    || (host.len() > domain.len()
                        && host.ends_with(domain.as_str())
                        && host.as_bytes()[host.len() - domain.len() - 1] == b'.')
            }
            DomainMatcher::Full(domain) => host == domain,
            DomainMatcher::Keyword(word) => host.contains(word.as_str()),
            DomainMatcher::Regexp(pattern) => pattern.is_match(host),
        }
    }
}

struct CompiledRoute {
    id: u64,
    matchers: Vec<DomainMatcher>,
    outbound: Arc<Ss2022Outbound>,
}

/// The routes in id order; the first that matches a host wins.
#[derive(Default)]
pub(crate) struct RouteTable {
    routes: Vec<CompiledRoute>,
}

impl RouteTable {
    fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    fn find(&self, host: &str) -> Option<&CompiledRoute> {
        self.routes
            .iter()
            .find(|route| route.matchers.iter().any(|matcher| matcher.matches(host)))
    }
}

/// Checks the whole configuration and compiles its routes; nothing is
/// applied when any entry is invalid. Messages name the entry, never a key.
pub(crate) fn compile(config: &EgressConfig) -> Result<RouteTable, String> {
    if config.routes.len() > MAX_ROUTES || config.relays.len() > MAX_ROUTES {
        return Err(format!("egress: at most {MAX_ROUTES} routes and relays"));
    }
    let mut ids = BTreeSet::new();
    let mut routes = Vec::with_capacity(config.routes.len());
    for route in &config.routes {
        let fail = |message: String| format!("egress route {}: {message}", route.id);
        if route.id == 0 || !ids.insert(route.id) {
            return Err(fail("the id is missing or repeated".into()));
        }
        if route.domains.is_empty() || route.domains.len() > MAX_DOMAINS {
            return Err(fail(format!("1 to {MAX_DOMAINS} domains")));
        }
        let matchers = route
            .domains
            .iter()
            .map(|entry| DomainMatcher::parse(entry))
            .collect::<Result<Vec<_>, _>>()
            .map_err(fail)?;
        let server = &route.server;
        check_protocol(&server.protocol).map_err(fail)?;
        if server.host.trim().is_empty() || server.port == 0 {
            return Err(fail("the server needs a host and a port".into()));
        }
        let method = Method::parse(&server.method)
            .map_err(|_| fail(format!("unsupported method {:?}", server.method)))?;
        let outbound = Ss2022Outbound::new(
            server.host.trim(),
            server.port,
            method,
            &server.password,
            Arc::new(TcpDialer),
        )
        .map_err(|_| fail("the server key does not fit the method".into()))?;
        routes.push(CompiledRoute {
            id: route.id,
            matchers,
            outbound: Arc::new(outbound),
        });
    }
    routes.sort_by_key(|route| route.id);
    let mut ids = BTreeSet::new();
    let mut ports = BTreeSet::new();
    for relay in &config.relays {
        let fail = |message: String| format!("egress relay {}: {message}", relay.id);
        if relay.id == 0 || !ids.insert(relay.id) {
            return Err(fail("the id is missing or repeated".into()));
        }
        check_protocol(&relay.protocol).map_err(fail)?;
        if relay.port == 0 || !ports.insert(relay.port) {
            return Err(fail(format!("port {} is missing or repeated", relay.port)));
        }
    }
    Ok(RouteTable { routes })
}

fn check_protocol(protocol: &str) -> Result<(), String> {
    if protocol.is_empty() || protocol == RELAY_PROTOCOL {
        Ok(())
    } else {
        Err(format!("anixcore has no relay protocol {protocol:?}"))
    }
}

/// The node's routes and address-to-name map, shared by every inbound.
#[derive(Default)]
pub struct Egress {
    table: RwLock<Arc<RouteTable>>,
    domains: DomainCache,
}

impl Egress {
    pub fn new() -> Self {
        Self::default()
    }

    /// Addresses mapped to names; inbounds with their own resolver record
    /// their answers here.
    pub fn domains(&self) -> &DomainCache {
        &self.domains
    }

    /// Route ids, in the order they are tried.
    pub fn route_ids(&self) -> Vec<u64> {
        self.table().routes.iter().map(|route| route.id).collect()
    }

    /// The id of the route `host` takes, if any.
    pub fn route_for(&self, host: &str) -> Option<u64> {
        let host = normalize(host)?;
        self.table().find(&host).map(|route| route.id)
    }

    pub(crate) fn set_table(&self, table: RouteTable) {
        *self.table.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(table);
    }

    fn table(&self) -> Arc<RouteTable> {
        self.table.read().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

/// The outbound of every inbound: the egress route a connection's domain
/// matches, else the direct outbound.
#[derive(Clone)]
pub struct Router {
    direct: Arc<DirectOutbound>,
    egress: Arc<Egress>,
}

impl Router {
    pub fn new(direct: DirectOutbound, egress: Arc<Egress>) -> Self {
        Self {
            direct: Arc::new(direct),
            egress,
        }
    }

    async fn connect_by(&self, target: &TargetAddr, host: Option<&str>) -> io::Result<BoxStream> {
        let table = self.egress.table();
        match host.and_then(|host| table.find(host)) {
            Some(route) => route.outbound.connect(target).await,
            None => self.direct.connect(target).await,
        }
    }
}

impl TcpOutbound for Router {
    fn protocol(&self) -> &'static str {
        "router"
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            if self.egress.table().is_empty() {
                return self.direct.connect(target).await;
            }
            match target {
                TargetAddr::Domain(host, _) => {
                    let host = normalize(host);
                    self.connect_by(target, host.as_deref()).await
                }
                TargetAddr::Ip(_) => Ok(Box::new(SniffStream {
                    router: self.clone(),
                    target: target.clone(),
                    state: State::Waiting(Box::pin(tokio::time::sleep(SNIFF_WAIT))),
                }) as BoxStream),
            }
        })
    }
}

/// An address-only connection that is routed once the client's first bytes
/// (or [`SNIFF_WAIT`] without any) show its domain.
struct SniffStream {
    router: Router,
    target: TargetAddr,
    state: State,
}

enum State {
    Waiting(Pin<Box<tokio::time::Sleep>>),
    Connecting(BoxFuture<'static, io::Result<BoxStream>>),
    Connected(BoxStream),
    Failed(io::ErrorKind),
}

impl SniffStream {
    /// Picks the route from `first` (the client's first bytes, or none) and
    /// starts connecting.
    fn decide(&mut self, first: &[u8]) {
        let host = sniff::host(first).or_else(|| match &self.target {
            TargetAddr::Ip(address) => self.router.egress.domains.lookup(address.ip()),
            TargetAddr::Domain(..) => None,
        });
        let router = self.router.clone();
        let target = self.target.clone();
        self.state = State::Connecting(Box::pin(async move {
            tokio::time::timeout(CONNECT_TIMEOUT, router.connect_by(&target, host.as_deref()))
                .await
                .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
        }));
    }

    /// Drives the connect; `Ok` once connected.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let State::Connecting(connecting) = &mut self.state {
            match connecting.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(stream)) => self.state = State::Connected(stream),
                Poll::Ready(Err(error)) => {
                    self.state = State::Failed(error.kind());
                    return Poll::Ready(Err(error));
                }
            }
        }
        match &self.state {
            State::Failed(kind) => Poll::Ready(Err((*kind).into())),
            _ => Poll::Ready(Ok(())),
        }
    }

    fn connected(&mut self) -> Pin<&mut BoxStream> {
        match &mut self.state {
            State::Connected(stream) => Pin::new(stream),
            _ => unreachable!("poll_ready answered Ok"),
        }
    }
}

impl AsyncRead for SniffStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let State::Waiting(wait) = &mut this.state {
            ready!(wait.as_mut().poll(cx));
            this.decide(&[]);
        }
        ready!(this.poll_ready(cx))?;
        this.connected().poll_read(cx, buf)
    }
}

impl AsyncWrite for SniffStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if matches!(this.state, State::Waiting(_)) {
            this.decide(buf);
        }
        ready!(this.poll_ready(cx))?;
        this.connected().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if matches!(this.state, State::Waiting(_)) {
            return Poll::Ready(Ok(()));
        }
        ready!(this.poll_ready(cx))?;
        this.connected().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if matches!(this.state, State::Waiting(_)) {
            this.decide(&[]);
        }
        ready!(this.poll_ready(cx))?;
        this.connected().poll_shutdown(cx)
    }
}

impl UdpOutbound for Router {
    fn bind(&self) -> BoxFuture<'_, io::Result<Arc<dyn UdpSession>>> {
        Box::pin(async move {
            let direct = self.direct.bind().await?;
            let (replies, receiver) = mpsc::channel(256);
            Ok(Arc::new(RoutedUdp {
                direct,
                egress: self.egress.clone(),
                flows: Mutex::new(HashMap::new()),
                replies,
                receiver: tokio::sync::Mutex::new(receiver),
            }) as Arc<dyn UdpSession>)
        })
    }
}

type Reply = (Vec<u8>, SocketAddr);

/// One target's flow through an exit node's relay.
struct RoutedFlow {
    send: Arc<tokio::sync::Mutex<Box<dyn DatagramSend>>>,
    reader: JoinHandle<()>,
}

/// A client's UDP session: direct datagrams on one socket, routed ones on
/// a relay flow per target. DNS replies are recorded on the way back.
struct RoutedUdp {
    direct: Arc<dyn UdpSession>,
    egress: Arc<Egress>,
    flows: Mutex<HashMap<TargetAddr, RoutedFlow>>,
    replies: mpsc::Sender<Reply>,
    receiver: tokio::sync::Mutex<mpsc::Receiver<Reply>>,
}

impl RoutedUdp {
    async fn flow(
        &self,
        outbound: &Ss2022Outbound,
        target: &TargetAddr,
    ) -> io::Result<Arc<tokio::sync::Mutex<Box<dyn DatagramSend>>>> {
        if let Some(flow) = self.lock().get(target) {
            return Ok(flow.send.clone());
        }
        if self.lock().len() >= MAX_ROUTED_FLOWS {
            return Err(io::Error::other("too many routed UDP flows"));
        }
        let flow = outbound.open_udp(target).await?;
        let source = reply_source(target).await;
        let (send, mut recv) = (flow.send, flow.recv);
        let replies = self.replies.clone();
        let egress = self.egress.clone();
        let reader = tokio::spawn(async move {
            while let Ok(payload) = recv.recv().await {
                if source.port() == 53 {
                    egress.domains.record_response(&payload);
                }
                if replies.send((payload, source)).await.is_err() {
                    return;
                }
            }
        });
        let send = Arc::new(tokio::sync::Mutex::new(send));
        let previous = self.lock().insert(
            target.clone(),
            RoutedFlow {
                send: send.clone(),
                reader,
            },
        );
        if let Some(previous) = previous {
            previous.reader.abort();
        }
        Ok(send)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<TargetAddr, RoutedFlow>> {
        self.flows.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// The source a routed flow's replies are reported from: the target
/// itself, or the first address its name resolves to.
async fn reply_source(target: &TargetAddr) -> SocketAddr {
    match target {
        TargetAddr::Ip(address) => *address,
        TargetAddr::Domain(host, port) => tokio::net::lookup_host((host.as_str(), *port))
            .await
            .ok()
            .and_then(|mut addresses| addresses.next())
            .map(|address| SocketAddr::new(address.ip().to_canonical(), address.port()))
            .unwrap_or_else(|| SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), *port)),
    }
}

impl UdpSession for RoutedUdp {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        target: &'a TargetAddr,
    ) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let table = self.egress.table();
            let host = match target {
                _ if table.is_empty() => None,
                TargetAddr::Domain(host, _) => normalize(host),
                TargetAddr::Ip(address) => self.egress.domains.lookup(address.ip()),
            };
            match host.as_deref().and_then(|host| table.find(host)) {
                Some(route) => {
                    let send = self.flow(&route.outbound, target).await?;
                    let mut send = send.lock().await;
                    send.send(payload).await
                }
                None => self.direct.send_to(payload, target).await,
            }
        })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, io::Result<(usize, SocketAddr)>> {
        Box::pin(async move {
            enum Got {
                Direct(io::Result<(usize, SocketAddr)>),
                Routed(Option<Reply>),
            }
            let mut receiver = self.receiver.lock().await;
            let got = tokio::select! {
                received = self.direct.recv_from(buf) => Got::Direct(received),
                reply = receiver.recv() => Got::Routed(reply),
            };
            match got {
                Got::Direct(received) => {
                    let (n, source) = received?;
                    if source.port() == 53 {
                        self.egress.domains.record_response(&buf[..n]);
                    }
                    Ok((n, source))
                }
                Got::Routed(Some((payload, source))) => {
                    let n = payload.len().min(buf.len());
                    buf[..n].copy_from_slice(&payload[..n]);
                    Ok((n, source))
                }
                Got::Routed(None) => Err(io::ErrorKind::BrokenPipe.into()),
            }
        })
    }
}

impl Drop for RoutedUdp {
    fn drop(&mut self) {
        for flow in self.lock().values() {
            flow.reader.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAA==";

    fn config(value: serde_json::Value) -> EgressConfig {
        serde_json::from_value(value).unwrap()
    }

    fn route(id: u64, domains: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "id": id, "domains": domains,
            "server": {"protocol": "shadowsocks", "host": "exit.example.test", "port": 8443,
                       "method": "2022-blake3-aes-128-gcm", "password": KEY}
        })
    }

    #[test]
    fn matches_control_matchers() {
        let egress = Egress::new();
        egress.set_table(
            compile(&config(serde_json::json!({"routes": [
                route(2, &["openai.com", "full:claude.ai", "keyword:gemini", r"regexp:^api\d+\.x\.test$"]),
                route(1, &[".Example.TEST"]),
            ]})))
            .unwrap(),
        );
        assert_eq!(egress.route_ids(), [1, 2]);
        assert_eq!(egress.route_for("openai.com"), Some(2));
        assert_eq!(egress.route_for("chat.OpenAI.com."), Some(2));
        assert_eq!(egress.route_for("notopenai.com"), None);
        assert_eq!(egress.route_for("claude.ai"), Some(2));
        assert_eq!(egress.route_for("www.claude.ai"), None);
        assert_eq!(egress.route_for("gemini.google.test"), Some(2));
        assert_eq!(egress.route_for("api42.x.test"), Some(2));
        assert_eq!(egress.route_for("api.x.test"), None);
        // Routes are tried in id order.
        assert_eq!(egress.route_for("a.example.test"), Some(1));
        assert_eq!(egress.route_for("192.0.2.1"), None);
    }

    #[test]
    fn refuses_invalid_entries_without_echoing_keys() {
        let cases = [
            serde_json::json!({"routes": [route(0, &["a.test"])]}),
            serde_json::json!({"routes": [route(1, &["a.test"]), route(1, &["b.test"])]}),
            serde_json::json!({"routes": [route(1, &[])]}),
            serde_json::json!({"routes": [route(1, &["geosite:openai"])]}),
            serde_json::json!({"routes": [route(1, &["regexp:("])]}),
            serde_json::json!({"routes": [{"id": 1, "domains": ["a.test"], "server":
                {"host": "h", "port": 1, "method": "aes-128-gcm", "password": KEY}}]}),
            serde_json::json!({"routes": [{"id": 1, "domains": ["a.test"], "server":
                {"protocol": "vless", "host": "h", "port": 1, "method": "2022-blake3-aes-128-gcm", "password": KEY}}]}),
            serde_json::json!({"routes": [{"id": 1, "domains": ["a.test"], "server":
                {"host": "h", "port": 1, "method": "2022-blake3-aes-256-gcm", "password": "secret-key"}}]}),
            serde_json::json!({"relays": [
                {"id": 1, "port": 9000, "method": "2022-blake3-aes-128-gcm", "password": KEY},
                {"id": 2, "port": 9000, "method": "2022-blake3-aes-128-gcm", "password": KEY}]}),
        ];
        for case in cases {
            let error = compile(&config(case)).err().expect("refused");
            assert!(error.starts_with("egress "), "{error}");
            assert!(!error.contains(KEY) && !error.contains("secret-key"), "{error}");
        }
        assert!(compile(&EgressConfig::default()).unwrap().is_empty());
    }

    #[tokio::test]
    async fn waits_for_the_first_bytes_of_an_address_target() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    while let Ok(n) = stream.read(&mut buf).await {
                        if n == 0 || stream.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        let egress = Arc::new(Egress::new());
        egress.set_table(
            compile(&config(serde_json::json!({"routes": [route(1, &["a.test"])]}))).unwrap(),
        );
        let router = Router::new(DirectOutbound::new(true, Vec::new()), egress);
        let target = TargetAddr::Ip(address);

        // Client first: the bytes pick the route (none here), then pass.
        let mut stream = router.connect(&target).await.unwrap();
        stream.write_all(b"GET / HTTP/1.1\r\nHost: b.test\r\n\r\n").await.unwrap();
        let mut echo = [0u8; 16];
        stream.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"GET / HTTP/1.1\r\n");

        // Server first: after the wait the address is used.
        let mut stream = router.connect(&target).await.unwrap();
        let started = tokio::time::Instant::now();
        let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut echo)).await;
        assert!(read.is_err(), "the echo server sends nothing first");
        assert!(started.elapsed() >= SNIFF_WAIT);
        stream.write_all(b"ping").await.unwrap();
        stream.read_exact(&mut echo[..4]).await.unwrap();
        assert_eq!(&echo[..4], b"ping");
    }
}
