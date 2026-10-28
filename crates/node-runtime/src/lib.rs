//! Node server runtime: the part of `anixcore` that a node agent drives.
//!
//! A [`Node`] runs inbounds by tag, each on its own TCP listener or UDP
//! socket, relaying through a direct outbound. Inbounds and their users can be
//! added and removed while the node runs; per-user traffic and online IPs are
//! read back for accounting. [`api`] exposes the same operations as a small
//! local HTTP/JSON management API for agents such as anix-agent.
//!
//! The direct outbound refuses loopback, private and link-local targets
//! unless `allow_private_targets` is set, so users cannot reach services on
//! the node or its network; an inbound's own `fallback` and REALITY
//! `handshake` addresses are always allowed.
//!
//! Every inbound relays through the node's [`egress::Router`]: the domain
//! egress routes of the panel ([`Node::apply_egress`]) send chosen domains
//! out through another node's Shadowsocks-2022 relay, and the relays this
//! node serves as an exit node run beside the inbounds.
//!
//! What no egress route takes leaves through the inbound's base outbound:
//! the direct outbound, or an outbound the embedding binary registered by
//! name ([`Node::with_outbound`]), such as a tunnel to another node. An
//! inbound picks one with its `outbound` key; without it the node's
//! default ([`Node::with_default_outbound`]) applies, else direct. A
//! registered outbound applies its own target policy:
//! `allow_private_targets` only governs the direct outbound.
//!
//! A `"type": "forward"` inbound ([`FORWARD_TYPE`]) is a panel forwarding
//! rule: its listen port relays TCP and UDP to one fixed `server:port`
//! through its base outbound only (egress routes do not apply), and the
//! inbound's bytes are read back with [`Node::inbound_traffic`].

pub mod api;
pub mod config;
mod direct;
pub mod domains;
pub mod egress;

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use engine_inbound::registry::{BuildError, Inbound, InboundRegistry, Settings};
use engine_inbound::server::{serve_with_udp, InboundStats, ServeSettings};
use engine_inbound::udp::UdpOutbound;
use engine_inbound::UserStore;
use engine_outbound::TcpOutbound;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

pub use config::{InboundConfig, ManagementSettings, NodeConfig};
pub use direct::DirectOutbound;
pub use egress::{Egress, EgressConfig};

use egress::{EgressRelay, Router};

/// The name an inbound's `outbound` key uses for the direct outbound.
pub const DIRECT_OUTBOUND: &str = "direct";

/// The `type` of fixed-target port forwards (`inbound-forward`): their
/// target is the operator's, so it passes the private-target filter, and
/// they leave through their base outbound without egress routes.
pub const FORWARD_TYPE: &str = "forward";

/// An inbound's base outbound, for TCP connections and UDP sessions.
#[derive(Clone)]
pub struct NodeOutbound {
    pub tcp: Arc<dyn TcpOutbound>,
    pub udp: Arc<dyn UdpOutbound>,
}

impl NodeOutbound {
    pub fn new(tcp: Arc<dyn TcpOutbound>, udp: Arc<dyn UdpOutbound>) -> Self {
        Self { tcp, udp }
    }

    pub fn direct(direct: DirectOutbound) -> Self {
        let direct = Arc::new(direct);
        Self {
            tcp: direct.clone(),
            udp: direct,
        }
    }
}

/// The inbound protocols this build was compiled with.
pub fn default_registry() -> InboundRegistry {
    #[allow(unused_mut)]
    let mut registry = InboundRegistry::new();
    #[cfg(feature = "shadowsocks")]
    registry.register(Arc::new(inbound_shadowsocks::ShadowsocksInboundFactory));
    #[cfg(feature = "trojan")]
    registry.register(Arc::new(inbound_trojan::TrojanInboundFactory));
    #[cfg(feature = "snell")]
    registry.register(Arc::new(inbound_snell::SnellInboundFactory));
    #[cfg(feature = "vless")]
    registry.register(Arc::new(inbound_vless::VlessInboundFactory));
    #[cfg(feature = "vmess")]
    registry.register(Arc::new(inbound_vmess::VmessInboundFactory));
    #[cfg(feature = "hysteria2")]
    registry.register_packet(Arc::new(inbound_hysteria2::Hysteria2InboundFactory));
    #[cfg(feature = "tuic")]
    registry.register_packet(Arc::new(inbound_tuic::TuicInboundFactory));
    #[cfg(feature = "iwan")]
    registry.register_packet(Arc::new(inbound_iwan::IwanInboundFactory));
    #[cfg(feature = "forward")]
    registry.register(Arc::new(inbound_forward::ForwardInboundFactory));
    registry
}

#[derive(Debug)]
pub enum NodeError {
    NotFound,
    Exists,
    Invalid(BuildError),
    /// An egress configuration was refused; nothing of it was applied.
    Egress(String),
    Io(io::Error),
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeError::NotFound => f.write_str("inbound not found"),
            NodeError::Exists => f.write_str("inbound tag already exists"),
            NodeError::Invalid(reason) => f.write_str(reason),
            NodeError::Egress(reason) => f.write_str(reason),
            NodeError::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for NodeError {}

impl From<io::Error> for NodeError {
    fn from(error: io::Error) -> Self {
        NodeError::Io(error)
    }
}

/// Counters of one running inbound.
#[derive(Clone, Debug, Serialize)]
pub struct InboundInfo {
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub listen: SocketAddr,
    pub users: usize,
    pub accepted: u64,
    pub active: u64,
    pub handshake_failed: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    /// The base outbound's name; [`DIRECT_OUTBOUND`] for direct.
    pub outbound: String,
}

/// Bytes relayed by one inbound, all users and none together.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct InboundTraffic {
    /// Client to target.
    pub up: u64,
    /// Target to client.
    pub down: u64,
}

/// What an egress configuration runs on this node.
#[derive(Clone, Debug, Serialize)]
pub struct EgressStatus {
    /// Route ids, in the order they are tried.
    pub routes: Vec<u64>,
    pub relays: Vec<RelayInfo>,
    /// Addresses currently mapped to names from DNS answers.
    pub mapped_addresses: usize,
}

/// Counters of one egress relay; never its key.
#[derive(Clone, Debug, Serialize)]
pub struct RelayInfo {
    pub id: u64,
    pub listen: SocketAddr,
    pub accepted: u64,
    pub active: u64,
    pub handshake_failed: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

struct Running {
    kind: String,
    outbound: String,
    listen: SocketAddr,
    inbound: Inbound,
    stats: Arc<InboundStats>,
    task: JoinHandle<()>,
    /// Bytes up and down already reported by a resetting
    /// [`Node::inbound_traffic`] call.
    reported: Mutex<(u64, u64)>,
}

struct RunningRelay {
    config: EgressRelay,
    running: Running,
}

pub struct Node {
    registry: InboundRegistry,
    serve_settings: ServeSettings,
    allow_private_targets: bool,
    inbounds: Mutex<BTreeMap<String, Running>>,
    egress: Arc<Egress>,
    /// Relays by id; also serializes [`Node::apply_egress`].
    relays: tokio::sync::Mutex<BTreeMap<u64, RunningRelay>>,
    /// Base outbounds the embedding binary registered, by name.
    outbounds: BTreeMap<String, NodeOutbound>,
    default_outbound: Option<String>,
}

impl Node {
    pub fn new(registry: InboundRegistry, allow_private_targets: bool) -> Self {
        Self {
            registry,
            serve_settings: ServeSettings::default(),
            allow_private_targets,
            inbounds: Mutex::new(BTreeMap::new()),
            egress: Arc::new(Egress::new()),
            relays: tokio::sync::Mutex::new(BTreeMap::new()),
            outbounds: BTreeMap::new(),
            default_outbound: None,
        }
    }

    pub fn with_serve_settings(mut self, settings: ServeSettings) -> Self {
        self.serve_settings = settings;
        self
    }

    /// Registers a base outbound inbounds can name in their `outbound` key.
    /// A later registration under the same name replaces the earlier one;
    /// [`DIRECT_OUTBOUND`] always means the direct outbound.
    pub fn with_outbound(mut self, name: impl Into<String>, outbound: NodeOutbound) -> Self {
        self.outbounds.insert(name.into(), outbound);
        self
    }

    /// The base outbound of inbounds without an `outbound` key; `None` (the
    /// default) is direct. An unknown name fails when an inbound is added.
    pub fn with_default_outbound(mut self, name: Option<String>) -> Self {
        self.default_outbound = name;
        self
    }

    /// Registered base outbound names, without [`DIRECT_OUTBOUND`].
    pub fn outbounds(&self) -> Vec<String> {
        self.outbounds.keys().cloned().collect()
    }

    /// The base outbound `name` stands for; `None` when it is unknown.
    fn base_outbound(&self, name: &str, config: &InboundConfig) -> Option<NodeOutbound> {
        if name == DIRECT_OUTBOUND {
            return Some(NodeOutbound::direct(DirectOutbound::new(
                self.allow_private_targets,
                config.allowed_targets(),
            )));
        }
        self.outbounds.get(name).cloned()
    }

    /// Builds, binds and starts an inbound. Returns the bound address.
    pub async fn add_inbound(&self, config: InboundConfig) -> Result<SocketAddr, NodeError> {
        if !valid_tag(&config.tag) {
            return Err(NodeError::Invalid(
                "inbound tag must be 1-64 letters, digits, '.', '_' or '-'",
            ));
        }
        if self.lock().contains_key(&config.tag) {
            return Err(NodeError::Exists);
        }
        let outbound = config
            .outbound
            .clone()
            .or_else(|| self.default_outbound.clone())
            .unwrap_or_else(|| DIRECT_OUTBOUND.to_owned());
        let base = self
            .base_outbound(&outbound, &config)
            .ok_or(NodeError::Invalid("inbound names an unknown outbound"))?;
        let inbound = self
            .registry
            .build(&config.kind, &config.settings)
            .map_err(NodeError::Invalid)?;
        let address = SocketAddr::new(config.listen, config.listen_port);
        let (listen, stats, task) = if config.kind == FORWARD_TYPE {
            self.spawn(&inbound, address, base.tcp, base.udp)?
        } else {
            let router = Arc::new(Router::new(base, self.egress.clone()));
            self.spawn(&inbound, address, router.clone(), router)?
        };
        let mut inbounds = self.lock();
        if inbounds.contains_key(&config.tag) {
            task.abort();
            return Err(NodeError::Exists);
        }
        inbounds.insert(
            config.tag,
            Running {
                kind: config.kind,
                outbound,
                listen,
                inbound,
                stats,
                task,
                reported: Mutex::new((0, 0)),
            },
        );
        Ok(listen)
    }

    /// Binds `inbound` on `address` and starts serving it.
    fn spawn(
        &self,
        inbound: &Inbound,
        address: SocketAddr,
        outbound: Arc<dyn TcpOutbound>,
        udp: Arc<dyn UdpOutbound>,
    ) -> io::Result<(SocketAddr, Arc<InboundStats>, JoinHandle<()>)> {
        let stats = Arc::new(InboundStats::default());
        let settings = self.serve_settings.clone();
        let (listen, task) = match inbound {
            Inbound::Stream(stream) => {
                let listener = bind_tcp(address)?;
                let listen = listener.local_addr()?;
                // UDP on the same port, for inbounds that take it.
                let datagrams = match stream.datagram() {
                    Some(datagram) => {
                        let socket = bind_udp(listen)?;
                        Some(datagram.serve(socket, udp.clone(), stats.clone()))
                    }
                    None => None,
                };
                let task = tokio::spawn({
                    let (stream, stats) = (stream.clone(), stats.clone());
                    async move {
                        let streams =
                            serve_with_udp(listener, stream, outbound, Some(udp), settings, stats);
                        match datagrams {
                            Some(datagrams) => {
                                let _ = tokio::join!(streams, datagrams);
                            }
                            None => {
                                let _ = streams.await;
                            }
                        }
                    }
                });
                (listen, task)
            }
            Inbound::Packet(packet) => {
                let socket = bind_udp(address)?;
                let listen = socket.local_addr()?;
                let served =
                    packet
                        .clone()
                        .serve(socket, outbound, Some(udp), settings, stats.clone());
                let task = tokio::spawn(async move {
                    let _ = served.await;
                });
                (listen, task)
            }
        };
        Ok((listen, stats, task))
    }

    /// The node's egress routes and address-to-name map.
    pub fn egress(&self) -> &Arc<Egress> {
        &self.egress
    }

    /// Replaces the egress routes and relays with `config`. Nothing changes
    /// when an entry is invalid. Relays that are unchanged keep running and
    /// keep their connections; a relay whose port cannot be bound fails
    /// alone, after everything else was applied. Connections already open
    /// keep the path they took.
    pub async fn apply_egress(&self, config: &EgressConfig) -> Result<EgressStatus, NodeError> {
        let table = egress::compile(config).map_err(NodeError::Egress)?;
        let mut built = Vec::new();
        for relay in &config.relays {
            let mut settings = Settings::new();
            settings.insert("method".into(), relay.method.clone().into());
            settings.insert("password".into(), relay.password.clone().into());
            let inbound = self
                .registry
                .build(egress::RELAY_PROTOCOL, &settings)
                .map_err(|reason| {
                    NodeError::Egress(format!("egress relay {}: {reason}", relay.id))
                })?;
            built.push((relay.clone(), inbound));
        }
        let mut relays = self.relays.lock().await;
        self.egress.set_table(table);
        let stale: Vec<u64> = relays
            .iter()
            .filter(|(id, running)| {
                !config
                    .relays
                    .iter()
                    .any(|relay| relay.id == **id && *relay == running.config)
            })
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            if let Some(relay) = relays.remove(&id) {
                // Wait for the listener to close: a changed relay binds the
                // same port again right after.
                relay.running.task.abort();
                let _ = relay.running.task.await;
            }
        }
        let mut failed = Vec::new();
        for (relay, inbound) in built {
            if relays.contains_key(&relay.id) {
                continue;
            }
            // A relay's traffic leaves here: direct, never another route.
            let direct = Arc::new(DirectOutbound::new(self.allow_private_targets, Vec::new()));
            let address = SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), relay.port);
            match self.spawn(&inbound, address, direct.clone(), direct) {
                Ok((listen, stats, task)) => {
                    relays.insert(
                        relay.id,
                        RunningRelay {
                            running: Running {
                                kind: egress::RELAY_PROTOCOL.to_owned(),
                                outbound: DIRECT_OUTBOUND.to_owned(),
                                listen,
                                inbound,
                                stats,
                                task,
                                reported: Mutex::new((0, 0)),
                            },
                            config: relay,
                        },
                    );
                }
                Err(error) => failed.push(format!("egress relay {}: {error}", relay.id)),
            }
        }
        if !failed.is_empty() {
            return Err(NodeError::Io(io::Error::other(failed.join("; "))));
        }
        Ok(self.egress_status(&relays))
    }

    /// What the egress configuration runs now.
    pub async fn egress_state(&self) -> EgressStatus {
        let relays = self.relays.lock().await;
        self.egress_status(&relays)
    }

    fn egress_status(&self, relays: &BTreeMap<u64, RunningRelay>) -> EgressStatus {
        EgressStatus {
            routes: self.egress.route_ids(),
            relays: relays
                .iter()
                .map(|(id, relay)| {
                    let stats = &relay.running.stats;
                    RelayInfo {
                        id: *id,
                        listen: relay.running.listen,
                        accepted: stats.accepted.load(Ordering::Relaxed),
                        active: stats.active.load(Ordering::Relaxed),
                        handshake_failed: stats.handshake_failed.load(Ordering::Relaxed),
                        bytes_up: stats.bytes_up.load(Ordering::Relaxed),
                        bytes_down: stats.bytes_down.load(Ordering::Relaxed),
                    }
                })
                .collect(),
            mapped_addresses: self.egress.domains().len(),
        }
    }

    /// Stops an inbound and closes its users' connections.
    pub fn remove_inbound(&self, tag: &str) -> Result<(), NodeError> {
        let running = self.lock().remove(tag).ok_or(NodeError::NotFound)?;
        running.task.abort();
        let users = running.inbound.users();
        for name in users.names() {
            users.remove(&name);
        }
        Ok(())
    }

    /// The user table of an inbound.
    pub fn users(&self, tag: &str) -> Result<Arc<UserStore>, NodeError> {
        self.lock()
            .get(tag)
            .map(|running| running.inbound.users().clone())
            .ok_or(NodeError::NotFound)
    }

    /// Bytes an inbound relayed since the last call with `reset`, or since
    /// it started; `reset` starts the next interval. Unlike per-user
    /// traffic this covers inbounds without users, such as forwards.
    pub fn inbound_traffic(&self, tag: &str, reset: bool) -> Result<InboundTraffic, NodeError> {
        let inbounds = self.lock();
        let running = inbounds.get(tag).ok_or(NodeError::NotFound)?;
        let total = (
            running.stats.bytes_up.load(Ordering::Relaxed),
            running.stats.bytes_down.load(Ordering::Relaxed),
        );
        let mut reported = running
            .reported
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let traffic = InboundTraffic {
            up: total.0.saturating_sub(reported.0),
            down: total.1.saturating_sub(reported.1),
        };
        if reset {
            *reported = total;
        }
        Ok(traffic)
    }

    pub fn list(&self) -> Vec<InboundInfo> {
        self.lock()
            .iter()
            .map(|(tag, running)| {
                let stats = &running.stats;
                InboundInfo {
                    tag: tag.clone(),
                    kind: running.kind.clone(),
                    listen: running.listen,
                    users: running.inbound.users().len(),
                    accepted: stats.accepted.load(Ordering::Relaxed),
                    active: stats.active.load(Ordering::Relaxed),
                    handshake_failed: stats.handshake_failed.load(Ordering::Relaxed),
                    bytes_up: stats.bytes_up.load(Ordering::Relaxed),
                    bytes_down: stats.bytes_down.load(Ordering::Relaxed),
                    outbound: running.outbound.clone(),
                }
            })
            .collect()
    }

    /// Registered inbound type names.
    pub fn types(&self) -> Vec<&'static str> {
        self.registry.type_names()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Running>> {
        self.inbounds
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        for running in self.lock().values() {
            running.task.abort();
        }
        for relay in self.relays.get_mut().values() {
            relay.running.task.abort();
        }
    }
}

/// Binds a TCP listener; `[::]` listens on IPv4 too (on every OS) and
/// falls back to `0.0.0.0` on a host without IPv6.
fn bind_tcp(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = match bind(address, socket2::Type::STREAM) {
        Err(error) if is_any_v6(address) && error.kind() != io::ErrorKind::AddrInUse => {
            bind(any_v4(address), socket2::Type::STREAM)?
        }
        bound => bound?,
    };
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

/// Binds a UDP socket like [`bind_tcp`].
fn bind_udp(address: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let socket = match bind(address, socket2::Type::DGRAM) {
        Err(error) if is_any_v6(address) && error.kind() != io::ErrorKind::AddrInUse => {
            bind(any_v4(address), socket2::Type::DGRAM)?
        }
        bound => bound?,
    };
    Ok(socket.into())
}

fn bind(address: SocketAddr, kind: socket2::Type) -> io::Result<socket2::Socket> {
    let socket = socket2::Socket::new(socket2::Domain::for_address(address), kind, None)?;
    if is_any_v6(address) {
        socket.set_only_v6(false)?;
    }
    // As tokio does; Windows' SO_REUSEADDR would let others share the port.
    if cfg!(unix) && kind == socket2::Type::STREAM {
        socket.set_reuse_address(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    Ok(socket)
}

fn is_any_v6(address: SocketAddr) -> bool {
    address.is_ipv6() && address.ip().is_unspecified()
}

fn any_v4(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), address.port())
}

fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 64
        && tag
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_tags() {
        assert!(valid_tag("ss-1.node_a"));
        assert!(!valid_tag(""));
        assert!(!valid_tag("a/b"));
        assert!(!valid_tag(&"x".repeat(65)));
    }
}
