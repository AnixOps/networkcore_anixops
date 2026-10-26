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

pub mod api;
pub mod config;
mod direct;

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use engine_inbound::registry::{BuildError, Inbound, InboundRegistry};
use engine_inbound::server::{serve, InboundStats, ServeSettings};
use engine_inbound::UserStore;
use engine_outbound::TcpOutbound;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

pub use config::{InboundConfig, ManagementSettings, NodeConfig};
pub use direct::DirectOutbound;

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
    registry
}

#[derive(Debug)]
pub enum NodeError {
    NotFound,
    Exists,
    Invalid(BuildError),
    Io(io::Error),
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeError::NotFound => f.write_str("inbound not found"),
            NodeError::Exists => f.write_str("inbound tag already exists"),
            NodeError::Invalid(reason) => f.write_str(reason),
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
}

struct Running {
    kind: String,
    listen: SocketAddr,
    inbound: Inbound,
    stats: Arc<InboundStats>,
    task: JoinHandle<()>,
}

pub struct Node {
    registry: InboundRegistry,
    serve_settings: ServeSettings,
    allow_private_targets: bool,
    inbounds: Mutex<BTreeMap<String, Running>>,
}

impl Node {
    pub fn new(registry: InboundRegistry, allow_private_targets: bool) -> Self {
        Self {
            registry,
            serve_settings: ServeSettings::default(),
            allow_private_targets,
            inbounds: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn with_serve_settings(mut self, settings: ServeSettings) -> Self {
        self.serve_settings = settings;
        self
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
        let inbound = self
            .registry
            .build(&config.kind, &config.settings)
            .map_err(NodeError::Invalid)?;
        let outbound: Arc<dyn TcpOutbound> = Arc::new(DirectOutbound::new(
            self.allow_private_targets,
            config.allowed_targets(),
        ));
        let stats = Arc::new(InboundStats::default());
        let settings = self.serve_settings.clone();
        let address = SocketAddr::new(config.listen, config.listen_port);
        let (listen, task) = match &inbound {
            Inbound::Stream(stream) => {
                let listener = TcpListener::bind(address).await?;
                let listen = listener.local_addr()?;
                let task = tokio::spawn({
                    let (stream, stats) = (stream.clone(), stats.clone());
                    async move {
                        let _ = serve(listener, stream, outbound, settings, stats).await;
                    }
                });
                (listen, task)
            }
            Inbound::Packet(packet) => {
                let socket = std::net::UdpSocket::bind(address)?;
                let listen = socket.local_addr()?;
                let served = packet
                    .clone()
                    .serve(socket, outbound, settings, stats.clone());
                let task = tokio::spawn(async move {
                    let _ = served.await;
                });
                (listen, task)
            }
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
                listen,
                inbound,
                stats,
                task,
            },
        );
        Ok(listen)
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
    }
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
