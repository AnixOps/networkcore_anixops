//! Port forward: every TCP connection and UDP datagram that reaches the
//! listen port is relayed to a configured `host:port`, or to one of several
//! picked by a balancing strategy with health checks and a circuit breaker
//! ([`balance`]).
//!
//! There is no handshake and no user table: the inbound is a plain port
//! mapping, as a panel forwarding rule is. Which way the traffic leaves is
//! the node's business (the inbound's base outbound, such as direct or a
//! tunnel to another node, where the target is resolved and dialed); the
//! bytes are counted per inbound by the serve loop.
//!
//! Per rule: a bandwidth cap per direction shared by all connections and
//! UDP sessions ([`limit`]), a cap on concurrent TCP connections, and a
//! PROXY protocol header written to the target ahead of the client's bytes
//! ([`proxy`]).
//!
//! UDP is relayed per client address: each client gets its own outbound
//! session, which ends after [`engine_inbound::udp::UDP_IDLE_TIMEOUT`]
//! without traffic, and keeps the target it was first given. Replies go back
//! to the client from the listen port.

pub mod balance;
mod factory;
pub mod limit;
pub mod proxy;

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use engine_inbound::server::{ConnectionContext, InboundStats};
use engine_inbound::udp::{
    DatagramInbound, ReplySink, SessionRelay, UdpOutbound, MAX_DATAGRAM, MAX_SESSIONS,
};
use engine_inbound::{Accepted, Rejected, StreamInbound, UserStore};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;

use crate::balance::{Health, Strategy, Target, Targets};
use crate::limit::{Bucket, Limited};
use crate::proxy::ProxyProtocol;

pub use factory::{ForwardInboundFactory, TYPE_NAME};

pub const PROTOCOL: &str = "forward";

/// Which transports a forward relays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Network {
    pub tcp: bool,
    pub udp: bool,
}

impl Network {
    pub const BOTH: Network = Network {
        tcp: true,
        udp: true,
    };

    /// `"tcp"`, `"udp"` or `"tcp,udp"` (either order).
    pub fn parse(value: &str) -> Option<Network> {
        let mut network = Network {
            tcp: false,
            udp: false,
        };
        for part in value.split(',').map(str::trim) {
            match part {
                "tcp" if !network.tcp => network.tcp = true,
                "udp" if !network.udp => network.udp = true,
                _ => return None,
            }
        }
        Some(network)
    }
}

/// Per-rule limits (forward.v1 `Limits`); 0 is no limit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Limits {
    /// Bits per second, each direction, shared by the whole rule.
    pub bandwidth_bps: u64,
    /// Concurrent TCP connections.
    pub max_conns: u32,
}

pub struct ForwardInbound {
    targets: Arc<Targets>,
    network: Network,
    max_conns: usize,
    conns: Arc<AtomicUsize>,
    up: Option<Arc<Bucket>>,
    down: Option<Arc<Bucket>>,
    proxy_protocol: ProxyProtocol,
    users: Arc<UserStore>,
}

impl ForwardInbound {
    /// One target, no limits.
    pub fn new(target: TargetAddr, network: Network) -> Self {
        Self::with_targets(
            vec![Target {
                addr: target,
                weight: 1,
                priority: 0,
            }],
            Strategy::default(),
            Health::default(),
            network,
        )
    }

    /// `targets` must not be empty. Active health checks run only with TCP.
    pub fn with_targets(
        targets: Vec<Target>,
        strategy: Strategy,
        mut health: Health,
        network: Network,
    ) -> Self {
        health.active &= network.tcp;
        Self {
            targets: Arc::new(Targets::new(targets, strategy, health)),
            network,
            max_conns: 0,
            conns: Arc::default(),
            up: None,
            down: None,
            proxy_protocol: ProxyProtocol::Off,
            users: Arc::new(UserStore::new(Some(Box::new(|_| {
                Err("forward inbounds have no users")
            })))),
        }
    }

    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.max_conns = limits.max_conns as usize;
        self.up = Bucket::from_bps(limits.bandwidth_bps);
        self.down = Bucket::from_bps(limits.bandwidth_bps);
        self
    }

    pub fn with_proxy_protocol(mut self, proxy_protocol: ProxyProtocol) -> Self {
        self.proxy_protocol = proxy_protocol;
        self
    }

    /// The first target.
    pub fn target(&self) -> &TargetAddr {
        self.targets.first()
    }

    pub fn targets(&self) -> &Arc<Targets> {
        &self.targets
    }

    pub fn network(&self) -> Network {
        self.network
    }

    async fn serve(&self, stream: BoxStream, context: ConnectionContext<'_>) {
        if !self.network.tcp {
            context.handshake_failed();
            return;
        }
        let Some(_conn) = ConnGuard::enter(&self.conns, self.max_conns) else {
            context.stats.rejected.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let client = context.peer.ip().to_canonical();
        let mut tried = Vec::new();
        let (lease, mut remote) = loop {
            let Some(lease) = self.targets.pick(client, &tried) else {
                return;
            };
            match context.connect(lease.target()).await {
                Ok(remote) => {
                    lease.succeeded();
                    break (lease, remote);
                }
                Err(_) => {
                    lease.failed();
                    tried.push(lease.index());
                }
            }
        };
        if self.proxy_protocol != ProxyProtocol::Off {
            // The address the client reached; the unspecified address when
            // the transport does not say.
            let destination = context.local.unwrap_or_else(|| {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), lease.target().port())
            });
            let header = self.proxy_protocol.header(context.peer, destination);
            if remote.write_all(&header).await.is_err() {
                return;
            }
        }
        let mut client = Limited::new(stream, self.up.clone(), self.down.clone());
        let _ = context.relay(None, &mut client, &mut remote).await;
        drop(lease);
    }
}

/// One of a forward's `max_conns`; released when dropped.
struct ConnGuard(Arc<AtomicUsize>);

impl ConnGuard {
    fn enter(conns: &Arc<AtomicUsize>, max: usize) -> Option<ConnGuard> {
        let entered = conns.fetch_add(1, Ordering::AcqRel);
        let guard = ConnGuard(conns.clone());
        (max == 0 || entered < max).then_some(guard)
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl StreamInbound for ForwardInbound {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn users(&self) -> &Arc<UserStore> {
        &self.users
    }

    fn accept<'a>(
        &'a self,
        _stream: BoxStream,
        _peer: SocketAddr,
    ) -> BoxFuture<'a, Result<Accepted, Rejected>> {
        // The serve loop calls serve_connection instead.
        Box::pin(async { Err(Rejected::close("forward serves whole connections")) })
    }

    fn serves_connections(&self) -> bool {
        true
    }

    fn serve_connection<'a>(
        &'a self,
        stream: BoxStream,
        context: ConnectionContext<'a>,
    ) -> BoxFuture<'a, ()> {
        Box::pin(self.serve(stream, context))
    }

    fn datagram(&self) -> Option<Arc<dyn DatagramInbound>> {
        self.network.udp.then(|| {
            Arc::new(ForwardDatagrams {
                targets: self.targets.clone(),
                up: self.up.clone(),
                down: self.down.clone(),
            }) as Arc<dyn DatagramInbound>
        })
    }

    fn background(&self, outbound: Arc<dyn TcpOutbound>) -> Option<BoxFuture<'static, ()>> {
        self.targets
            .health()
            .active
            .then(|| Box::pin(self.targets.clone().check(outbound)) as BoxFuture<'static, ()>)
    }

    fn target_health(&self) -> Option<Vec<engine_inbound::health::TargetHealth>> {
        Some(self.targets.report())
    }
}

/// Waits out what `bucket` charges for `bytes`.
async fn pace(bucket: &Option<Arc<Bucket>>, bytes: usize) {
    if let Some(bucket) = bucket {
        let delay = bucket.take(bytes);
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }
}

/// The UDP side: one relay session per client address.
struct ForwardDatagrams {
    targets: Arc<Targets>,
    up: Option<Arc<Bucket>>,
    down: Option<Arc<Bucket>>,
}

impl DatagramInbound for ForwardDatagrams {
    fn serve(
        self: Arc<Self>,
        socket: std::net::UdpSocket,
        outbound: Arc<dyn UdpOutbound>,
        stats: Arc<InboundStats>,
    ) -> BoxFuture<'static, io::Result<()>> {
        Box::pin(async move {
            socket.set_nonblocking(true)?;
            let socket = Arc::new(UdpSocket::from_std(socket)?);
            let sink = Arc::new(Replies {
                socket: socket.clone(),
                peers: Mutex::default(),
                down: self.down.clone(),
            });
            let relay = SessionRelay::new(outbound, sink.clone(), stats);
            let mut buf = vec![0u8; MAX_DATAGRAM];
            loop {
                let (n, peer) = match socket.recv_from(&mut buf).await {
                    Ok(received) => received,
                    // A reply to an earlier client that is gone (Windows
                    // reports ICMP port unreachable here); keep serving.
                    Err(error) if error.kind() == io::ErrorKind::ConnectionReset => continue,
                    Err(error) => {
                        relay.close();
                        return Err(error);
                    }
                };
                let Some((session, target)) = sink.session(peer, &relay, &self.targets) else {
                    continue;
                };
                pace(&self.up, n).await;
                relay.send(session, None, &target, &buf[..n]).await;
            }
        })
    }
}

#[derive(Default)]
struct Peers {
    by_address: HashMap<SocketAddr, u64>,
    /// Each session's client and target.
    by_session: HashMap<u64, (SocketAddr, TargetAddr)>,
    next: u64,
}

/// Sends replies back to each session's client address.
struct Replies {
    socket: Arc<UdpSocket>,
    peers: Mutex<Peers>,
    down: Option<Arc<Bucket>>,
}

impl Replies {
    /// The session id and target of `peer`, assigning both for a new
    /// client; `None` when [`MAX_SESSIONS`] clients are open.
    fn session(
        &self,
        peer: SocketAddr,
        relay: &SessionRelay,
        targets: &Arc<Targets>,
    ) -> Option<(u64, TargetAddr)> {
        let mut peers = self.lock();
        if let Some(&session) = peers.by_address.get(&peer) {
            let target = peers.by_session[&session].1.clone();
            return Some((session, target));
        }
        if peers.by_session.len() >= MAX_SESSIONS {
            // Forget clients whose sessions idled out.
            let Peers {
                by_address,
                by_session,
                ..
            } = &mut *peers;
            by_session.retain(|session, (address, _)| {
                let open = relay.contains(*session);
                if !open {
                    by_address.remove(address);
                }
                open
            });
            if peers.by_session.len() >= MAX_SESSIONS {
                return None;
            }
        }
        let target = targets
            .pick(peer.ip().to_canonical(), &[])
            .expect("a forward has a target")
            .target()
            .clone();
        let session = peers.next;
        peers.next += 1;
        peers.by_address.insert(peer, session);
        peers.by_session.insert(session, (peer, target.clone()));
        Some((session, target))
    }

    fn lock(&self) -> MutexGuard<'_, Peers> {
        self.peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl ReplySink for Replies {
    fn reply<'a>(
        &'a self,
        session: u64,
        _source: SocketAddr,
        payload: &'a [u8],
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            let Some(peer) = self.lock().by_session.get(&session).map(|(peer, _)| *peer) else {
                return false;
            };
            pace(&self.down, payload.len()).await;
            // A failed send drops this reply only.
            let _ = self.socket.send_to(payload, peer).await;
            true
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_networks() {
        assert_eq!(Network::parse("tcp,udp"), Some(Network::BOTH));
        assert_eq!(Network::parse("udp, tcp"), Some(Network::BOTH));
        assert_eq!(
            Network::parse("tcp"),
            Some(Network {
                tcp: true,
                udp: false
            })
        );
        assert_eq!(
            Network::parse("udp"),
            Some(Network {
                tcp: false,
                udp: true
            })
        );
        assert_eq!(Network::parse(""), None);
        assert_eq!(Network::parse("tcp,tcp"), None);
        assert_eq!(Network::parse("quic"), None);
    }

    #[test]
    fn refuses_users() {
        let inbound =
            ForwardInbound::new(TargetAddr::Domain("example.com".into(), 443), Network::BOTH);
        let user = engine_inbound::User::with_password("a", "b");
        assert!(inbound.users().add_all(vec![user]).is_err());
    }
}
