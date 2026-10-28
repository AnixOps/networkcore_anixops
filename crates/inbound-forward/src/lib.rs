//! Fixed-target port forward: every TCP connection and UDP datagram that
//! reaches the listen port is relayed to one configured `host:port`.
//!
//! There is no handshake and no user table: the inbound is a plain port
//! mapping, as a panel forwarding rule is. Which way the traffic leaves is
//! the node's business (the inbound's base outbound, such as direct or a
//! tunnel to another node); the bytes are counted per inbound by the serve
//! loop.
//!
//! UDP is relayed per client address: each client gets its own outbound
//! session, which ends after [`engine_inbound::udp::UDP_IDLE_TIMEOUT`]
//! without traffic. Replies go back to the client from the listen port.

mod factory;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use engine_inbound::server::InboundStats;
use engine_inbound::udp::{
    DatagramInbound, ReplySink, SessionRelay, UdpOutbound, MAX_DATAGRAM, MAX_SESSIONS,
};
use engine_inbound::{Accepted, Rejected, StreamInbound, UserStore};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr};
use tokio::net::UdpSocket;

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

pub struct ForwardInbound {
    target: TargetAddr,
    network: Network,
    users: Arc<UserStore>,
}

impl ForwardInbound {
    pub fn new(target: TargetAddr, network: Network) -> Self {
        Self {
            target,
            network,
            users: Arc::new(UserStore::new(Some(Box::new(|_| {
                Err("forward inbounds have no users")
            })))),
        }
    }

    pub fn target(&self) -> &TargetAddr {
        &self.target
    }

    pub fn network(&self) -> Network {
        self.network
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
        stream: BoxStream,
        _peer: SocketAddr,
    ) -> BoxFuture<'a, Result<Accepted, Rejected>> {
        Box::pin(async move {
            if !self.network.tcp {
                return Err(Rejected::close("forward does not relay tcp"));
            }
            Ok(Accepted {
                user: None,
                target: self.target.clone(),
                stream,
                udp: None,
                mux: false,
            })
        })
    }

    fn datagram(&self) -> Option<Arc<dyn DatagramInbound>> {
        self.network.udp.then(|| {
            Arc::new(ForwardDatagrams {
                target: self.target.clone(),
            }) as Arc<dyn DatagramInbound>
        })
    }
}

/// The UDP side: one relay session per client address.
struct ForwardDatagrams {
    target: TargetAddr,
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
                let Some(session) = sink.session(peer, &relay) else {
                    continue;
                };
                relay.send(session, None, &self.target, &buf[..n]).await;
            }
        })
    }
}

#[derive(Default)]
struct Peers {
    by_address: HashMap<SocketAddr, u64>,
    by_session: HashMap<u64, SocketAddr>,
    next: u64,
}

/// Sends replies back to each session's client address.
struct Replies {
    socket: Arc<UdpSocket>,
    peers: Mutex<Peers>,
}

impl Replies {
    /// The session id of `peer`, assigning one for a new client; `None`
    /// when [`MAX_SESSIONS`] clients are open.
    fn session(&self, peer: SocketAddr, relay: &SessionRelay) -> Option<u64> {
        let mut peers = self.lock();
        if let Some(&session) = peers.by_address.get(&peer) {
            return Some(session);
        }
        if peers.by_session.len() >= MAX_SESSIONS {
            // Forget clients whose sessions idled out.
            let Peers {
                by_address,
                by_session,
                ..
            } = &mut *peers;
            by_session.retain(|session, address| {
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
        let session = peers.next;
        peers.next += 1;
        peers.by_address.insert(peer, session);
        peers.by_session.insert(session, peer);
        Some(session)
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
            let Some(peer) = self.lock().by_session.get(&session).copied() else {
                return false;
            };
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
