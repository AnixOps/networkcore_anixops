//! Panabit iWAN server inbound (`"type": "iwan"`), written only from
//! `docs/protocols/iwan.md` §12.
//!
//! iWAN clients (iwand, OpenWrt routers, Panabit devices) log in with a user
//! name and password over UDP and then send IPv4 packets. Each login gets a
//! session and an address from the inbound's pool; the session's packets go
//! into one userspace TCP/IP stack per inbound that accepts any destination,
//! and every TCP connection and UDP flow it terminates is relayed through the
//! node's outbound and charged to the session's user, like the streams of
//! the proxy protocols. The node's router then finds the domain from the
//! TLS SNI / HTTP `Host` or from the DNS answers relayed for the client, so
//! the panel's domain egress routes apply to iWAN users too.
//!
//! The gateway (the first address of the pool) answers pings and relays
//! DNS on UDP 53 to `dns_upstream`; it is the DNS address sent in OPENACK.
//! Packets to other users' addresses are dropped unless
//! `allow_client_to_client` is set; packets whose source is not the
//! session's address are dropped as spoofed.
//!
//! The packet codec, password block and XOR mask come from `outbound-iwan`.
//! iWAN has no confidentiality or integrity (spec §9); XOR masking only hides
//! the payload from casual inspection.

mod factory;
mod ip;
mod pool;
mod server;

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use engine_inbound::registry::BuildError;
use engine_inbound::server::{InboundStats, ServeSettings};
use engine_inbound::udp::UdpOutbound;
use engine_inbound::users::{UserIndex, Validator};
use engine_inbound::{PacketInbound, User, UserStore};
use engine_outbound::{BoxFuture, TcpOutbound};
use outbound_iwan::crypto::PASSWORD_BLOCK;
use outbound_iwan::packet::MAX_USERNAME_LEN;

pub use factory::{IwanInboundFactory, TYPE_NAME};
pub use pool::Network;

pub const PROTOCOL: &str = "iwan";

/// Settings of one inbound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IwanInboundConfig {
    /// The node's MTU; sessions use the smaller of it and the client's.
    pub mtu: u16,
    pub pool: Network,
    /// Where the gateway's DNS queries go.
    pub dns_upstream: SocketAddr,
    /// Whether users may send packets to each other's addresses.
    pub allow_client_to_client: bool,
    /// Whether clients that ask for XOR masking get it.
    pub allow_encrypt: bool,
}

pub struct IwanInbound {
    config: IwanInboundConfig,
    users: Arc<UserStore>,
    /// Users by login name.
    logins: UserIndex<Vec<u8>>,
    /// Users by fixed address.
    fixed: UserIndex<Ipv4Addr>,
}

impl IwanInbound {
    pub fn new(config: IwanInboundConfig) -> Self {
        let pool = config.pool;
        let validator: Validator = Box::new(move |user: &User| validate(user, pool));
        let users = Arc::new(UserStore::with_unique_keys(Some(validator), unique_keys));
        Self {
            logins: UserIndex::new(users.clone(), |user: &User| {
                Some(login(user).as_bytes().to_vec())
            }),
            fixed: UserIndex::new(users.clone(), |user: &User| match user.address {
                Some(IpAddr::V4(address)) => Some(address),
                _ => None,
            }),
            users,
            config,
        }
    }

    pub fn config(&self) -> &IwanInboundConfig {
        &self.config
    }
}

/// The name a client logs in with.
fn login(user: &User) -> &str {
    user.username.as_deref().unwrap_or(&user.name)
}

/// Login names and fixed addresses belong to one user each (spec §12.4).
fn unique_keys(user: &User) -> Vec<String> {
    let mut keys = vec![format!("login:{}", login(user))];
    if let Some(address) = user.address {
        keys.push(format!("address:{address}"));
    }
    keys
}

fn validate(user: &User, pool: Network) -> Result<(), BuildError> {
    match user.password.as_deref() {
        Some(password) if !password.is_empty() && password.len() <= PASSWORD_BLOCK => {}
        _ => return Err("iwan user password must be 1 to 16 bytes"),
    }
    let login = login(user);
    if login.is_empty() || login.len() > MAX_USERNAME_LEN {
        return Err("iwan user name must be 1 to 253 bytes");
    }
    match user.address {
        None => Ok(()),
        Some(IpAddr::V4(address)) if pool.assignable(address) => Ok(()),
        Some(_) => Err("iwan user address must be a pool address other than the gateway"),
    }
}

impl PacketInbound for IwanInbound {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn users(&self) -> &Arc<UserStore> {
        &self.users
    }

    fn serve(
        self: Arc<Self>,
        socket: std::net::UdpSocket,
        outbound: Arc<dyn TcpOutbound>,
        udp: Option<Arc<dyn UdpOutbound>>,
        settings: ServeSettings,
        stats: Arc<InboundStats>,
    ) -> BoxFuture<'static, io::Result<()>> {
        Box::pin(server::serve(self, socket, outbound, udp, settings, stats))
    }
}
