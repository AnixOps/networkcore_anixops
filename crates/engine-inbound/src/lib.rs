//! Server-side inbound interfaces shared by the node kernel and its protocol
//! crates.
//!
//! A protocol crate (Shadowsocks-2022, VLESS, Trojan, ...) implements
//! [`StreamInbound`]: it takes an accepted client stream, authenticates the
//! user, reads the requested destination and hands back an [`Accepted`]
//! stream that carries the payload. [`server::serve`] owns the listener,
//! relays every accepted stream through a [`engine_outbound::TcpOutbound`]
//! and charges the bytes to the user.
//!
//! Each inbound owns a [`UserStore`]: users can be added and removed while
//! the inbound runs, and the store reports per-user traffic and online IPs.
//! That is the surface a node agent (anix-agent) drives.
//!
//! [`registry`] maps config `type` names to inbound factories, mirroring
//! `engine_outbound::registry`.
//!
//! Errors are plain [`std::io::Error`] values or fixed `&'static str`
//! reasons. Implementations must keep credentials out of both.

pub mod addr;
pub mod registry;
pub mod replay;
pub mod server;
pub mod stream;
pub mod udp;
pub mod users;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use tokio::io::AsyncReadExt;

use crate::stream::PrefixedStream;

pub use users::{OnlineUser, User, UserEntry, UserStore, UserTraffic};

/// A client that passed the protocol handshake.
pub struct Accepted {
    /// The authenticated user; `None` for single-key inbounds without a user
    /// table.
    pub user: Option<Arc<UserEntry>>,
    pub target: TargetAddr,
    /// Payload stream: reads return what the client sends to `target`,
    /// writes go back to the client.
    pub stream: BoxStream,
}

/// A client that failed the handshake.
pub struct Rejected {
    /// Fixed, credential-free reason for diagnostics.
    pub reason: &'static str,
    /// The client connection, when the inbound wants the serve loop to keep
    /// it open and discard input instead of closing it at once. Closing
    /// immediately after a bad handshake tells an active prober where the
    /// authentication boundary is.
    pub stream: Option<BoxStream>,
}

impl Rejected {
    pub fn close(reason: &'static str) -> Self {
        Self {
            reason,
            stream: None,
        }
    }

    pub fn hold(reason: &'static str, stream: BoxStream) -> Self {
        Self {
            reason,
            stream: Some(stream),
        }
    }
}

impl From<io::Error> for Rejected {
    fn from(_: io::Error) -> Self {
        Rejected::close("connection failed during the handshake")
    }
}

/// A stream-based server protocol.
pub trait StreamInbound: Send + Sync {
    /// Short protocol tag for diagnostics, e.g. `"shadowsocks-2022"`.
    fn protocol(&self) -> &'static str;

    /// The users this inbound accepts. Inbounds without per-user credentials
    /// return an empty store.
    fn users(&self) -> &Arc<UserStore>;

    fn accept<'a>(
        &'a self,
        stream: BoxStream,
        peer: SocketAddr,
    ) -> BoxFuture<'a, Result<Accepted, Rejected>>;

    /// Whether the serve loop hands whole connections to
    /// [`StreamInbound::serve_connection`] instead of calling
    /// [`StreamInbound::accept`] once and relaying one target. Protocols
    /// that carry several requests or UDP on one connection, or answer
    /// connect failures, return `true`.
    fn serves_connections(&self) -> bool {
        false
    }

    /// Runs one client connection to completion; only called when
    /// [`StreamInbound::serves_connections`] is `true`. The implementation
    /// applies [`server::ServeSettings::handshake_timeout`] itself and
    /// relays through the context, which charges users and counts.
    fn serve_connection<'a>(
        &'a self,
        stream: BoxStream,
        context: server::ConnectionContext<'a>,
    ) -> BoxFuture<'a, ()> {
        let _ = (stream, context);
        Box::pin(async {})
    }
}

/// A server protocol that owns a UDP socket, such as the QUIC-based
/// Hysteria2 and TUIC. Each proxied stream is relayed with
/// [`server::relay_accepted`].
pub trait PacketInbound: Send + Sync {
    fn protocol(&self) -> &'static str;

    fn users(&self) -> &Arc<UserStore>;

    /// Serves on `socket` until the socket fails or the future is dropped.
    fn serve(
        self: Arc<Self>,
        socket: std::net::UdpSocket,
        outbound: Arc<dyn TcpOutbound>,
        settings: server::ServeSettings,
        stats: Arc<server::InboundStats>,
    ) -> BoxFuture<'static, io::Result<()>>;
}

/// Largest first read a protocol inspects before deciding between its own
/// handshake and the fallback; one TLS record.
pub const FIRST_READ_BYTES: usize = 16 * 1024;

/// Reads whatever the client sends first, up to [`FIRST_READ_BYTES`]. An
/// empty result means the client closed the connection.
pub async fn read_first(stream: &mut BoxStream) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; FIRST_READ_BYTES];
    let n = stream.read(&mut buf).await?;
    buf.truncate(n);
    Ok(buf)
}

/// Answers a client that failed authentication: with a fallback (usually a
/// local web server) the connection is relayed there unchanged, starting
/// with the bytes already read, and charged to no user; without one it is
/// held open and drained.
pub fn fallback_or_hold(
    fallback: Option<&TargetAddr>,
    consumed: Vec<u8>,
    stream: BoxStream,
    reason: &'static str,
) -> Result<Accepted, Rejected> {
    match fallback {
        Some(target) => Ok(Accepted {
            user: None,
            target: target.clone(),
            stream: Box::new(PrefixedStream::new(stream).with_read_prefix(consumed)),
        }),
        None => Err(Rejected::hold(reason, stream)),
    }
}

/// `"fallback": {"server": "127.0.0.1", "server_port": 8080}` in inbound
/// settings.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FallbackSettings {
    pub server: String,
    pub server_port: u16,
}

impl FallbackSettings {
    pub fn target(&self) -> TargetAddr {
        match self.server.parse::<std::net::IpAddr>() {
            Ok(ip) => TargetAddr::Ip(SocketAddr::new(ip, self.server_port)),
            Err(_) => TargetAddr::Domain(self.server.clone(), self.server_port),
        }
    }
}
