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

pub mod registry;
pub mod server;
pub mod users;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use engine_outbound::{BoxFuture, BoxStream, TargetAddr};

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
}
