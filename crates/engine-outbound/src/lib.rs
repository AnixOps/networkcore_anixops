//! Outbound interfaces shared by `engine-embedded` and its protocol crates.
//!
//! A protocol crate (Shadowsocks-2022, VLESS + REALITY, ...) implements
//! [`TcpOutbound`]. The engine builds each outbound with an injected
//! [`Dialer`], so the Network Extension can replace [`TcpDialer`] with a
//! dialer bound to the physical interface or using its own resolver.
//!
//! [`registry`] maps config `type` names to per-protocol factories, so an
//! engine can add or drop protocols with cargo features.
//!
//! Errors are plain [`std::io::Error`] values. Implementations must keep
//! credentials (UUIDs, passwords, private keys) out of error messages.

pub mod registry;

use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// Boxed `Send` future used by the object-safe traits in this crate.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A bidirectional byte stream returned by dialers and outbounds.
pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> ProxyStream for T {}

/// Owned, type-erased [`ProxyStream`].
pub type BoxStream = Box<dyn ProxyStream>;

/// Destination requested by the routing layer.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl TargetAddr {
    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Ip(addr) => addr.port(),
            TargetAddr::Domain(_, port) => *port,
        }
    }

    /// Host part without the port, suitable for a [`Dialer`].
    pub fn host(&self) -> String {
        match self {
            TargetAddr::Ip(addr) => addr.ip().to_string(),
            TargetAddr::Domain(domain, _) => domain.clone(),
        }
    }
}

impl From<SocketAddr> for TargetAddr {
    fn from(addr: SocketAddr) -> Self {
        TargetAddr::Ip(addr)
    }
}

impl From<(IpAddr, u16)> for TargetAddr {
    fn from((ip, port): (IpAddr, u16)) -> Self {
        TargetAddr::Ip(SocketAddr::new(ip, port))
    }
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetAddr::Ip(addr) => write!(f, "{addr}"),
            TargetAddr::Domain(domain, port) => write!(f, "{domain}:{port}"),
        }
    }
}

/// Opens the underlying transport connection to a proxy server.
pub trait Dialer: Send + Sync {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, io::Result<BoxStream>>;
}

/// Default dialer: a plain tokio TCP connection with `TCP_NODELAY`.
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpDialer;

impl Dialer for TcpDialer {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let stream = TcpStream::connect((host, port)).await?;
            stream.set_nodelay(true)?;
            Ok(Box::new(stream) as BoxStream)
        })
    }
}

/// A TCP-capable outbound protocol.
///
/// Implementations receive their [`Dialer`] at construction time; `connect`
/// returns a stream that carries the payload for `target` once the protocol
/// handshake has been started.
pub trait TcpOutbound: Send + Sync {
    /// Short protocol tag for diagnostics, e.g. `"vless"` or `"shadowsocks"`.
    fn protocol(&self) -> &'static str;

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>>;
}
