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
//! UDP goes through [`TcpOutbound::open_udp`], one [`UdpFlow`] per
//! destination; protocols without UDP keep its default, which fails with
//! [`io::ErrorKind::Unsupported`].
//!
//! Errors are plain [`std::io::Error`] values. Implementations must keep
//! credentials (UUIDs, passwords, private keys) out of error messages.

pub mod registry;
pub mod sniff;

use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpStream, UdpSocket};

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

    /// An address target when `host` is an IP address, else a name.
    pub fn from_host(host: &str, port: u16) -> Self {
        match host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
        {
            Ok(ip) => TargetAddr::Ip(SocketAddr::new(ip, port)),
            Err(_) => TargetAddr::Domain(host.to_string(), port),
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

    /// Opens a datagram path to a proxy server, for protocols whose UDP
    /// goes to the server as datagrams (Shadowsocks, SOCKS5 UDP ASSOCIATE).
    /// The default is a system UDP socket connected to the server.
    fn open_datagram<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(socket_flow(host, port))
    }
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

/// Dials through another outbound: the `via` of a node (a proxy chain). TCP
/// connections to the server are the outbound's connections and datagrams
/// its UDP flows; host names are left to the outbound to resolve.
pub struct OutboundDialer(pub std::sync::Arc<dyn TcpOutbound>);

impl Dialer for OutboundDialer {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move { self.0.connect(&TargetAddr::from_host(host, port)).await })
    }

    fn open_datagram<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(async move { self.0.open_udp(&TargetAddr::from_host(host, port)).await })
    }
}

/// A system UDP socket connected to `host:port`, as a flow.
async fn socket_flow(host: &str, port: u16) -> io::Result<UdpFlow> {
    let addr = tokio::net::lookup_host((host, port))
        .await?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "proxy server not found"))?;
    let bind: SocketAddr = if addr.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(addr).await?;
    let socket = std::sync::Arc::new(socket);
    Ok(UdpFlow::new(
        Box::new(SocketSend(socket.clone())),
        Box::new(SocketRecv {
            socket,
            buf: vec![0u8; MAX_DATAGRAM],
        }),
    ))
}

struct SocketSend(std::sync::Arc<UdpSocket>);

impl DatagramSend for SocketSend {
    fn send<'a>(&'a mut self, payload: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move { self.0.send(payload).await.map(|_| ()) })
    }
}

struct SocketRecv {
    socket: std::sync::Arc<UdpSocket>,
    buf: Vec<u8>,
}

impl DatagramRecv for SocketRecv {
    fn recv(&mut self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        Box::pin(async move {
            let n = self.socket.recv(&mut self.buf).await?;
            Ok(self.buf[..n].to_vec())
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

    /// Opens a UDP flow to `target`. Protocols without UDP keep this default,
    /// which fails with [`io::ErrorKind::Unsupported`].
    fn open_udp<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
        let _ = target;
        Box::pin(async { Err(udp_unsupported()) })
    }
}

/// The error [`TcpOutbound::open_udp`] returns for protocols without UDP.
pub fn udp_unsupported() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "outbound does not relay udp")
}

/// Largest datagram a [`UdpFlow`] built from a stream reads at once.
pub const MAX_DATAGRAM: usize = 64 * 1024;

/// Sends the datagrams of one UDP flow.
pub trait DatagramSend: Send {
    /// Sends `payload` as one datagram to the flow's destination.
    fn send<'a>(&'a mut self, payload: &'a [u8]) -> BoxFuture<'a, io::Result<()>>;
}

/// Receives the datagrams of one UDP flow.
pub trait DatagramRecv: Send {
    /// The next datagram from the flow's destination. Fails once the flow
    /// has ended.
    fn recv(&mut self) -> BoxFuture<'_, io::Result<Vec<u8>>>;
}

/// UDP to one destination: replies are attributed to that destination
/// whatever source the proxy reports.
pub struct UdpFlow {
    pub send: Box<dyn DatagramSend>,
    pub recv: Box<dyn DatagramRecv>,
}

impl UdpFlow {
    pub fn new(send: Box<dyn DatagramSend>, recv: Box<dyn DatagramRecv>) -> Self {
        Self { send, recv }
    }

    /// A flow over a stream where each write carries one datagram and each
    /// read returns one, such as a VMess UDP session.
    pub fn message_stream(stream: BoxStream) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self::new(
            Box::new(MessageSend(writer)),
            Box::new(MessageRecv {
                reader,
                buf: vec![0u8; MAX_DATAGRAM],
            }),
        )
    }
}

struct MessageSend(WriteHalf<BoxStream>);

impl DatagramSend for MessageSend {
    fn send<'a>(&'a mut self, payload: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            self.0.write_all(payload).await?;
            self.0.flush().await
        })
    }
}

struct MessageRecv {
    reader: ReadHalf<BoxStream>,
    buf: Vec<u8>,
}

impl DatagramRecv for MessageRecv {
    fn recv(&mut self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        Box::pin(async move {
            let n = self.reader.read(&mut self.buf).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            Ok(self.buf[..n].to_vec())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_host_tells_addresses_from_names() {
        assert_eq!(
            TargetAddr::from_host("198.51.100.20", 8388),
            TargetAddr::Ip("198.51.100.20:8388".parse().unwrap())
        );
        assert_eq!(
            TargetAddr::from_host("[2001:db8::1]", 443),
            TargetAddr::Ip("[2001:db8::1]:443".parse().unwrap())
        );
        assert_eq!(
            TargetAddr::from_host("2001:db8::1", 443),
            TargetAddr::Ip("[2001:db8::1]:443".parse().unwrap())
        );
        assert_eq!(
            TargetAddr::from_host("land.example", 443),
            TargetAddr::Domain("land.example".to_string(), 443)
        );
    }
}
