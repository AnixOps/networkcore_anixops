//! Direct outbound with a private-target filter and an optional source
//! address (a network-model egress, see [`crate::network`]).

use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use engine_inbound::udp::{UdpOutbound, UdpSession};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

#[derive(Clone)]
pub struct DirectOutbound {
    allow_private: bool,
    /// `(host, port)` pairs allowed even when private.
    allowed: Vec<(String, u16)>,
    /// The address connections leave from; only targets of its family are
    /// reached. The agent's `ip rule from <source>` picks the line.
    source: Option<IpAddr>,
}

impl DirectOutbound {
    pub fn new(allow_private: bool, allowed: Vec<(String, u16)>) -> Self {
        Self {
            allow_private,
            allowed,
            source: None,
        }
    }

    /// Binds TCP connections (`bind` then `connect`) and UDP sessions
    /// (`bind(source:0)`) to `source`.
    pub fn with_source(mut self, source: Option<IpAddr>) -> Self {
        self.source = source.map(|source| source.to_canonical());
        self
    }

    /// Whether a target address can be reached from the source.
    fn reaches(&self, address: &SocketAddr) -> bool {
        match self.source {
            Some(source) => source.is_ipv4() == address.ip().to_canonical().is_ipv4(),
            None => true,
        }
    }

    fn permits(&self, target: &TargetAddr, ip: IpAddr) -> bool {
        self.allow_private
            || is_public(ip)
            || self
                .allowed
                .iter()
                .any(|(host, port)| *port == target.port() && *host == target.host())
    }
}

impl TcpOutbound for DirectOutbound {
    fn protocol(&self) -> &'static str {
        "direct"
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let addresses: Vec<SocketAddr> = match target {
                TargetAddr::Ip(address) => vec![*address],
                TargetAddr::Domain(host, port) => tokio::net::lookup_host((host.as_str(), *port))
                    .await?
                    .collect(),
            };
            let mut last_error = None;
            for address in addresses {
                if !self.permits(target, address.ip()) {
                    last_error = Some(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "private target refused",
                    ));
                    continue;
                }
                if !self.reaches(&address) {
                    last_error.get_or_insert_with(|| {
                        io::Error::new(
                            io::ErrorKind::AddrNotAvailable,
                            "target has no address of the egress family",
                        )
                    });
                    continue;
                }
                match self.connect_tcp(address).await {
                    Ok(stream) => {
                        let _ = stream.set_nodelay(true);
                        return Ok(Box::new(stream) as BoxStream);
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "target has no address")
            }))
        })
    }
}

impl DirectOutbound {
    async fn connect_tcp(&self, address: SocketAddr) -> io::Result<TcpStream> {
        let Some(source) = self.source else {
            return TcpStream::connect(address).await;
        };
        let address = SocketAddr::new(address.ip().to_canonical(), address.port());
        let socket = match source {
            IpAddr::V4(_) => TcpSocket::new_v4()?,
            IpAddr::V6(_) => TcpSocket::new_v6()?,
        };
        socket.bind(SocketAddr::new(source, 0))?;
        socket.connect(address).await
    }
}

impl UdpOutbound for DirectOutbound {
    fn bind(&self) -> BoxFuture<'_, io::Result<Arc<dyn UdpSession>>> {
        Box::pin(async move {
            // One dual-stack socket when the host has IPv6, else IPv4 only;
            // with a source, a socket of its family bound to it.
            let (socket, dual_stack) = match self.source {
                Some(source) => (UdpSocket::bind(SocketAddr::new(source, 0)).await?, false),
                None => match dual_stack_socket() {
                    Ok(socket) => (socket, true),
                    Err(_) => (UdpSocket::bind("0.0.0.0:0").await?, false),
                },
            };
            Ok(Arc::new(DirectUdp {
                policy: self.clone(),
                socket,
                dual_stack,
            }) as Arc<dyn UdpSession>)
        })
    }
}

/// An IPv6 socket that also carries IPv4 (as IPv4-mapped addresses);
/// `IPV6_V6ONLY` is cleared explicitly because its default differs by OS.
fn dual_stack_socket() -> io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_only_v6(false)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0).into())?;
    UdpSocket::from_std(socket.into())
}

struct DirectUdp {
    policy: DirectOutbound,
    socket: UdpSocket,
    dual_stack: bool,
}

impl DirectUdp {
    /// Whether the socket can send to `address`.
    fn reaches(&self, address: &SocketAddr) -> bool {
        match self.policy.source {
            Some(_) => self.policy.reaches(address),
            None => self.dual_stack || address.is_ipv4(),
        }
    }
}

impl UdpSession for DirectUdp {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        target: &'a TargetAddr,
    ) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let address = match target {
                TargetAddr::Ip(address) if self.policy.source.is_some() => {
                    let address = SocketAddr::new(address.ip().to_canonical(), address.port());
                    if !self.reaches(&address) {
                        return Err(io::Error::new(
                            io::ErrorKind::AddrNotAvailable,
                            "target is not of the egress family",
                        ));
                    }
                    address
                }
                TargetAddr::Ip(address) => *address,
                TargetAddr::Domain(host, port) => {
                    let mut addresses = tokio::net::lookup_host((host.as_str(), *port)).await?;
                    let mut chosen = None;
                    for address in addresses.by_ref() {
                        if self.reaches(&address) {
                            chosen = Some(address);
                            break;
                        }
                    }
                    chosen.ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotFound, "target has no usable address")
                    })?
                }
            };
            if !self.policy.permits(target, address.ip()) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private target refused",
                ));
            }
            let address = match (address, self.dual_stack) {
                (SocketAddr::V4(v4), true) => {
                    SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port())
                }
                (address, _) => address,
            };
            self.socket.send_to(payload, address).await.map(|_| ())
        })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, io::Result<(usize, SocketAddr)>> {
        Box::pin(async move {
            let (n, source) = self.socket.recv_from(buf).await?;
            Ok((
                n,
                SocketAddr::new(source.ip().to_canonical(), source.port()),
            ))
        })
    }
}

/// Whether `ip` is a globally routable unicast address.
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || a == 0
                || (a == 100 && (64..128).contains(&b)))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_addresses() {
        for private in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!is_public(private.parse().unwrap()), "{private}");
        }
        for public in ["1.1.1.1", "8.8.8.8", "2606:4700::1111", "100.128.0.1"] {
            assert!(is_public(public.parse().unwrap()), "{public}");
        }
    }

    #[tokio::test]
    async fn udp_relays_and_refuses_private_targets() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_address = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            while let Ok((n, from)) = echo.recv_from(&mut buf).await {
                let _ = echo.send_to(&buf[..n], from).await;
            }
        });
        let target = TargetAddr::Ip(echo_address);
        let strict = DirectOutbound::new(false, Vec::new()).bind().await.unwrap();
        let error = strict.send_to(b"x", &target).await.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

        let open = DirectOutbound::new(true, Vec::new()).bind().await.unwrap();
        open.send_to(b"ping", &target).await.unwrap();
        let mut buf = [0u8; 64];
        let (n, source) = open.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(source, echo_address);
    }

    #[tokio::test]
    async fn binds_the_source_address() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        // Every 127/8 address is local on Linux; elsewhere only 127.0.0.1.
        let source: IpAddr = if cfg!(target_os = "linux") {
            "127.0.0.2"
        } else {
            "127.0.0.1"
        }
        .parse()
        .unwrap();
        let bound = DirectOutbound::new(true, Vec::new()).with_source(Some(source));
        let _stream = bound.connect(&TargetAddr::Ip(address)).await.unwrap();
        let (_, peer) = listener.accept().await.unwrap();
        assert_eq!(peer.ip(), source);
        // A v4 source reaches no v6 target.
        let error = bound
            .connect(&TargetAddr::Ip("[::1]:9".parse().unwrap()))
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);

        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let session = bound.bind().await.unwrap();
        session
            .send_to(b"x", &TargetAddr::Ip(echo.local_addr().unwrap()))
            .await
            .unwrap();
        let mut buf = [0u8; 8];
        let (_, from) = echo.recv_from(&mut buf).await.unwrap();
        assert_eq!(from.ip(), source);
    }

    #[tokio::test]
    async fn refuses_private_targets_unless_allowed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let target = TargetAddr::Ip(address);
        let strict = DirectOutbound::new(false, Vec::new());
        let error = strict.connect(&target).await.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let excepted = DirectOutbound::new(false, vec![("127.0.0.1".into(), address.port())]);
        assert!(excepted.connect(&target).await.is_ok());
        assert!(DirectOutbound::new(true, Vec::new())
            .connect(&target)
            .await
            .is_ok());
    }
}
