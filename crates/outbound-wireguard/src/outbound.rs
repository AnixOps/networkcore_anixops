//! `"type": "wireguard"` as a routable outbound: every TCP connection and
//! UDP flow runs over the node's private stack inside the tunnel.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use engine_outbound::registry::{parse_settings, BuildError, OutboundFactory, Settings};
use engine_outbound::{
    BoxFuture, BoxStream, DatagramRecv, DatagramSend, Dialer, TargetAddr, TcpOutbound, UdpFlow,
};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::config::{WireGuardConfig, WireGuardSettings};
use crate::node::{closed, Node, Pending, UdpHandle};
use crate::TYPE_NAME;

/// How long a TCP connection may take to establish inside the tunnel,
/// handshake included.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct WireGuardFactory;

impl OutboundFactory for WireGuardFactory {
    fn type_name(&self) -> &'static str {
        TYPE_NAME
    }

    /// The tunnel runs over its own UDP socket, which a `via` cannot carry.
    fn supports_via(&self) -> bool {
        false
    }

    /// The tunnel runs over its own UDP socket, so the dialer is unused.
    fn build(
        &self,
        settings: &Settings,
        _dialer: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn TcpOutbound>, BuildError> {
        let config: WireGuardConfig =
            parse_settings(settings, "wireguard settings are missing or invalid")?;
        Ok(Arc::new(WireGuardOutbound::new(config.validate()?)))
    }
}

/// One WireGuard node. Clones share the session.
#[derive(Clone)]
pub struct WireGuardOutbound {
    node: Arc<Node>,
}

impl WireGuardOutbound {
    pub fn new(settings: WireGuardSettings) -> Self {
        Self {
            node: Node::new(settings),
        }
    }

    /// Accepts one TCP connection to `port` of the node's own address. A
    /// node only dials out in normal use; this serves tests that pass traffic
    /// between two nodes of one peer.
    pub async fn accept_tcp(&self, port: u16) -> io::Result<BoxStream> {
        let _pending = Pending::new(&self.node);
        let handle = self.node.listen_tcp(port)?;
        let stream = WireGuardTcpStream {
            node: self.node.clone(),
            handle,
        };
        self.node.wake();
        stream.wait_established(true).await?;
        Ok(Box::new(stream))
    }

    /// Like [`TcpOutbound::open_udp`] with a fixed local port; for tests.
    pub async fn open_udp_on(&self, port: u16, target: &TargetAddr) -> io::Result<UdpFlow> {
        self.udp_flow(Some(port), target).await
    }

    /// The address a target goes to: names resolve through the tunnel, and
    /// the result must be inside AllowedIPs and of a family the interface
    /// has an address of.
    async fn remote(&self, target: &TargetAddr) -> io::Result<SocketAddr> {
        let (address, port) = match target {
            TargetAddr::Ip(address) => (address.ip(), address.port()),
            TargetAddr::Domain(host, port) => {
                match host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<IpAddr>()
                {
                    Ok(address) => (address, *port),
                    Err(_) => (self.node.resolve(host).await?, *port),
                }
            }
        };
        let address = match address {
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(v6)),
            v4 => v4,
        };
        if !self.node.has_family(address) {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "wireguard has no local address of this family",
            ));
        }
        if !self.node.settings().allowed_ips.contains(address) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "destination is outside the wireguard peer's allowed_ips",
            ));
        }
        Ok(SocketAddr::new(address, port))
    }

    async fn tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        let _pending = Pending::new(&self.node);
        let remote = self.remote(target).await?;
        let handle = self.node.open_tcp(remote)?;
        let stream = WireGuardTcpStream {
            node: self.node.clone(),
            handle,
        };
        self.node.wake();
        match tokio::time::timeout(CONNECT_TIMEOUT, stream.wait_established(false)).await {
            Ok(Ok(())) => Ok(Box::new(stream)),
            Ok(Err(err)) => Err(err),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "wireguard connection timed out",
            )),
        }
    }

    async fn udp_flow(&self, port: Option<u16>, target: &TargetAddr) -> io::Result<UdpFlow> {
        let _pending = Pending::new(&self.node);
        let remote = self.remote(target).await?;
        let socket = Arc::new(UdpHandle::open(&self.node, port)?);
        self.node.wake();
        Ok(UdpFlow::new(
            Box::new(WireGuardUdpSend {
                socket: socket.clone(),
                remote,
            }),
            Box::new(WireGuardUdpRecv { socket }),
        ))
    }
}

impl TcpOutbound for WireGuardOutbound {
    fn protocol(&self) -> &'static str {
        TYPE_NAME
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(self.tcp(target))
    }

    fn open_udp<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(self.udp_flow(None, target))
    }

    /// When the last handshake finished and whether the session runs.
    /// Never addresses or keys.
    fn health(&self) -> Option<serde_json::Value> {
        let (since, running) = self.node.health();
        let mut health = serde_json::Map::new();
        health.insert("running".into(), running.into());
        if let Some(since) = since {
            health.insert("last_handshake_secs".into(), since.as_secs().into());
        }
        if let Some(failure) = self.node.failure() {
            health.insert("last_error".into(), failure.into());
        }
        Some(serde_json::Value::Object(health))
    }
}

/// A TCP connection of the private stack.
struct WireGuardTcpStream {
    node: Arc<Node>,
    handle: SocketHandle,
}

impl WireGuardTcpStream {
    /// Waits for the handshake; `listening` sockets may also sit in LISTEN.
    async fn wait_established(&self, listening: bool) -> io::Result<()> {
        std::future::poll_fn(|cx| {
            self.node
                .with_socket::<tcp::Socket, _>(self.handle, |socket| match socket.state() {
                    tcp::State::Established | tcp::State::CloseWait => Poll::Ready(Ok(())),
                    tcp::State::SynSent | tcp::State::SynReceived => {
                        socket.register_send_waker(cx.waker());
                        Poll::Pending
                    }
                    tcp::State::Listen if listening => {
                        socket.register_send_waker(cx.waker());
                        Poll::Pending
                    }
                    _ => Poll::Ready(Err(())),
                })
        })
        .await
        .map_err(|()| {
            let reason = self
                .node
                .failure()
                .unwrap_or("wireguard connection was refused");
            io::Error::new(io::ErrorKind::ConnectionRefused, reason)
        })
    }
}

impl AsyncRead for WireGuardTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let read = self
            .node
            .with_socket::<tcp::Socket, _>(self.handle, |socket| {
                if socket.can_recv() {
                    return match socket.recv_slice(buf.initialize_unfilled()) {
                        Ok(read) => Poll::Ready(read),
                        Err(_) => Poll::Ready(0),
                    };
                }
                if !socket.may_recv() {
                    // End of stream, or the connection was reset.
                    return Poll::Ready(0);
                }
                socket.register_recv_waker(cx.waker());
                Poll::Pending
            });
        match read {
            Poll::Ready(read) => {
                buf.advance(read);
                if read > 0 {
                    // The window opened; let the stack tell the peer.
                    self.node.wake();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WireGuardTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let written = self
            .node
            .with_socket::<tcp::Socket, _>(self.handle, |socket| {
                if !socket.may_send() {
                    return Poll::Ready(Err(closed()));
                }
                if socket.can_send() {
                    return Poll::Ready(socket.send_slice(data).map_err(|_| closed()));
                }
                socket.register_send_waker(cx.waker());
                Poll::Pending
            });
        if matches!(written, Poll::Ready(Ok(_))) {
            self.node.wake();
        }
        written
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.node
            .with_socket::<tcp::Socket, _>(self.handle, |socket| socket.close());
        self.node.wake();
        Poll::Ready(Ok(()))
    }
}

impl Drop for WireGuardTcpStream {
    fn drop(&mut self) {
        self.node.release_tcp(self.handle);
    }
}

struct WireGuardUdpSend {
    socket: Arc<UdpHandle>,
    remote: SocketAddr,
}

impl DatagramSend for WireGuardUdpSend {
    fn send<'a>(&'a mut self, payload: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(self.socket.send_to(payload, self.remote))
    }
}

/// Replies are attributed to the flow's destination whatever their source.
struct WireGuardUdpRecv {
    socket: Arc<UdpHandle>,
}

impl DatagramRecv for WireGuardUdpRecv {
    fn recv(&mut self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        Box::pin(self.socket.recv())
    }
}
