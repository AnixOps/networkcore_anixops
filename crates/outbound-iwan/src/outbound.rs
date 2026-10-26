//! `"type": "iwan"` as a routable outbound (spec §11): every TCP connection
//! and UDP flow runs over the node's private stack inside the tunnel.

use std::io;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
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

use crate::config::{IwanConfig, IwanSettings};
use crate::node::{Node, UdpHandle};
use crate::TYPE_NAME;

/// How long a TCP connection may take to establish inside the tunnel.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct IwanFactory;

impl OutboundFactory for IwanFactory {
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
        let config: IwanConfig = parse_settings(settings, "iwan settings are missing or invalid")?;
        Ok(Arc::new(IwanOutbound::new(config.validate()?)))
    }
}

/// One iWAN node. Clones share the session.
#[derive(Clone)]
pub struct IwanOutbound {
    node: Arc<Node>,
}

impl IwanOutbound {
    pub fn new(settings: IwanSettings) -> Self {
        Self {
            node: Node::new(settings),
        }
    }

    /// The last ECHO round trip, once one has finished (spec §6.4).
    pub fn rtt(&self) -> Option<Duration> {
        match self.node.rtt_us() {
            0 => None,
            micros => Some(Duration::from_micros(u64::from(micros))),
        }
    }

    /// Accepts one TCP connection to `port` of the node's tunnel address.
    /// A node only dials out in normal use; this serves tests that pass
    /// traffic between two nodes.
    pub async fn accept_tcp(&self, port: u16) -> io::Result<BoxStream> {
        let generation = self.node.session().await?;
        let handle = self.node.listen_tcp(generation, port)?;
        let stream = IwanTcpStream {
            node: self.node.clone(),
            handle,
            generation,
        };
        self.node.wake();
        stream.wait_established(true).await?;
        Ok(Box::new(stream))
    }

    /// Like [`TcpOutbound::open_udp`] with a fixed local port; for tests.
    pub async fn open_udp_on(&self, port: u16, target: &TargetAddr) -> io::Result<UdpFlow> {
        self.udp_flow(Some(port), target).await
    }

    async fn remote(&self, generation: u64, target: &TargetAddr) -> io::Result<SocketAddrV4> {
        match target {
            TargetAddr::Ip(SocketAddr::V4(address)) => Ok(*address),
            TargetAddr::Ip(SocketAddr::V6(_)) => Err(ipv6_unsupported()),
            TargetAddr::Domain(host, port) => match host.parse::<IpAddr>() {
                Ok(IpAddr::V6(_)) => Err(ipv6_unsupported()),
                _ => {
                    let address = self.node.resolve(generation, host).await?;
                    Ok(SocketAddrV4::new(address, *port))
                }
            },
        }
    }

    async fn tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        let generation = self.node.session().await?;
        let remote = self.remote(generation, target).await?;
        let handle = self.node.open_tcp(generation, remote)?;
        let stream = IwanTcpStream {
            node: self.node.clone(),
            handle,
            generation,
        };
        self.node.wake();
        match tokio::time::timeout(CONNECT_TIMEOUT, stream.wait_established(false)).await {
            Ok(Ok(())) => Ok(Box::new(stream)),
            Ok(Err(err)) => Err(err),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "iwan connection timed out",
            )),
        }
    }

    async fn udp_flow(&self, port: Option<u16>, target: &TargetAddr) -> io::Result<UdpFlow> {
        let generation = self.node.session().await?;
        let remote = self.remote(generation, target).await?;
        let socket = Arc::new(UdpHandle::open(&self.node, generation, port)?);
        Ok(UdpFlow::new(
            Box::new(IwanUdpSend {
                socket: socket.clone(),
                remote,
            }),
            Box::new(IwanUdpRecv { socket }),
        ))
    }
}

impl TcpOutbound for IwanOutbound {
    fn protocol(&self) -> &'static str {
        TYPE_NAME
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(self.tcp(target))
    }

    fn open_udp<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(self.udp_flow(None, target))
    }
}

fn ipv6_unsupported() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "iwan carries IPv4 only")
}

fn session_gone() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, "iwan session was replaced")
}

/// A TCP connection of the private stack.
struct IwanTcpStream {
    node: Arc<Node>,
    handle: SocketHandle,
    generation: u64,
}

impl IwanTcpStream {
    /// Waits for the handshake; `listening` sockets may also sit in LISTEN.
    async fn wait_established(&self, listening: bool) -> io::Result<()> {
        std::future::poll_fn(|cx| {
            self.with(|socket| match socket.state() {
                tcp::State::Established | tcp::State::CloseWait => Poll::Ready(Ok(())),
                tcp::State::SynSent | tcp::State::SynReceived => {
                    socket.register_send_waker(cx.waker());
                    Poll::Pending
                }
                tcp::State::Listen if listening => {
                    socket.register_send_waker(cx.waker());
                    Poll::Pending
                }
                _ => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "iwan connection was refused",
                ))),
            })
        })
        .await
    }

    fn with<R>(
        &self,
        f: impl FnOnce(&mut tcp::Socket<'static>) -> Poll<io::Result<R>>,
    ) -> Poll<io::Result<R>> {
        self.node
            .with_socket::<tcp::Socket, _>(self.handle, self.generation, f)
            .unwrap_or_else(|| Poll::Ready(Err(session_gone())))
    }
}

impl AsyncRead for IwanTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let read = self.with(|socket| {
            if socket.can_recv() {
                return match socket.recv_slice(buf.initialize_unfilled()) {
                    Ok(read) => Poll::Ready(Ok(read)),
                    Err(_) => Poll::Ready(Ok(0)),
                };
            }
            if !socket.may_recv() {
                // End of stream, or the connection was reset.
                return Poll::Ready(Ok(0));
            }
            socket.register_recv_waker(cx.waker());
            Poll::Pending
        });
        match read {
            Poll::Ready(Ok(read)) => {
                buf.advance(read);
                if read > 0 {
                    // The window opened; let the stack tell the peer.
                    self.node.wake();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for IwanTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let written = self.with(|socket| {
            if !socket.may_send() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "iwan connection is closed",
                )));
            }
            if socket.can_send() {
                return Poll::Ready(socket.send_slice(data).map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "iwan connection is closed")
                }));
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
        let closed = self.with(|socket| {
            socket.close();
            Poll::Ready(Ok(()))
        });
        self.node.wake();
        closed
    }
}

impl Drop for IwanTcpStream {
    fn drop(&mut self) {
        self.node.release_tcp(self.handle, self.generation);
    }
}

struct IwanUdpSend {
    socket: Arc<UdpHandle>,
    remote: SocketAddrV4,
}

impl DatagramSend for IwanUdpSend {
    fn send<'a>(&'a mut self, payload: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(self.socket.send_to(payload, self.remote))
    }
}

/// Replies are attributed to the flow's destination whatever their source.
struct IwanUdpRecv {
    socket: Arc<UdpHandle>,
}

impl DatagramRecv for IwanUdpRecv {
    fn recv(&mut self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        Box::pin(self.socket.recv())
    }
}
