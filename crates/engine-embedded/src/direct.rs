//! Direct outbound: connects to the target without a proxy protocol.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use engine_outbound::registry::{BuildError, OutboundFactory, Settings};
use engine_outbound::{
    BoxFuture, BoxStream, DatagramRecv, DatagramSend, Dialer, TargetAddr, TcpOutbound, UdpFlow,
    MAX_DATAGRAM,
};
use tokio::net::UdpSocket;

pub const PROTOCOL: &str = "direct";

pub struct DirectOutbound {
    dialer: Arc<dyn Dialer>,
}

impl DirectOutbound {
    pub fn new(dialer: Arc<dyn Dialer>) -> Self {
        Self { dialer }
    }
}

impl TcpOutbound for DirectOutbound {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let host = target.host();
            self.dialer.dial(&host, target.port()).await
        })
    }

    /// A connected UDP socket of its own; a domain is resolved by the system.
    fn open_udp<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(async move {
            let address = match target {
                TargetAddr::Ip(address) => *address,
                TargetAddr::Domain(domain, port) => {
                    tokio::net::lookup_host((domain.as_str(), *port))
                        .await?
                        .next()
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::NotFound, "udp target did not resolve")
                        })?
                }
            };
            let local: SocketAddr = if address.is_ipv4() {
                (Ipv4Addr::UNSPECIFIED, 0).into()
            } else {
                (Ipv6Addr::UNSPECIFIED, 0).into()
            };
            let socket = Arc::new(UdpSocket::bind(local).await?);
            socket.connect(address).await?;
            Ok(UdpFlow::new(
                Box::new(DirectSend(socket.clone())),
                Box::new(DirectRecv {
                    socket,
                    buf: vec![0u8; MAX_DATAGRAM],
                }),
            ))
        })
    }
}

struct DirectSend(Arc<UdpSocket>);

impl DatagramSend for DirectSend {
    fn send<'a>(&'a mut self, payload: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move { self.0.send(payload).await.map(|_| ()) })
    }
}

struct DirectRecv {
    socket: Arc<UdpSocket>,
    buf: Vec<u8>,
}

impl DatagramRecv for DirectRecv {
    fn recv(&mut self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        Box::pin(async move {
            let n = self.socket.recv(&mut self.buf).await?;
            Ok(self.buf[..n].to_vec())
        })
    }
}

/// Registry entry for `"type": "direct"`. It takes no settings.
pub struct DirectFactory;

impl OutboundFactory for DirectFactory {
    fn type_name(&self) -> &'static str {
        PROTOCOL
    }

    fn build(
        &self,
        _settings: &Settings,
        dialer: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn TcpOutbound>, BuildError> {
        Ok(Arc::new(DirectOutbound::new(dialer)))
    }
}
