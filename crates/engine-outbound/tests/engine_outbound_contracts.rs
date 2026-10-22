use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use engine_outbound::{BoxFuture, BoxStream, Dialer, TargetAddr, TcpDialer, TcpOutbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[test]
fn target_addr_exposes_port_host_and_display() {
    let ip = TargetAddr::from(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443));
    assert_eq!(ip.port(), 443);
    assert_eq!(ip.host(), "127.0.0.1");
    assert_eq!(ip.to_string(), "127.0.0.1:443");

    let domain = TargetAddr::Domain("example.com".to_owned(), 8443);
    assert_eq!(domain.port(), 8443);
    assert_eq!(domain.host(), "example.com");
    assert_eq!(domain.to_string(), "example.com:8443");
}

/// An outbound that connects straight to the target with its injected dialer.
struct DirectOutbound {
    dialer: Arc<dyn Dialer>,
}

impl TcpOutbound for DirectOutbound {
    fn protocol(&self) -> &'static str {
        "direct"
    }

    fn connect<'a>(
        &'a self,
        target: &'a TargetAddr,
    ) -> BoxFuture<'a, std::io::Result<BoxStream>> {
        Box::pin(async move {
            let host = target.host();
            self.dialer.dial(&host, target.port()).await
        })
    }
}

#[tokio::test(flavor = "current_thread")]
async fn tcp_dialer_carries_bytes_through_a_trait_object_outbound() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4];
        socket.read_exact(&mut buf).await.unwrap();
        socket.write_all(&buf).await.unwrap();
    });

    let outbound: Box<dyn TcpOutbound> = Box::new(DirectOutbound {
        dialer: Arc::new(TcpDialer),
    });
    assert_eq!(outbound.protocol(), "direct");
    let mut stream = outbound.connect(&TargetAddr::from(addr)).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");
    server.await.unwrap();
}
