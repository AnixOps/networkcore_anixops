//! The Trojan server inbound behind TLS + WebSocket and TLS + gRPC against
//! the engine's Trojan client with the same transport.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use engine_inbound::registry::InboundFactory;
use engine_inbound::server::{serve, InboundStats, ServeSettings};
use engine_inbound::StreamInbound;
use engine_outbound::registry::OutboundFactory;
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpDialer, TcpOutbound};
use inbound_trojan::TrojanInboundFactory;
use outbound_trojan::TrojanFactory;
use rcgen::{CertificateParams, KeyPair};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TIMEOUT: Duration = Duration::from_secs(10);

struct Direct;

impl TcpOutbound for Direct {
    fn protocol(&self) -> &'static str {
        "direct"
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, std::io::Result<BoxStream>> {
        Box::pin(async move {
            let stream = TcpStream::connect((target.host(), target.port())).await?;
            Ok(Box::new(stream) as BoxStream)
        })
    }
}

async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    addr
}

async fn start(transport: Value) -> (SocketAddr, Arc<dyn StreamInbound>) {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["trojan.test".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let settings = json!({
        "users": [{"name": "alice", "password": "alice-secret"}],
        "tls": {"certificate": cert.pem(), "key": key.serialize_pem()},
        "transport": transport,
    });
    let inbound = TrojanInboundFactory
        .build(settings.as_object().unwrap())
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(
        listener,
        inbound.clone(),
        Arc::new(Direct),
        ServeSettings::default(),
        Arc::new(InboundStats::default()),
    ));
    (addr, inbound)
}

fn client(server: SocketAddr, password: &str, transport: Value) -> Arc<dyn TcpOutbound> {
    let settings = json!({
        "server": server.ip().to_string(),
        "port": server.port(),
        "password": password,
        "server_name": "trojan.test",
        "insecure": true,
        "transport": transport,
    });
    TrojanFactory
        .build(settings.as_object().unwrap(), Arc::new(TcpDialer))
        .unwrap()
}

async fn echo_through(outbound: &dyn TcpOutbound, target: SocketAddr, payload: &[u8]) {
    let mut stream = tokio::time::timeout(TIMEOUT, outbound.connect(&TargetAddr::Ip(target)))
        .await
        .expect("connect timed out")
        .unwrap();
    stream.write_all(payload).await.unwrap();
    let mut received = vec![0u8; payload.len()];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut received))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(received, payload);
}

async fn relays_over(transport: Value) {
    let (addr, inbound) = start(transport.clone()).await;
    let echo = echo_server().await;
    let outbound = client(addr, "alice-secret", transport.clone());
    let payload: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
    // Two connections at once, and a second round on fresh ones.
    for _ in 0..2 {
        tokio::join!(
            echo_through(outbound.as_ref(), echo, &payload),
            echo_through(outbound.as_ref(), echo, b"second"),
        );
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let traffic = inbound.users().traffic(false);
    assert_eq!(traffic.len(), 1);
    assert_eq!(traffic[0].name, "alice");
    let expected = 2 * (payload.len() as u64 + 6);
    assert_eq!(traffic[0].up, expected);
    assert_eq!(traffic[0].down, expected);

    // A wrong password gets no echo.
    let stranger = client(addr, "guess", transport);
    if let Ok(Ok(mut stream)) =
        tokio::time::timeout(TIMEOUT, stranger.connect(&TargetAddr::Ip(echo))).await
    {
        let _ = stream.write_all(b"nope").await;
        let mut buf = [0u8; 4];
        let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
        assert!(!matches!(read, Ok(Ok(n)) if n > 0), "wrong password got data");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trojan_over_websocket() {
    relays_over(json!({"type": "ws", "path": "/trojan", "host": "trojan.test"})).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trojan_over_grpc() {
    relays_over(json!({"type": "grpc", "service_name": "TrojanTun"})).await;
}

#[test]
fn transports_are_validated() {
    for transport in [
        json!({"type": "grpc", "service_name": ""}),
        json!({"type": "ws", "path": "relative"}),
        json!({"type": "quic"}),
    ] {
        let settings = json!({"users": [], "transport": transport});
        assert!(
            TrojanInboundFactory
                .build(settings.as_object().unwrap())
                .is_err(),
            "{transport}"
        );
    }
}
