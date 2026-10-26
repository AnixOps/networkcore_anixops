//! The Hysteria2 server inbound against the engine's Hysteria2 client.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use engine_inbound::registry::PacketInboundFactory;
use engine_inbound::server::{InboundStats, ServeSettings};
use engine_inbound::{PacketInbound, User};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use inbound_hysteria2::Hysteria2InboundFactory;
use outbound_hysteria2::Hysteria2Outbound;
use rcgen::{CertificateParams, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use transport_quic::salamander::Salamander;
use transport_tls::TlsSettings;

const TIMEOUT: Duration = Duration::from_secs(10);
const OBFS: &str = "cry me a river";

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

struct Server {
    addr: SocketAddr,
    inbound: Arc<dyn PacketInbound>,
    stats: Arc<InboundStats>,
}

async fn start(obfs: bool) -> Server {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["hy2.test".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let mut settings = serde_json::json!({
        "users": [
            {"name": "alice", "password": "alice-secret"},
            {"name": "bob", "password": "bob-secret"}
        ],
        "tls": {"certificate": cert.pem(), "key": key.serialize_pem()}
    });
    if obfs {
        settings["obfs"] = serde_json::json!({"type": "salamander", "password": OBFS});
    }
    let inbound = Hysteria2InboundFactory
        .build(settings.as_object().unwrap())
        .unwrap_or_else(|err| panic!("{err}"));
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let stats = Arc::new(InboundStats::default());
    tokio::spawn(inbound.clone().serve(
        socket,
        Arc::new(Direct),
        ServeSettings {
            handshake_timeout: Duration::from_secs(5),
            ..ServeSettings::default()
        },
        stats.clone(),
    ));
    Server {
        addr,
        inbound,
        stats,
    }
}

fn client(server: SocketAddr, password: &str, obfs: bool) -> Hysteria2Outbound {
    let tls = TlsSettings {
        server_name: "hy2.test".into(),
        alpn: Vec::new(),
        insecure: true,
    };
    let outbound =
        Hysteria2Outbound::new(server.ip().to_string(), server.port(), password, &tls).unwrap();
    if obfs {
        outbound
            .with_salamander(Salamander::new(OBFS).unwrap())
            .unwrap()
    } else {
        outbound
    }
}

async fn echo(stream: &mut BoxStream, payload: &[u8]) {
    stream.write_all(payload).await.unwrap();
    let mut received = vec![0u8; payload.len()];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut received))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(received, payload);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relays_streams_and_charges_the_user() {
    let server = start(false).await;
    let echo_addr = echo_server().await;
    let client = client(server.addr, "alice-secret", false);
    let payload: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();
    // Two streams on one authenticated connection.
    let mut first = client.connect(&TargetAddr::Ip(echo_addr)).await.unwrap();
    let mut second = client
        .connect(&TargetAddr::Domain("localhost".into(), echo_addr.port()))
        .await
        .unwrap();
    echo(&mut first, &payload).await;
    echo(&mut second, b"second").await;

    // The relay charges a write just after handing it to the socket, so the
    // client can see the echo a moment before it is counted.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let traffic = server.inbound.users().traffic(true);
    assert_eq!(traffic.len(), 1);
    assert_eq!(traffic[0].name, "alice");
    let expected = payload.len() as u64 + 6;
    assert_eq!((traffic[0].up, traffic[0].down), (expected, expected));
    assert_eq!(server.inbound.users().online().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn salamander_obfuscated_connections_work() {
    let server = start(true).await;
    let echo_addr = echo_server().await;
    let mut stream = client(server.addr, "bob-secret", true)
        .connect(&TargetAddr::Ip(echo_addr))
        .await
        .unwrap();
    echo(&mut stream, b"obfuscated").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_passwords_are_refused() {
    let server = start(false).await;
    let echo_addr = echo_server().await;
    let result = tokio::time::timeout(
        TIMEOUT,
        client(server.addr, "guess", false).connect(&TargetAddr::Ip(echo_addr)),
    )
    .await
    .expect("refusal timed out");
    let err = result.err().expect("wrong password must be refused");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(server.stats.handshake_failed.load(Ordering::Relaxed) >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn users_added_and_removed_at_runtime() {
    let server = start(false).await;
    let echo_addr = echo_server().await;
    server
        .inbound
        .users()
        .add(User::with_password("carol", "carol-secret"))
        .unwrap();
    let carol = client(server.addr, "carol-secret", false);
    let mut stream = carol.connect(&TargetAddr::Ip(echo_addr)).await.unwrap();
    echo(&mut stream, b"carol").await;

    assert!(server.inbound.users().remove("carol"));
    let mut buf = [0u8; 8];
    let read = tokio::time::timeout(TIMEOUT, stream.read(&mut buf))
        .await
        .expect("revoked connection should close");
    assert!(matches!(read, Ok(0) | Err(_)));
    let again = tokio::time::timeout(TIMEOUT, carol.connect(&TargetAddr::Ip(echo_addr)))
        .await
        .expect("reconnect timed out");
    assert!(again.is_err());
}
