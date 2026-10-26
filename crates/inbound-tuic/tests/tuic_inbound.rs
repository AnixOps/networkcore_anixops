//! The TUIC server inbound against the engine's TUIC client.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use engine_inbound::registry::PacketInboundFactory;
use engine_inbound::server::{InboundStats, ServeSettings};
use engine_inbound::{PacketInbound, User};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use inbound_tuic::TuicInboundFactory;
use outbound_tuic::{parse_uuid, TuicOutbound};
use rcgen::{CertificateParams, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use transport_quic::Congestion;
use transport_tls::TlsSettings;

const TIMEOUT: Duration = Duration::from_secs(10);
const ALICE: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const BOB: &str = "6e1bb6b4-2a43-4b5e-9a3a-1f0c3c2c7d10";
const CAROL: &str = "0a0b0c0d-0e0f-4011-8213-141516171819";

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

async fn start(congestion: &str) -> Server {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["tuic.test".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let settings = serde_json::json!({
        "users": [
            {"name": "alice", "uuid": ALICE, "password": "alice-secret"},
            {"name": "bob", "uuid": BOB, "password": "bob-secret"}
        ],
        "tls": {"certificate": cert.pem(), "key": key.serialize_pem()},
        "congestion_control": congestion
    });
    let inbound = TuicInboundFactory
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

fn client(server: SocketAddr, uuid: &str, password: &str, congestion: Congestion) -> TuicOutbound {
    let tls = TlsSettings {
        server_name: "tuic.test".into(),
        alpn: Vec::new(),
        insecure: true,
    };
    TuicOutbound::new(
        server.ip().to_string(),
        server.port(),
        parse_uuid(uuid).unwrap(),
        password,
        &tls,
        congestion,
    )
    .unwrap()
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
    let server = start("cubic").await;
    let echo_addr = echo_server().await;
    let client = client(server.addr, ALICE, "alice-secret", Congestion::Cubic);
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
async fn bbr_connections_work() {
    let server = start("bbr").await;
    let echo_addr = echo_server().await;
    let mut stream = client(server.addr, BOB, "bob-secret", Congestion::Bbr)
        .connect(&TargetAddr::Ip(echo_addr))
        .await
        .unwrap();
    echo(&mut stream, b"bbr").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_passwords_are_refused() {
    let server = start("cubic").await;
    let echo_addr = echo_server().await;
    // TUIC servers never answer the Authenticate command, so a wrong
    // password shows up as a closed connection: on the first read, or
    // already while opening the stream when the close arrives first.
    let connected = client(server.addr, ALICE, "guess", Congestion::Cubic)
        .connect(&TargetAddr::Ip(echo_addr))
        .await;
    if let Ok(mut stream) = connected {
        let _ = stream.write_all(b"hello").await;
        let mut buf = [0u8; 5];
        let read = tokio::time::timeout(TIMEOUT, stream.read_exact(&mut buf))
            .await
            .expect("refusal timed out");
        assert!(read.is_err());
    }
    assert!(server.stats.handshake_failed.load(Ordering::Relaxed) >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn users_added_and_removed_at_runtime() {
    let server = start("cubic").await;
    let echo_addr = echo_server().await;
    server
        .inbound
        .users()
        .add(User {
            name: "carol".into(),
            password: Some("carol-secret".into()),
            uuid: Some(CAROL.into()),
            flow: None,
        })
        .unwrap();
    let carol = client(server.addr, CAROL, "carol-secret", Congestion::Cubic);
    let mut stream = carol.connect(&TargetAddr::Ip(echo_addr)).await.unwrap();
    echo(&mut stream, b"carol").await;

    assert!(server.inbound.users().remove("carol"));
    let mut buf = [0u8; 8];
    let read = tokio::time::timeout(TIMEOUT, stream.read(&mut buf))
        .await
        .expect("revoked connection should close");
    assert!(matches!(read, Ok(0) | Err(_)));
    // A new connection with the removed user's credentials is closed.
    let mut again = carol.connect(&TargetAddr::Ip(echo_addr)).await.unwrap();
    let _ = again.write_all(b"carol").await;
    let read = tokio::time::timeout(TIMEOUT, again.read_exact(&mut buf[..5]))
        .await
        .expect("refusal timed out");
    assert!(read.is_err());
}
