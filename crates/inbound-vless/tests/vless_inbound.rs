//! The VLESS server inbound against the engine's VLESS client over TLS.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use engine_inbound::addr::{write_port_addr, VMESS};
use engine_inbound::registry::InboundFactory;
use engine_inbound::server::{serve_with_udp, InboundStats, ServeSettings};
use engine_inbound::udp::BoundUdpOutbound;
use engine_inbound::{StreamInbound, User};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpDialer, TcpOutbound};
use inbound_vless::VlessInboundFactory;
use outbound_vless::{parse_uuid, VlessTlsOutbound};
use rcgen::{CertificateParams, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use transport_tls::{TlsConnector, TlsSettings};

const TIMEOUT: Duration = Duration::from_secs(10);
const ALICE: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const BOB: &str = "6e1bb6b4-2a43-4b5e-9a3a-1f0c3c2c7d10";
const CAROL: &str = "0a0b0c0d-0e0f-4011-8213-141516171819";
const GUESS: &str = "ffffffff-ffff-4fff-bfff-ffffffffffff";

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

/// Stands in for the web server behind the fallback: answers every
/// connection with a fixed HTTP response.
async fn web_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await;
            });
        }
    });
    addr
}

struct Server {
    addr: SocketAddr,
    inbound: Arc<dyn StreamInbound>,
    stats: Arc<InboundStats>,
}

async fn start(fallback: Option<SocketAddr>) -> Server {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["vless.test".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let mut settings = serde_json::json!({
        "users": [
            {"name": "alice", "uuid": ALICE},
            {"name": "bob", "uuid": BOB, "flow": ""}
        ],
        "tls": {"certificate": cert.pem(), "key": key.serialize_pem()}
    });
    if let Some(fallback) = fallback {
        settings["fallback"] = serde_json::json!({
            "server": fallback.ip().to_string(),
            "server_port": fallback.port()
        });
    }
    let settings = settings.as_object().unwrap().clone();
    let inbound = VlessInboundFactory.build(&settings).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stats = Arc::new(InboundStats::default());
    let serve_settings = ServeSettings {
        reject_hold: Duration::from_millis(300),
        ..ServeSettings::default()
    };
    tokio::spawn(serve_with_udp(
        listener,
        inbound.clone(),
        Arc::new(Direct),
        Some(Arc::new(BoundUdpOutbound::new(
            "127.0.0.1:0".parse().unwrap(),
        ))),
        serve_settings,
        stats.clone(),
    ));
    Server {
        addr,
        inbound,
        stats,
    }
}

fn tls() -> TlsSettings {
    TlsSettings {
        server_name: "vless.test".into(),
        alpn: Vec::new(),
        insecure: true,
    }
}

fn client(server: SocketAddr, uuid: &str) -> VlessTlsOutbound {
    VlessTlsOutbound::new(
        server.ip().to_string(),
        server.port(),
        parse_uuid(uuid).unwrap(),
        Some(TlsConnector::new(&tls()).unwrap()),
        Arc::new(TcpDialer),
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relays_and_charges_the_user() {
    let server = start(None).await;
    let echo = echo_server().await;
    let mut stream = client(server.addr, ALICE)
        .connect(&TargetAddr::Ip(echo))
        .await
        .unwrap();
    let payload: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
    stream.write_all(&payload).await.unwrap();
    let mut received = vec![0u8; payload.len()];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut received))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(received, payload);

    // The relay charges a write just after handing it to the socket, so the
    // client can see the echo a moment before it is counted.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let traffic = server.inbound.users().traffic(true);
    assert_eq!(traffic.len(), 1);
    assert_eq!(traffic[0].name, "alice");
    assert_eq!(traffic[0].up, payload.len() as u64);
    assert_eq!(traffic[0].down, payload.len() as u64);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn domain_targets_work() {
    let server = start(None).await;
    let echo = echo_server().await;
    let mut stream = client(server.addr, BOB)
        .connect(&TargetAddr::Domain("localhost".into(), echo.port()))
        .await
        .unwrap();
    stream.write_all(b"domain").await.unwrap();
    let mut received = [0u8; 6];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut received))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(&received, b"domain");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_password_without_fallback_gets_nothing() {
    let server = start(None).await;
    let echo = echo_server().await;
    let mut stream = client(server.addr, GUESS)
        .connect(&TargetAddr::Ip(echo))
        .await
        .unwrap();
    stream.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    let read = tokio::time::timeout(TIMEOUT, stream.read_exact(&mut buf))
        .await
        .expect("held connection should close");
    assert!(read.is_err());
    assert_eq!(server.stats.handshake_failed.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_vless_clients_reach_the_fallback() {
    let web = web_server().await;
    let server = start(Some(web)).await;
    let connector = TlsConnector::new(&tls()).unwrap();
    let tcp = TcpStream::connect(server.addr).await.unwrap();
    let mut stream = connector.connect(Box::new(tcp)).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: vless.test\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(TIMEOUT, stream.read_to_end(&mut response))
        .await
        .expect("fallback response timed out")
        .ok();
    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    assert!(server.inbound.users().traffic(false).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removed_users_are_refused() {
    let server = start(None).await;
    let echo = echo_server().await;
    assert!(server.inbound.users().remove("alice"));
    server
        .inbound
        .users()
        .add(User::with_uuid("carol", CAROL))
        .unwrap();
    let mut stream = client(server.addr, CAROL)
        .connect(&TargetAddr::Ip(echo))
        .await
        .unwrap();
    stream.write_all(b"carol").await.unwrap();
    let mut buf = [0u8; 5];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut buf))
        .await
        .expect("echo timed out")
        .unwrap();

    let mut stream = client(server.addr, ALICE)
        .connect(&TargetAddr::Ip(echo))
        .await
        .unwrap();
    stream.write_all(b"alice").await.unwrap();
    let read = tokio::time::timeout(TIMEOUT, stream.read_exact(&mut buf))
        .await
        .expect("held connection should close");
    assert!(read.is_err());
}

async fn udp_echo_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_536];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], from).await;
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_command_relays_datagrams() {
    let server = start(None).await;
    let echo = udp_echo_server().await;
    let tcp = TcpStream::connect(server.addr).await.unwrap();
    let mut stream = TlsConnector::new(&tls())
        .unwrap()
        .connect(Box::new(tcp))
        .await
        .unwrap();
    let payloads = [b"query".to_vec(), vec![9u8; 1400]];
    let mut request = vec![0u8];
    request.extend_from_slice(&parse_uuid(ALICE).unwrap());
    request.extend_from_slice(&[0, 2]);
    write_port_addr(&mut request, echo, VMESS);
    for payload in &payloads {
        request.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        request.extend_from_slice(payload);
    }
    stream.write_all(&request).await.unwrap();
    stream.flush().await.unwrap();

    let mut header = [0u8; 2];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut header))
        .await
        .expect("vless response timed out")
        .unwrap();
    assert_eq!(header, [0, 0]);
    for payload in &payloads {
        let mut len = [0u8; 2];
        tokio::time::timeout(TIMEOUT, stream.read_exact(&mut len))
            .await
            .expect("udp reply timed out")
            .unwrap();
        assert_eq!(usize::from(u16::from_be_bytes(len)), payload.len());
        let mut body = vec![0u8; payload.len()];
        stream.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, payload);
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    let traffic = server.inbound.users().traffic(false);
    let alice = traffic.iter().find(|entry| entry.name == "alice").unwrap();
    let total = payloads.iter().map(Vec::len).sum::<usize>() as u64;
    assert_eq!((alice.up, alice.down), (total, total));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_udp_flow_round_trips() {
    let server = start(None).await;
    let echo = udp_echo_server().await;
    let mut flow = client(server.addr, ALICE)
        .open_udp(&TargetAddr::Ip(echo))
        .await
        .unwrap();
    for payload in [b"query".to_vec(), vec![9u8; 1400]] {
        flow.send.send(&payload).await.unwrap();
        let reply = tokio::time::timeout(TIMEOUT, flow.recv.recv())
            .await
            .expect("udp reply timed out")
            .unwrap();
        assert_eq!(reply, payload);
    }
}
