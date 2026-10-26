//! The VMess server inbound against the engine's VMess client.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use engine_inbound::registry::InboundFactory;
use engine_inbound::server::{serve, InboundStats, ServeSettings};
use engine_inbound::{StreamInbound, User};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpDialer, TcpOutbound};
use inbound_vmess::VmessInboundFactory;
use outbound_vmess::{parse_uuid, Security, VmessOutbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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

async fn echo_server(banner: Option<&'static [u8]>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                if let Some(banner) = banner {
                    if stream.write_all(banner).await.is_err() {
                        return;
                    }
                }
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
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

async fn start() -> Server {
    let settings = serde_json::json!({
        "users": [
            {"name": "alice", "uuid": ALICE},
            {"name": "bob", "uuid": BOB}
        ]
    });
    let inbound = VmessInboundFactory
        .build(settings.as_object().unwrap())
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stats = Arc::new(InboundStats::default());
    let serve_settings = ServeSettings {
        reject_hold: Duration::from_millis(300),
        ..ServeSettings::default()
    };
    tokio::spawn(serve(
        listener,
        inbound.clone(),
        Arc::new(Direct),
        serve_settings,
        stats.clone(),
    ));
    Server {
        addr,
        inbound,
        stats,
    }
}

fn client(server: SocketAddr, uuid: &str, security: Security) -> VmessOutbound {
    VmessOutbound::new(
        server.ip().to_string(),
        server.port(),
        parse_uuid(uuid).unwrap(),
        security,
        None,
        Arc::new(TcpDialer),
    )
    .unwrap()
}

async fn echo(stream: &mut BoxStream, payload: &[u8]) -> std::io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let write = async {
        writer.write_all(payload).await?;
        writer.flush().await
    };
    let read = async {
        let mut received = vec![0u8; payload.len()];
        reader.read_exact(&mut received).await?;
        Ok::<_, std::io::Error>(received)
    };
    let (written, received) = tokio::time::timeout(TIMEOUT, async { tokio::join!(write, read) })
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "echo timed out"))?;
    written?;
    assert!(received? == payload, "echoed bytes differ");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn both_securities_round_trip_and_charge_the_user() {
    let server = start().await;
    let echo_addr = echo_server(None).await;
    let payload: Vec<u8> = (0..150_000).map(|i| (i % 251) as u8).collect();
    for security in [Security::Aes128Gcm, Security::ChaCha20Poly1305] {
        let mut stream = client(server.addr, ALICE, security)
            .connect(&TargetAddr::Ip(echo_addr))
            .await
            .unwrap();
        echo(&mut stream, &payload).await.unwrap();
        echo(&mut stream, b"again").await.unwrap();
    }
    let traffic = server.inbound.users().traffic(true);
    assert_eq!(traffic.len(), 1);
    assert_eq!(traffic[0].name, "alice");
    let expected = 2 * (payload.len() as u64 + 5);
    assert_eq!((traffic[0].up, traffic[0].down), (expected, expected));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_speaks_first_to_a_domain_target() {
    let server = start().await;
    let echo_addr = echo_server(Some(b"220 ready\r\n")).await;
    let mut stream = client(server.addr, BOB, Security::Aes128Gcm)
        .connect(&TargetAddr::Domain("localhost".into(), echo_addr.port()))
        .await
        .unwrap();
    let mut banner = [0u8; 11];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut banner))
        .await
        .expect("banner timed out")
        .unwrap();
    assert_eq!(&banner, b"220 ready\r\n");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_and_removed_users_get_nothing() {
    let server = start().await;
    let echo_addr = echo_server(None).await;
    let mut stream = client(server.addr, GUESS, Security::Aes128Gcm)
        .connect(&TargetAddr::Ip(echo_addr))
        .await
        .unwrap();
    assert!(echo(&mut stream, b"hello").await.is_err());
    assert_eq!(server.stats.handshake_failed.load(Ordering::Relaxed), 1);

    let users = server.inbound.users();
    users.add(User::with_uuid("carol", CAROL)).unwrap();
    assert!(users.remove("bob"));
    let mut stream = client(server.addr, CAROL, Security::ChaCha20Poly1305)
        .connect(&TargetAddr::Ip(echo_addr))
        .await
        .unwrap();
    echo(&mut stream, b"carol").await.unwrap();
    let mut stream = client(server.addr, BOB, Security::Aes128Gcm)
        .connect(&TargetAddr::Ip(echo_addr))
        .await
        .unwrap();
    assert!(echo(&mut stream, b"bob").await.is_err());
}
