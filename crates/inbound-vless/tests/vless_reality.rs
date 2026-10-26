//! The VLESS server behind REALITY against the engine's VLESS + REALITY
//! client.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use engine_inbound::registry::InboundFactory;
use engine_inbound::server::{serve, InboundStats, ServeSettings};
use engine_inbound::StreamInbound;
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpDialer, TcpOutbound};
use inbound_vless::VlessInboundFactory;
use outbound_vless::{
    parse_short_id, parse_uuid, Flow, RealityConfig, VlessRealityConfig, VlessRealityOutbound,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use x25519_dalek::{PublicKey, StaticSecret};

const TIMEOUT: Duration = Duration::from_secs(10);
const ALICE: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const PRIVATE_KEY: [u8; 32] = [
    0x60, 0x2d, 0x11, 0x9a, 0x45, 0x0c, 0x7e, 0x33, 0x81, 0x9f, 0x24, 0xd6, 0x5b, 0x70, 0x02, 0xee,
    0x13, 0x48, 0xa7, 0x3c, 0x91, 0x5e, 0x06, 0xbb, 0x2f, 0xc4, 0x77, 0x18, 0xd0, 0x6a, 0x39, 0x55,
];
const SHORT_ID: &str = "0123456789abcdef";
const SERVER_NAME: &str = "www.example.com";

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

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, byte)| {
            acc | ((*byte as u32) << (16 - 8 * i))
        });
        for i in 0..=chunk.len() {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
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

/// Stands in for the real site: records the first bytes of each connection
/// and answers with a fixed HTTP response.
async fn handshake_site() -> (SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let record = record.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                record.lock().unwrap().push(buf[..n].to_vec());
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await;
            });
        }
    });
    (addr, seen)
}

struct Server {
    addr: SocketAddr,
    inbound: Arc<dyn StreamInbound>,
    site: Arc<Mutex<Vec<Vec<u8>>>>,
}

async fn start() -> Server {
    let (site_addr, site) = handshake_site().await;
    let settings = serde_json::json!({
        "users": [{"name": "alice", "uuid": ALICE}],
        "reality": {
            "private_key": base64(&PRIVATE_KEY),
            "short_ids": ["", SHORT_ID],
            "server_names": [SERVER_NAME],
            "handshake": {"server": site_addr.ip().to_string(), "server_port": site_addr.port()},
            "max_time_difference_secs": 90
        }
    });
    let inbound = VlessInboundFactory
        .build(settings.as_object().unwrap())
        .unwrap_or_else(|err| panic!("{err}"));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(
        listener,
        inbound.clone(),
        Arc::new(Direct),
        ServeSettings::default(),
        Arc::new(InboundStats::default()),
    ));
    Server {
        addr,
        inbound,
        site,
    }
}

fn client(server: SocketAddr, public_key: [u8; 32], short_id: &str) -> VlessRealityOutbound {
    VlessRealityOutbound::new(
        VlessRealityConfig {
            server: server.ip().to_string(),
            port: server.port(),
            uuid: parse_uuid(ALICE).unwrap(),
            flow: Flow::None,
            reality: RealityConfig::new(SERVER_NAME, public_key, parse_short_id(short_id).unwrap()),
        },
        Arc::new(TcpDialer),
    )
}

fn server_public_key() -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(PRIVATE_KEY)).to_bytes()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_clients_are_relayed() {
    let server = start().await;
    let echo_addr = echo_server().await;
    let outbound = client(server.addr, server_public_key(), SHORT_ID);
    let mut stream = tokio::time::timeout(TIMEOUT, outbound.connect(&TargetAddr::Ip(echo_addr)))
        .await
        .expect("connect timed out")
        .unwrap();
    let payload: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
    stream.write_all(&payload).await.unwrap();
    let mut received = vec![0u8; payload.len()];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut received))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(received, payload);

    let traffic = server.inbound.users().traffic(false);
    assert_eq!(traffic.len(), 1);
    assert_eq!(traffic[0].up, payload.len() as u64);
    assert!(server.site.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_short_id_is_accepted_when_listed() {
    let server = start().await;
    let echo_addr = echo_server().await;
    let mut stream = client(server.addr, server_public_key(), "")
        .connect(&TargetAddr::Ip(echo_addr))
        .await
        .unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut buf))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(&buf, b"ping");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unauthenticated_clients_reach_the_real_site() {
    let server = start().await;
    let echo_addr = echo_server().await;
    for (public_key, short_id) in [([9u8; 32], SHORT_ID), (server_public_key(), "ffff")] {
        let result = tokio::time::timeout(
            TIMEOUT,
            client(server.addr, public_key, short_id).connect(&TargetAddr::Ip(echo_addr)),
        )
        .await
        .expect("refusal timed out");
        assert!(result.is_err());
    }
    let site = server.site.lock().unwrap().clone();
    assert_eq!(site.len(), 2);
    assert!(site.iter().all(|first| first.first() == Some(&0x16)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_probes_reach_the_real_site() {
    let server = start().await;
    let mut probe = TcpStream::connect(server.addr).await.unwrap();
    probe
        .write_all(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(TIMEOUT, probe.read_to_end(&mut response))
        .await
        .expect("probe timed out")
        .unwrap();
    assert!(response.ends_with(b"ok"));
    assert!(server.site.lock().unwrap()[0].starts_with(b"GET /"));
}
