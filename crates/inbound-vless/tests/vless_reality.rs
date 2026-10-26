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
use ring::signature::{Ed25519KeyPair, KeyPair};
use tls_mimic::server::{
    accept, ed25519_certificate_template, parse_client_hello, read_client_hello, ServerIdentity,
};
use tls_mimic::{ClientConfig, Fingerprint, HandshakeHooks};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use x25519_dalek::{PublicKey, StaticSecret};

const TIMEOUT: Duration = Duration::from_secs(10);
const ALICE: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
/// A user with the Vision flow.
const BOB: &str = "b831381d-6324-4d53-ad4f-8cda48b30812";
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
        "users": [
            {"name": "alice", "uuid": ALICE},
            {"name": "bob", "uuid": BOB, "flow": "xtls-rprx-vision"}
        ],
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
    user_client(server, public_key, short_id, ALICE, Flow::None)
}

fn user_client(
    server: SocketAddr,
    public_key: [u8; 32],
    short_id: &str,
    uuid: &str,
    flow: Flow,
) -> VlessRealityOutbound {
    VlessRealityOutbound::new(
        VlessRealityConfig {
            server: server.ip().to_string(),
            port: server.port(),
            uuid: parse_uuid(uuid).unwrap(),
            flow,
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

    // The relay charges a write just after handing it to the socket, so the
    // client can see the echo a moment before it is counted.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let traffic = server.inbound.users().traffic(false);
    let alice = traffic.iter().find(|entry| entry.name == "alice").unwrap();
    assert_eq!(alice.up, payload.len() as u64);
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

/// An inner TLS 1.3 echo server, the kind of target Vision copies directly.
async fn tls_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let rng = ring::rand::SystemRandom::new();
                let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
                let signer = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
                let public: [u8; 32] = signer.public_key().as_ref().try_into().unwrap();
                let chain = [ed25519_certificate_template(&public)];
                let mut consumed = Vec::new();
                let Ok(message) = read_client_hello(&mut stream, &mut consumed).await else {
                    return;
                };
                let Ok(hello) = parse_client_hello(&message) else {
                    return;
                };
                let identity = ServerIdentity {
                    certificate_chain: &chain,
                    signer: &signer,
                    alpn: &[b"http/1.1".to_vec()],
                };
                let Ok(mut tls) = accept(stream, &hello, &identity).await else {
                    return;
                };
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match tls.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if tls.write_all(&buf[..n]).await.is_err() || tls.flush().await.is_err()
                            {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// Test-only verifier for the inner target's throwaway certificate.
struct AcceptAnyCertificate;

impl HandshakeHooks for AcceptAnyCertificate {
    fn verify_server_certificates(
        &mut self,
        _server_name: &str,
        _chain: &[Vec<u8>],
    ) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vision_relays_plain_traffic_with_padding() {
    let server = start().await;
    let echo_addr = echo_server().await;
    let outbound = user_client(
        server.addr,
        server_public_key(),
        SHORT_ID,
        BOB,
        Flow::Vision,
    );
    let mut stream =
        tokio::time::timeout(TIMEOUT, outbound.connect_stream(&TargetAddr::Ip(echo_addr)))
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
    assert!(!stream.is_direct_write() && !stream.is_direct_read());

    tokio::time::sleep(Duration::from_millis(50)).await;
    let traffic = server.inbound.users().traffic(false);
    let bob = traffic.iter().find(|entry| entry.name == "bob").unwrap();
    assert_eq!(
        (bob.up, bob.down),
        (payload.len() as u64, payload.len() as u64)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vision_copies_inner_tls13_directly() {
    let server = start().await;
    let target = tls_echo_server().await;
    let outbound = user_client(
        server.addr,
        server_public_key(),
        SHORT_ID,
        BOB,
        Flow::Vision,
    );
    let vless = tokio::time::timeout(TIMEOUT, outbound.connect_stream(&TargetAddr::Ip(target)))
        .await
        .expect("connect timed out")
        .unwrap();
    let mut inner = tokio::time::timeout(
        TIMEOUT,
        tls_mimic::connect(
            vless,
            &ClientConfig::new("target.test", Fingerprint::Chrome),
            &mut AcceptAnyCertificate,
        ),
    )
    .await
    .expect("inner handshake timed out")
    .unwrap();
    for size in [5usize, 50_000] {
        let payload: Vec<u8> = (0..size).map(|i| (i % 253) as u8).collect();
        inner.write_all(&payload).await.unwrap();
        inner.flush().await.unwrap();
        let mut received = vec![0u8; size];
        tokio::time::timeout(TIMEOUT, inner.read_exact(&mut received))
            .await
            .expect("inner echo timed out")
            .unwrap();
        assert_eq!(received, payload);
    }
    let vless = inner.get_ref();
    assert!(vless.vision_state().unwrap().enable_xtls);
    assert!(vless.is_direct_write(), "uplink did not switch to direct");
    assert!(vless.is_direct_read(), "downlink did not switch to direct");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flow_must_match_the_user() {
    let server = start().await;
    let echo_addr = echo_server().await;
    for (uuid, flow) in [(BOB, Flow::None), (ALICE, Flow::Vision)] {
        let outbound = user_client(server.addr, server_public_key(), SHORT_ID, uuid, flow);
        let mut stream =
            tokio::time::timeout(TIMEOUT, outbound.connect(&TargetAddr::Ip(echo_addr)))
                .await
                .expect("connect timed out")
                .unwrap();
        let _ = stream.write_all(b"ping").await;
        let mut buf = [0u8; 4];
        let read = tokio::time::timeout(TIMEOUT, stream.read_exact(&mut buf))
            .await
            .expect("refusal timed out");
        assert!(read.is_err(), "{uuid} with {flow:?} was relayed");
    }
}
