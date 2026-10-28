//! The AnyTLS server inbound against a minimal client written from the
//! protocol: TLS, the password hash, settings and stream frames.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use engine_inbound::addr::{write_addr_port, SOCKS};
use engine_inbound::registry::InboundFactory;
use engine_inbound::server::{serve_with_udp, InboundStats, ServeSettings};
use engine_inbound::udp::BoundUdpOutbound;
use engine_inbound::StreamInbound;
use engine_outbound::{BoxFuture, BoxStream, TargetAddr};
use inbound_anytls::{AnyTlsInboundFactory, PaddingScheme, UOT_MAGIC_ADDRESS};
use rcgen::{CertificateParams, KeyPair};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use transport_tls::{TlsConnector, TlsSettings};

const TIMEOUT: Duration = Duration::from_secs(10);

const SYN: u8 = 1;
const PSH: u8 = 2;
const FIN: u8 = 3;
const SETTINGS: u8 = 4;
const ALERT: u8 = 5;
const UPDATE_PADDING_SCHEME: u8 = 6;
const SYNACK: u8 = 7;
const HEART_REQUEST: u8 = 8;
const HEART_RESPONSE: u8 = 9;
const SERVER_SETTINGS: u8 = 10;

struct Direct;

impl engine_outbound::TcpOutbound for Direct {
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
}

async fn start(fallback: Option<SocketAddr>) -> Server {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["anytls.test".to_string()])
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
    if let Some(fallback) = fallback {
        settings["fallback"] = serde_json::json!({
            "server": fallback.ip().to_string(),
            "server_port": fallback.port()
        });
    }
    let inbound = AnyTlsInboundFactory
        .build(settings.as_object().unwrap())
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_with_udp(
        listener,
        inbound.clone(),
        Arc::new(Direct),
        Some(Arc::new(BoundUdpOutbound::new(
            "127.0.0.1:0".parse().unwrap(),
        ))),
        ServeSettings {
            reject_hold: Duration::from_millis(300),
            ..ServeSettings::default()
        },
        Arc::new(InboundStats::default()),
    ));
    Server { addr, inbound }
}

async fn tls(server: SocketAddr) -> BoxStream {
    let tcp = TcpStream::connect(server).await.unwrap();
    TlsConnector::new(&TlsSettings {
        server_name: "anytls.test".into(),
        alpn: Vec::new(),
        insecure: true,
    })
    .unwrap()
    .connect(Box::new(tcp))
    .await
    .unwrap()
}

struct Client {
    stream: BoxStream,
    /// Stream data received so far, by stream.
    received: HashMap<u32, Vec<u8>>,
    /// Frames other than stream data, in order.
    others: Vec<(u8, u32, Vec<u8>)>,
}

impl Client {
    /// Authenticates with `password` and some padding, then sends
    /// `settings` when given.
    async fn open(server: SocketAddr, password: &str, settings: Option<String>) -> Self {
        let mut stream = tls(server).await;
        let mut hello = Sha256::digest(password.as_bytes()).to_vec();
        hello.extend_from_slice(&40u16.to_be_bytes());
        hello.extend_from_slice(&[0u8; 40]);
        stream.write_all(&hello).await.unwrap();
        let mut client = Self {
            stream,
            received: HashMap::new(),
            others: Vec::new(),
        };
        if let Some(settings) = settings {
            client.send(SETTINGS, 0, settings.as_bytes()).await;
        }
        client
    }

    async fn v2(server: SocketAddr, password: &str) -> Self {
        let md5 = PaddingScheme::default().md5().to_owned();
        Self::open(
            server,
            password,
            Some(format!("v=2\nclient=test/1.0\npadding-md5={md5}")),
        )
        .await
    }

    async fn send(&mut self, command: u8, id: u32, data: &[u8]) {
        let mut frame = vec![command];
        frame.extend_from_slice(&id.to_be_bytes());
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(data);
        self.stream.write_all(&frame).await.unwrap();
    }

    async fn recv(&mut self) -> (u8, u32, Vec<u8>) {
        tokio::time::timeout(TIMEOUT, async {
            let mut header = [0u8; 7];
            self.stream.read_exact(&mut header).await?;
            let len = usize::from(u16::from_be_bytes([header[5], header[6]]));
            let mut data = vec![0u8; len];
            self.stream.read_exact(&mut data).await?;
            let id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
            Ok::<_, std::io::Error>((header[0], id, data))
        })
        .await
        .expect("frame timed out")
        .expect("session closed")
    }

    /// Opens stream `id` toward `target`, with `payload` in the same frame.
    async fn open_stream(&mut self, id: u32, target: &TargetAddr, payload: &[u8]) {
        self.send(SYN, id, &[]).await;
        let mut data = socks(target);
        data.extend_from_slice(payload);
        self.send(PSH, id, &data).await;
    }

    /// Takes `len` bytes of stream `id`, waiting for them; other frames
    /// are kept in `others`.
    async fn read_stream(&mut self, id: u32, len: usize) -> Vec<u8> {
        while self.received.get(&id).map_or(0, Vec::len) < len {
            let (command, from, data) = self.recv().await;
            if command == PSH {
                self.received
                    .entry(from)
                    .or_default()
                    .extend_from_slice(&data);
            } else {
                self.others.push((command, from, data));
            }
        }
        self.received.remove(&id).unwrap_or_default()
    }
}

fn socks(target: &TargetAddr) -> Vec<u8> {
    let mut out = Vec::new();
    match target {
        TargetAddr::Ip(addr) => write_addr_port(&mut out, *addr, SOCKS),
        TargetAddr::Domain(host, port) => {
            out.push(3);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relays_streams_and_charges_the_user() {
    let server = start(None).await;
    let echo = echo_server().await;
    let mut client = Client::v2(server.addr, "alice-secret").await;

    let (command, _, data) = client.recv().await;
    assert_eq!(
        (command, data.as_slice()),
        (SERVER_SETTINGS, b"v=2".as_slice())
    );

    let payload: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
    client
        .open_stream(1, &TargetAddr::Ip(echo), &payload[..1000])
        .await;
    for chunk in payload[1000..].chunks(8000) {
        client.send(PSH, 1, chunk).await;
    }
    client
        .open_stream(
            2,
            &TargetAddr::Domain("localhost".into(), echo.port()),
            b"second",
        )
        .await;
    let echoed = client.read_stream(1, payload.len()).await;
    assert_eq!(echoed, payload);
    let second = client.read_stream(2, 6).await;
    assert_eq!(second, b"second");
    assert!(
        client.others.contains(&(SYNACK, 1, Vec::new())),
        "{:?}",
        client.others
    );
    assert!(
        client.others.contains(&(SYNACK, 2, Vec::new())),
        "{:?}",
        client.others
    );

    // A FIN from the client closes the stream; the server answers with one.
    client.send(FIN, 2, &[]).await;
    loop {
        let (command, id, _) = client.recv().await;
        if (command, id) == (FIN, 2) {
            break;
        }
    }
    client.send(HEART_REQUEST, 0, &[]).await;
    loop {
        let (command, _, _) = client.recv().await;
        if command == HEART_RESPONSE {
            break;
        }
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    let traffic = server.inbound.users().traffic(true);
    assert_eq!(traffic.len(), 1);
    assert_eq!(traffic[0].name, "alice");
    let total = (payload.len() + 6) as u64;
    assert_eq!((traffic[0].up, traffic[0].down), (total, total));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn version_one_clients_get_no_synack_and_other_schemes_are_updated() {
    let server = start(None).await;
    let echo = echo_server().await;
    let mut client = Client::open(
        server.addr,
        "bob-secret",
        Some("client=old\npadding-md5=00".into()),
    )
    .await;
    let (command, _, data) = client.recv().await;
    assert_eq!(command, UPDATE_PADDING_SCHEME);
    assert_eq!(data, PaddingScheme::default().raw());
    client.open_stream(1, &TargetAddr::Ip(echo), b"v1").await;
    assert_eq!(client.read_stream(1, 2).await, b"v1");
    assert!(client.others.is_empty(), "{:?}", client.others);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreachable_targets_get_a_synack_with_the_error() {
    let server = start(None).await;
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = closed.local_addr().unwrap();
    drop(closed);
    let mut client = Client::v2(server.addr, "alice-secret").await;
    client.open_stream(1, &TargetAddr::Ip(target), b"x").await;
    let mut synack = None;
    loop {
        let (command, id, data) = client.recv().await;
        match (command, id) {
            (SYNACK, 1) => synack = Some(data),
            (FIN, 1) => break,
            _ => {}
        }
    }
    assert!(!synack.expect("no SYNACK").is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streams_before_settings_get_an_alert() {
    let server = start(None).await;
    let echo = echo_server().await;
    let mut client = Client::open(server.addr, "alice-secret", None).await;
    client.open_stream(1, &TargetAddr::Ip(echo), b"x").await;
    let (command, _, data) = client.recv().await;
    assert_eq!(command, ALERT);
    assert!(!data.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_over_tcp_in_both_modes() {
    let server = start(None).await;
    let udp_echo = udp_echo_server().await;
    let magic = TargetAddr::Domain(UOT_MAGIC_ADDRESS.into(), 0);
    let mut client = Client::v2(server.addr, "alice-secret").await;

    // Packets with addresses (codes 0 IPv4, 1 IPv6, 2 domain).
    let mut request = vec![0u8];
    request.extend_from_slice(&socks(&TargetAddr::Ip(udp_echo)));
    let mut packet = vec![0u8];
    packet.extend_from_slice(&[127, 0, 0, 1]);
    packet.extend_from_slice(&udp_echo.port().to_be_bytes());
    packet.extend_from_slice(&5u16.to_be_bytes());
    packet.extend_from_slice(b"hello");
    request.extend_from_slice(&packet);
    client.open_stream(1, &magic, &request).await;
    assert_eq!(client.read_stream(1, packet.len()).await, packet);

    // Connect mode: one destination, packets without addresses.
    let mut request = vec![1u8];
    request.extend_from_slice(&socks(&TargetAddr::Ip(udp_echo)));
    request.extend_from_slice(&3u16.to_be_bytes());
    request.extend_from_slice(b"abc");
    client.open_stream(2, &magic, &request).await;
    let mut expected = 3u16.to_be_bytes().to_vec();
    expected.extend_from_slice(b"abc");
    assert_eq!(client.read_stream(2, 5).await, expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_passwords_go_to_the_fallback() {
    let web = web_server().await;
    let server = start(Some(web)).await;
    let mut stream = tls(server.addr).await;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: anytls.test\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(TIMEOUT, stream.read_to_end(&mut response)).await;
    assert!(response.starts_with(b"HTTP/1.1 200 OK"), "{response:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removing_the_user_ends_the_session() {
    let server = start(None).await;
    let echo = echo_server().await;
    let mut client = Client::v2(server.addr, "bob-secret").await;
    client.open_stream(1, &TargetAddr::Ip(echo), b"hi").await;
    assert_eq!(client.read_stream(1, 2).await, b"hi");
    assert!(server.inbound.users().remove("bob"));
    let closed = tokio::time::timeout(TIMEOUT, async {
        let mut buf = [0u8; 256];
        loop {
            match client.stream.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "the session stayed open");
}
