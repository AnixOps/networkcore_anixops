//! The inbound against two kinds of clients: the `outbound-iwan` client for
//! TCP, tunnel DNS and UDP end to end, and raw datagrams for the session
//! rules of spec §12.1 and §12.2.
//!
//! The node side is faked: the TCP outbound records each target and connects
//! to a local echo server; the UDP outbound records each target and sends to
//! a local echo socket, or for port 53 to a resolver that answers every A
//! query with [`RESOLVED`].

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use engine_inbound::registry::{PacketInboundFactory, Settings};
use engine_inbound::server::{InboundStats, ServeSettings};
use engine_inbound::udp::{UdpOutbound, UdpSession};
use engine_inbound::PacketInbound;
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use inbound_iwan::IwanInboundFactory;
use outbound_iwan::crypto::XorKey;
use outbound_iwan::packet::{self, kind, EchoRequest, Header, OpenRequest, HEADER_LEN};
use outbound_iwan::{IwanConfig, IwanOutbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 1);
const BOB_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 50);
const UPSTREAM_DNS: &str = "192.0.2.53:53";
const RESOLVED: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
const QUIET: Duration = Duration::from_millis(400);

type Targets = Arc<Mutex<Vec<TargetAddr>>>;

struct Fixture {
    port: u16,
    inbound: Arc<dyn PacketInbound>,
    tcp_targets: Targets,
    udp_targets: Targets,
}

async fn start(client_to_client: bool) -> Fixture {
    let json = serde_json::json!({
        "pool": "10.66.0.0/24",
        "mtu": 1400,
        "dns_upstream": UPSTREAM_DNS,
        "allow_client_to_client": client_to_client,
        "users": [
            {"name": "1001", "username": "alice", "password": "pw-alice"},
            {"name": "1002", "username": "bob", "password": "pw-bob", "address": BOB_ADDRESS.to_string()},
        ],
    });
    let settings: Settings = serde_json::from_value(json).unwrap();
    let inbound = IwanInboundFactory.build(&settings).ok().unwrap();

    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_address = echo.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = echo.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    let udp_echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_echo_address = udp_echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = [0u8; 2048];
        while let Ok((len, from)) = udp_echo.recv_from(&mut buffer).await {
            let _ = udp_echo.send_to(&buffer[..len], from).await;
        }
    });
    let resolver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let resolver_address = resolver.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = [0u8; 2048];
        while let Ok((len, from)) = resolver.recv_from(&mut buffer).await {
            if let Some(answer) = answer(&buffer[..len]) {
                let _ = resolver.send_to(&answer, from).await;
            }
        }
    });

    let tcp_targets = Targets::default();
    let udp_targets = Targets::default();
    let outbound = Arc::new(FakeTcp {
        echo: echo_address,
        targets: tcp_targets.clone(),
    });
    let udp = Arc::new(FakeUdp {
        echo: udp_echo_address,
        resolver: resolver_address,
        targets: udp_targets.clone(),
    });
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    let served = inbound.clone().serve(
        socket,
        outbound,
        Some(udp),
        ServeSettings::default(),
        Arc::new(InboundStats::default()),
    );
    tokio::spawn(served);
    Fixture {
        port,
        inbound,
        tcp_targets,
        udp_targets,
    }
}

/// Answers an A query with one record for [`RESOLVED`].
fn answer(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut end = 12;
    while *query.get(end)? != 0 {
        end += 1 + usize::from(query[end]);
    }
    let question_end = end + 5;
    let question = query.get(12..question_end)?;
    let mut out = Vec::new();
    out.extend_from_slice(&query[..2]);
    out.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
    out.extend_from_slice(question);
    out.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
    out.extend_from_slice(&RESOLVED.octets());
    Some(out)
}

struct FakeTcp {
    echo: SocketAddr,
    targets: Targets,
}

impl TcpOutbound for FakeTcp {
    fn protocol(&self) -> &'static str {
        "fake"
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            self.targets.lock().unwrap().push(target.clone());
            let stream = TcpStream::connect(self.echo).await?;
            Ok(Box::new(stream) as BoxStream)
        })
    }
}

struct FakeUdp {
    echo: SocketAddr,
    resolver: SocketAddr,
    targets: Targets,
}

impl UdpOutbound for FakeUdp {
    fn bind(&self) -> BoxFuture<'_, io::Result<Arc<dyn UdpSession>>> {
        Box::pin(async move {
            let socket = UdpSocket::bind("127.0.0.1:0").await?;
            Ok(Arc::new(FakeSession {
                socket,
                echo: self.echo,
                resolver: self.resolver,
                targets: self.targets.clone(),
                last: Mutex::new(None),
            }) as Arc<dyn UdpSession>)
        })
    }
}

struct FakeSession {
    socket: UdpSocket,
    echo: SocketAddr,
    resolver: SocketAddr,
    targets: Targets,
    last: Mutex<Option<SocketAddr>>,
}

impl UdpSession for FakeSession {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        target: &'a TargetAddr,
    ) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            self.targets.lock().unwrap().push(target.clone());
            let TargetAddr::Ip(address) = target else {
                return Err(io::ErrorKind::Unsupported.into());
            };
            let to = if address.port() == 53 {
                self.resolver
            } else {
                *self.last.lock().unwrap() = Some(*address);
                self.echo
            };
            self.socket.send_to(payload, to).await.map(|_| ())
        })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, io::Result<(usize, SocketAddr)>> {
        Box::pin(async move {
            let (len, from) = self.socket.recv_from(buf).await?;
            let source = if from == self.resolver {
                UPSTREAM_DNS.parse().unwrap()
            } else {
                self.last.lock().unwrap().unwrap_or(from)
            };
            Ok((len, source))
        })
    }
}

fn client(port: u16, username: &str, password: &str, encrypt: bool) -> IwanOutbound {
    let config: IwanConfig = serde_json::from_value(serde_json::json!({
        "server": "127.0.0.1",
        "port": port,
        "username": username,
        "password": password,
        "encrypt": encrypt,
    }))
    .unwrap();
    IwanOutbound::new(config.validate().unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_dns_and_udp_through_the_inbound() {
    let fixture = start(false).await;
    let alice = client(fixture.port, "alice", "pw-alice", true);

    let target = TargetAddr::Ip("203.0.113.9:443".parse().unwrap());
    let stream = tokio::time::timeout(Duration::from_secs(15), alice.connect(&target))
        .await
        .unwrap()
        .unwrap();
    let (mut reader, mut writer) = tokio::io::split(stream);
    let upload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let expected = upload.clone();
    let sender = tokio::spawn(async move {
        writer.write_all(&upload).await.unwrap();
        writer
    });
    let mut echoed = vec![0u8; expected.len()];
    tokio::time::timeout(Duration::from_secs(20), reader.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echoed, expected);
    drop(sender.await.unwrap());

    // The client resolves through the gateway; the node sees the address.
    let named = TargetAddr::Domain("example.test".into(), 80);
    let mut stream = tokio::time::timeout(Duration::from_secs(15), alice.connect(&named))
        .await
        .unwrap()
        .unwrap();
    stream.write_all(b"hello").await.unwrap();
    let mut greeting = [0u8; 5];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"hello");
    let tcp_targets = fixture.tcp_targets.lock().unwrap().clone();
    assert_eq!(
        tcp_targets,
        vec![target, TargetAddr::Ip(SocketAddr::new(RESOLVED.into(), 80)),]
    );
    assert!(fixture
        .udp_targets
        .lock()
        .unwrap()
        .contains(&TargetAddr::Ip(UPSTREAM_DNS.parse().unwrap())));

    let udp_target = TargetAddr::Ip("203.0.113.10:5000".parse().unwrap());
    let mut flow = alice.open_udp(&udp_target).await.unwrap();
    flow.send.send(b"ping").await.unwrap();
    let pong = tokio::time::timeout(Duration::from_secs(5), flow.recv.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pong, b"ping");
    assert!(fixture.udp_targets.lock().unwrap().contains(&udp_target));

    let traffic = fixture.inbound.users().traffic(false);
    let alice_traffic = traffic.iter().find(|entry| entry.name == "1001").unwrap();
    assert!(alice_traffic.up >= 200_000, "{}", alice_traffic.up);
    assert!(alice_traffic.down >= 200_000, "{}", alice_traffic.down);
    assert!(fixture
        .inbound
        .users()
        .online()
        .iter()
        .any(|online| online.name == "1001"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_password_is_rejected() {
    let fixture = start(false).await;
    let eve = client(fixture.port, "alice", "nope", false);
    let target = TargetAddr::Ip("203.0.113.9:443".parse().unwrap());
    let error = eve.connect(&target).await.err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

    let raw = Raw::new(fixture.port).await;
    raw.send(&open("mallory", "pw-alice", 1400, false)).await;
    let reply = raw.recv().await.unwrap();
    assert_eq!(reply, packet::encode_open_rej());
    // MTU out of range.
    raw.send(&open("alice", "pw-alice", 45, false)).await;
    assert_eq!(raw.recv().await.unwrap(), packet::encode_open_rej());
}

/// A client speaking datagrams directly.
struct Raw {
    socket: UdpSocket,
    server: SocketAddr,
}

impl Raw {
    async fn new(port: u16) -> Self {
        Self {
            socket: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            server: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port),
        }
    }

    async fn send(&self, datagram: &[u8]) {
        self.socket.send_to(datagram, self.server).await.unwrap();
    }

    async fn recv(&self) -> Option<Vec<u8>> {
        let mut buffer = [0u8; 4096];
        match tokio::time::timeout(QUIET, self.socket.recv_from(&mut buffer)).await {
            Ok(Ok((len, _))) => Some(buffer[..len].to_vec()),
            _ => None,
        }
    }

    async fn login(&self, username: &str, password: &str, mtu: u16, encrypt: bool) -> Login {
        self.send(&open(username, password, mtu, encrypt)).await;
        let reply = self.recv().await.unwrap();
        let ack = packet::decode_open_ack(&reply).unwrap();
        Login {
            session: ack.session,
            address: ack.address.unwrap(),
            mtu: ack.server_mtu.unwrap(),
            dns: ack.dns,
            xor: (ack.encrypt != 0).then(|| XorKey::new(username.as_bytes(), password.as_bytes())),
        }
    }

    async fn echo(&self, login: &Login) -> bool {
        let echo = EchoRequest {
            sent_us: 42,
            current_us: 0,
            min_us: 0,
            max_us: 0,
            route_magic: 0,
        };
        self.send(&packet::encode_echo_request(login.session, &echo))
            .await;
        match self.recv().await {
            Some(reply) => packet::decode_echo_response(&reply) == Some(42),
            None => false,
        }
    }

    async fn send_ip(&self, login: &Login, ip: &[u8]) {
        self.send(&packet::encode_data(login.session, login.xor.as_ref(), ip))
            .await;
    }

    /// The IP packet of the next DATA, unmasked.
    async fn recv_ip(&self, login: &Login) -> Option<Vec<u8>> {
        let datagram = self.recv().await?;
        let header = Header::decode(&datagram)?;
        let expected = if login.xor.is_some() {
            kind::DATA_ENC
        } else {
            kind::DATA
        };
        assert_eq!(header.kind, expected);
        assert_eq!(header.session, login.session);
        let mut ip = datagram[HEADER_LEN..].to_vec();
        if let Some(xor) = &login.xor {
            xor.apply(&mut ip);
        }
        Some(ip)
    }
}

struct Login {
    session: packet::Session,
    address: Ipv4Addr,
    mtu: u16,
    dns: Vec<Ipv4Addr>,
    xor: Option<XorKey>,
}

fn open(username: &str, password: &str, mtu: u16, encrypt: bool) -> Vec<u8> {
    packet::encode_open(&OpenRequest {
        username: username.as_bytes(),
        password: password.as_bytes(),
        mtu,
        encrypt,
        pipe_id: 0,
        pipe_idx: 0,
    })
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in data.chunks(2) {
        let word = u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]);
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv4(protocol: u8, src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x45, 0, 0, 0, 0, 1, 0, 0, 64, protocol, 0, 0];
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());
    out.extend_from_slice(payload);
    let total = out.len() as u16;
    out[2..4].copy_from_slice(&total.to_be_bytes());
    let sum = checksum(&out[..20]);
    out[10..12].copy_from_slice(&sum.to_be_bytes());
    out
}

fn ping(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34, 0, 7, b'i', b'w', b'a', b'n'];
    let sum = checksum(&icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    ipv4(1, src, dst, &icmp)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sessions_follow_the_server_rules() {
    let fixture = start(false).await;
    let bob = Raw::new(fixture.port).await;
    let login = bob.login("bob", "pw-bob", 1300, true).await;
    assert_eq!(login.address, BOB_ADDRESS);
    assert_eq!(login.mtu, 1300);
    assert_eq!(login.dns, vec![GATEWAY]);
    assert!(login.xor.is_some());
    assert!(bob.echo(&login).await);

    // The gateway answers pings; a spoofed source gets nothing.
    bob.send_ip(&login, &ping(BOB_ADDRESS, GATEWAY)).await;
    let reply = bob.recv_ip(&login).await.unwrap();
    assert_eq!(&reply[12..16], &GATEWAY.octets());
    assert_eq!(&reply[16..20], &BOB_ADDRESS.octets());
    assert_eq!(reply[20], 0);
    bob.send_ip(&login, &ping(Ipv4Addr::new(10, 66, 0, 99), GATEWAY))
        .await;
    assert!(bob.recv().await.is_none());

    // The wrong DATA type for the session is dropped.
    let plain = packet::encode_data(login.session, None, &ping(BOB_ADDRESS, GATEWAY));
    bob.send(&plain).await;
    assert!(bob.recv().await.is_none());

    // Alice gets a pool address that is not bob's fixed one, without XOR.
    let alice = Raw::new(fixture.port).await;
    let alice_login = alice.login("alice", "pw-alice", 1400, false).await;
    assert_eq!(alice_login.address, Ipv4Addr::new(10, 66, 0, 2));
    assert_eq!(alice_login.mtu, 1400);
    assert!(alice_login.xor.is_none());

    // Users cannot reach each other by default.
    alice
        .send_ip(
            &alice_login,
            &ipv4(17, alice_login.address, BOB_ADDRESS, b"hi bob"),
        )
        .await;
    assert!(bob.recv().await.is_none());

    // A new login of bob from another port replaces the first session and
    // keeps the address.
    let bob_again = Raw::new(fixture.port).await;
    let relogin = bob_again.login("bob", "pw-bob", 1400, false).await;
    assert_eq!(relogin.address, BOB_ADDRESS);
    assert!(!bob.echo(&login).await);
    assert!(bob_again.echo(&relogin).await);

    // CLOSE ends the session.
    bob_again
        .send(&packet::signed(
            Header::new(kind::CLOSE, 0, relogin.session),
            &[],
        ))
        .await;
    assert!(bob_again.recv().await.is_none());
    assert!(!bob_again.echo(&relogin).await);

    // Removing the user ends its session within the sweep interval.
    assert!(alice.echo(&alice_login).await);
    fixture.inbound.users().remove("1001");
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(!alice.echo(&alice_login).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_to_client_when_allowed() {
    let fixture = start(true).await;
    let alice = Raw::new(fixture.port).await;
    let alice_login = alice.login("alice", "pw-alice", 1400, false).await;
    let bob = Raw::new(fixture.port).await;
    let bob_login = bob.login("bob", "pw-bob", 1400, true).await;
    let packet = ipv4(17, alice_login.address, BOB_ADDRESS, b"hi bob");
    alice.send_ip(&alice_login, &packet).await;
    assert_eq!(bob.recv_ip(&bob_login).await.unwrap(), packet);
}
