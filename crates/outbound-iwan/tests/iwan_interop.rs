//! Black-box interop with `iwand-server` (spec §10.2, §10.1), run by the
//! interop CI job:
//!
//! ```text
//! NC_IWAN_SERVER=127.0.0.1:45670 \
//! NC_IWAN_PLAIN=plain:pw-plain:10.20.30.10 NC_IWAN_XOR=xor:pw-xor:10.20.30.11 \
//! NC_IWAN_DNS=1.1.1.1,8.8.8.8 NC_IWAN_MTU=1380 \
//!   cargo test -p outbound-iwan --test iwan_interop -- --ignored --test-threads=1
//! ```
//!
//! The server's `plain` user has `allow_encrypt: false`; its `xor` user may
//! mask. Packet-level cases drive the sans-IO client over a blocking socket;
//! the outbound cases pass TCP and UDP between two nodes through the
//! server's forwarding.
//!
//! Setting `IWAN_SERVER` targets an external server instead, such as a real
//! Panabit device: `IWAN_SERVER` (IPv4 or host name), `IWAN_PORT` (default
//! 4567), `IWAN_USER_PLAIN`/`IWAN_PASS_PLAIN`, optional
//! `IWAN_USER_XOR`/`IWAN_PASS_XOR`, `IWAN_MTU` (client MTU, default 1400) and
//! optional `IWAN_FETCH` (`host:port` of an HTTP server reachable through the
//! server's exit). Only the handshake and lease, OPENREJ, ECHO RTT and the
//! fetch run then; cases that rely on iwand-server's echo and forwarding
//! are skipped.

use std::collections::VecDeque;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use engine_outbound::{TargetAddr, TcpOutbound};
use outbound_iwan::packet;
use outbound_iwan::{Client, ClientConfig, IwanConfig, IwanOutbound, Output, State};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const WAIT: Duration = Duration::from_secs(10);
/// TEST-NET-1: not any user's address, so the server echoes it (spec §10.1).
const ECHO_TARGET: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

#[derive(Clone)]
struct User {
    name: String,
    password: String,
    address: Ipv4Addr,
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// An external server (`IWAN_SERVER`) rather than the CI iwand-server.
fn external() -> bool {
    optional_env("IWAN_SERVER").is_some()
}

/// Skips a case that needs iwand-server's echo or forwarding.
fn iwand_only(case: &str) -> bool {
    if external() {
        eprintln!("{case}: skipped against an external server");
    }
    external()
}

/// Host and port as the outbound config takes them.
fn server_host() -> (String, u16) {
    match optional_env("IWAN_SERVER") {
        Some(host) => {
            let port = optional_env("IWAN_PORT").map_or(4567, |port| port.parse().unwrap());
            (host, port)
        }
        None => {
            let server: SocketAddr = env("NC_IWAN_SERVER").parse().unwrap();
            (server.ip().to_string(), server.port())
        }
    }
}

fn server() -> SocketAddr {
    use std::net::ToSocketAddrs;
    let (host, port) = server_host();
    (host.as_str(), port)
        .to_socket_addrs()
        .unwrap()
        .find(SocketAddr::is_ipv4)
        .expect("iwan server has no IPv4 address")
}

fn client_mtu() -> u16 {
    optional_env("IWAN_MTU").map_or(1400, |mtu| mtu.parse().unwrap())
}

/// `kind` is `PLAIN` or `XOR`. Against an external server the tunnel address
/// is not known in advance and stays unspecified.
fn user(kind: &str) -> User {
    if external() {
        return User {
            name: env(&format!("IWAN_USER_{kind}")),
            password: env(&format!("IWAN_PASS_{kind}")),
            address: Ipv4Addr::UNSPECIFIED,
        };
    }
    let value = env(&format!("NC_IWAN_{kind}"));
    let mut parts = value.splitn(3, ':');
    User {
        name: parts.next().unwrap().to_owned(),
        password: parts.next().unwrap().to_owned(),
        address: parts.next().unwrap().parse().unwrap(),
    }
}

fn dns() -> Vec<Ipv4Addr> {
    env("NC_IWAN_DNS")
        .split(',')
        .map(|address| address.parse().unwrap())
        .collect()
}

fn server_mtu() -> u16 {
    env("NC_IWAN_MTU").parse().unwrap()
}

/// An IPv4/UDP packet; the server forwards or echoes it without checking.
fn udp_packet(source: Ipv4Addr, destination: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let total = 28 + payload.len();
    let mut packet = vec![0u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let mut sum = 0u32;
    for word in packet[..20].chunks(2) {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    packet[20..22].copy_from_slice(&40000u16.to_be_bytes());
    packet[22..24].copy_from_slice(&9u16.to_be_bytes());
    packet[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    packet[28..].copy_from_slice(payload);
    packet
}

/// The sans-IO client on a blocking socket, like a minimal driver.
struct Harness {
    client: Client,
    socket: UdpSocket,
    next_tick: Instant,
    events: VecDeque<Output>,
}

impl Harness {
    fn new(user: &User, password: &str, encrypt: bool) -> Self {
        let config = ClientConfig {
            username: user.name.clone().into_bytes(),
            password: password.as_bytes().to_vec(),
            mtu: client_mtu(),
            encrypt,
            pipe_id: 0,
            pipe_idx: 0,
            resolve: false,
        };
        let now = Instant::now();
        let mut harness = Self {
            client: Client::new(config, now),
            socket: connect(),
            next_tick: now + Duration::from_secs(1),
            events: VecDeque::new(),
        };
        let mut out = Vec::new();
        harness.client.start(now, &mut out);
        harness.perform(out);
        harness
    }

    fn perform(&mut self, out: Vec<Output>) {
        for output in out {
            match output {
                Output::Transmit(datagram) => {
                    let _ = self.socket.send(&datagram);
                }
                Output::ResetSocket => self.socket = connect(),
                other => self.events.push_back(other),
            }
        }
    }

    fn step(&mut self) {
        let mut buffer = [0u8; packet::MAX_DATAGRAM];
        let mut out = Vec::new();
        match self.socket.recv(&mut buffer) {
            Ok(len) => self
                .client
                .receive(Instant::now(), &buffer[..len], &mut out),
            Err(err) if is_timeout(&err) => {}
            Err(err) => panic!("udp receive failed: {err}"),
        }
        let now = Instant::now();
        if now >= self.next_tick {
            self.next_tick = now + Duration::from_secs(1);
            self.client.tick(now, &mut out);
        }
        self.perform(out);
    }

    /// Steps until an event matches, keeping the others.
    fn wait_for(&mut self, within: Duration, matches: impl Fn(&Output) -> bool) -> Option<Output> {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if let Some(index) = self.events.iter().position(&matches) {
                return self.events.remove(index);
            }
            self.step();
        }
        None
    }

    fn established(&mut self) -> outbound_iwan::Network {
        match self.wait_for(WAIT, |event| {
            matches!(event, Output::Established(_) | Output::Rejected { .. })
        }) {
            Some(Output::Established(network)) => network,
            other => panic!("no session: {other:?}"),
        }
    }

    fn send_ip(&mut self, packet: &[u8]) {
        let datagram = self.client.encapsulate(packet).expect("session is up");
        self.socket.send(&datagram).unwrap();
    }

    fn delivered(&mut self, within: Duration) -> Option<Vec<u8>> {
        match self.wait_for(within, |event| matches!(event, Output::Deliver(_))) {
            Some(Output::Deliver(packet)) => Some(packet),
            _ => None,
        }
    }
}

fn connect() -> UdpSocket {
    // A loopback-bound socket cannot reach an external server (EINVAL).
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.connect(server()).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    socket
}

fn is_timeout(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::ConnectionRefused
    )
}

#[test]
#[ignore = "needs iwand-server; run by the interop CI job"]
fn handshake_hands_out_address_dns_and_mtu() {
    let plain = user("PLAIN");
    let mut harness = Harness::new(&plain, &plain.password, false);
    let network = harness.established();
    assert!(!network.address.is_unspecified());
    assert!(network.mtu <= client_mtu());
    if external() {
        eprintln!(
            "lease: address {} dns {:?} mtu {}",
            network.address, network.dns, network.mtu
        );
        if optional_env("IWAN_USER_XOR").is_some() {
            let masked = user("XOR");
            let mut harness = Harness::new(&masked, &masked.password, true);
            harness.established();
            eprintln!("xor user: masking {}", harness.client.encrypted());
        }
        return;
    }
    assert_eq!(network.address, plain.address);
    assert_eq!(network.dns, dns());
    assert_eq!(network.mtu, server_mtu().min(client_mtu()));
    assert!(!harness.client.encrypted());
}

#[test]
#[ignore = "needs iwand-server; run by the interop CI job"]
fn wrong_password_is_rejected() {
    let plain = user("PLAIN");
    let mut harness = Harness::new(&plain, "not-the-password", false);
    let event = harness.wait_for(WAIT, |event| {
        matches!(event, Output::Established(_) | Output::Rejected { .. })
    });
    assert!(matches!(event, Some(Output::Rejected { .. })), "{event:?}");
}

fn assert_echo(harness: &mut Harness, source: Ipv4Addr) {
    let packet = udp_packet(source, ECHO_TARGET, b"iwan echo payload");
    harness.send_ip(&packet);
    assert_eq!(harness.delivered(WAIT), Some(packet));
}

#[test]
#[ignore = "needs iwand-server; run by the interop CI job"]
fn plain_and_masked_packets_are_echoed() {
    if iwand_only("echo") {
        return;
    }
    let plain = user("PLAIN");
    let mut harness = Harness::new(&plain, &plain.password, false);
    harness.established();
    assert_echo(&mut harness, plain.address);

    let masked = user("XOR");
    let mut harness = Harness::new(&masked, &masked.password, true);
    harness.established();
    assert!(
        harness.client.encrypted(),
        "xor user should negotiate masking"
    );
    assert_echo(&mut harness, masked.address);

    // allow_encrypt is off for the plain user: the server answers mode 0.
    let mut harness = Harness::new(&plain, &plain.password, true);
    harness.established();
    assert!(!harness.client.encrypted());
    assert_echo(&mut harness, plain.address);
}

#[test]
#[ignore = "needs iwand-server; run by the interop CI job"]
fn echo_round_trip_updates_latency() {
    let plain = user("PLAIN");
    let mut harness = Harness::new(&plain, &plain.password, false);
    harness.established();
    let rtt = harness.wait_for(WAIT, |event| matches!(event, Output::Rtt { .. }));
    assert!(matches!(rtt, Some(Output::Rtt { .. })), "no ECHO reply");
    let latency = harness.client.latency();
    assert!(latency.min_us <= latency.current_us && latency.current_us <= latency.max_us);
    assert!(latency.max_us < 5_000_000);
}

#[test]
#[ignore = "needs iwand-server; run by the interop CI job"]
fn closed_session_is_removed() {
    if iwand_only("session removal") {
        return;
    }
    let plain = user("PLAIN");
    let mut harness = Harness::new(&plain, &plain.password, false);
    harness.established();
    let packet = udp_packet(plain.address, ECHO_TARGET, b"before close");
    let stale = harness.client.encapsulate(&packet).unwrap();
    harness.send_ip(&packet);
    assert!(harness.delivered(WAIT).is_some());

    let close = harness.client.close_datagram().unwrap();
    harness.socket.send(&close).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    harness.socket.send(&stale).unwrap();
    // The client still thinks the session is up; the server stays silent.
    assert_eq!(harness.client.state(), State::Established);
    assert_eq!(harness.delivered(Duration::from_millis(1500)), None);
}

fn node(user: &User, encrypt: bool) -> IwanOutbound {
    let (host, port) = server_host();
    let json = serde_json::json!({
        "server": host,
        "port": port,
        "username": user.name,
        "password": user.password,
        "encrypt": encrypt,
        "mtu": client_mtu(),
    });
    let config: IwanConfig = serde_json::from_value(json).unwrap();
    IwanOutbound::new(config.validate().unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs iwand-server; run by the interop CI job"]
async fn outbound_tcp_and_udp_between_two_nodes() {
    if iwand_only("forwarding between nodes") {
        return;
    }
    let plain_user = user("PLAIN");
    let masked_user = user("XOR");
    let plain = node(&plain_user, false);
    let masked = node(&masked_user, true);

    let listener = masked.clone();
    let accepted = tokio::spawn(async move { listener.accept_tcp(8080).await });
    let target = TargetAddr::Ip(SocketAddr::new(masked_user.address.into(), 8080));
    let mut client = None;
    for _ in 0..40 {
        match plain.connect(&target).await {
            Ok(stream) => {
                client = Some(stream);
                break;
            }
            Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(err) => panic!("connect failed: {err}"),
        }
    }
    let mut client = client.expect("listener never answered");
    let mut server = tokio::time::timeout(WAIT, accepted)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let upload: Vec<u8> = (0..200_000u32).map(|i| (i % 253) as u8).collect();
    let expected = upload.clone();
    let reader = tokio::spawn(async move {
        let mut received = vec![0u8; expected.len()];
        server.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected);
        server.write_all(b"ok").await.unwrap();
        server
    });
    client.write_all(&upload).await.unwrap();
    let mut reply = [0u8; 2];
    tokio::time::timeout(WAIT, client.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"ok");
    drop(reader.await.unwrap());

    let to_plain = TargetAddr::Ip(SocketAddr::new(plain_user.address.into(), 7101));
    let to_masked = TargetAddr::Ip(SocketAddr::new(masked_user.address.into(), 7100));
    let mut masked_flow = masked.open_udp_on(7100, &to_plain).await.unwrap();
    let mut plain_flow = plain.open_udp_on(7101, &to_masked).await.unwrap();
    plain_flow.send.send(b"ping").await.unwrap();
    let ping = tokio::time::timeout(WAIT, masked_flow.recv.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ping, b"ping");
    masked_flow.send.send(b"pong").await.unwrap();
    let pong = tokio::time::timeout(WAIT, plain_flow.recv.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pong, b"pong");
}

/// An HTTP request through the tunnel to `IWAN_FETCH`, for a server with an
/// exit; skipped when it is not set.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs an iWAN server with an exit"]
async fn fetch_through_the_tunnel() {
    let Some(fetch) = optional_env("IWAN_FETCH") else {
        eprintln!("fetch: skipped, IWAN_FETCH is not set");
        return;
    };
    let (host, port) = fetch.rsplit_once(':').expect("IWAN_FETCH is host:port");
    let port: u16 = port.parse().unwrap();
    let target = match host.parse::<Ipv4Addr>() {
        Ok(address) => TargetAddr::Ip(SocketAddr::new(address.into(), port)),
        Err(_) => TargetAddr::Domain(host.to_owned(), port),
    };
    let plain = node(&user("PLAIN"), false);
    let mut stream = tokio::time::timeout(WAIT, plain.connect(&target))
        .await
        .unwrap()
        .unwrap();
    let request = format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut head = [0u8; 5];
    tokio::time::timeout(WAIT, stream.read_exact(&mut head))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&head, b"HTTP/");
    eprintln!("fetch: ECHO rtt {:?}", plain.rtt());
}
