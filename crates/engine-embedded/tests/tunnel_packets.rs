//! Packet-level tunnel tests: raw IP packets in, raw IP packets out.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use engine_embedded::config::{DnsConfig, DnsRuleConfig, DnsServerConfig, DnsVia};
use engine_embedded::dns_policy::DnsPolicy;
use engine_embedded::tunnel::{PacketSink, Tunnel, TunnelSettings};
use engine_outbound::{
    BoxFuture, BoxStream, DatagramRecv, DatagramSend, TargetAddr, TcpOutbound, UdpFlow,
};
use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};

const APP: [u8; 4] = [10, 0, 0, 2];
const REMOTE: [u8; 4] = [10, 0, 0, 80];
const DNS: [u8; 4] = [10, 0, 0, 53];
const WAIT: Duration = Duration::from_secs(10);

/// Test outbound that sends every flow to one local server, whatever the target.
struct Redirect(SocketAddr);

impl TcpOutbound for Redirect {
    fn protocol(&self) -> &'static str {
        "test-redirect"
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let stream = tokio::net::TcpStream::connect(self.0).await?;
            Ok(Box::new(stream) as BoxStream)
        })
    }
}

/// Test outbound whose UDP flows all go to one local UDP server.
struct UdpRedirect(SocketAddr);

impl TcpOutbound for UdpRedirect {
    fn protocol(&self) -> &'static str {
        "test-udp-redirect"
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async { Err(io::Error::other("test outbound carries udp only")) })
    }

    fn open_udp<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(async move {
            let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
            socket.connect(self.0).await?;
            Ok(UdpFlow::new(
                Box::new(SocketSend(socket.clone())),
                Box::new(SocketRecv(socket)),
            ))
        })
    }
}

struct SocketSend(Arc<tokio::net::UdpSocket>);

impl DatagramSend for SocketSend {
    fn send<'a>(&'a mut self, payload: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move { self.0.send(payload).await.map(|_| ()) })
    }
}

struct SocketRecv(Arc<tokio::net::UdpSocket>);

impl DatagramRecv for SocketRecv {
    fn recv(&mut self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        Box::pin(async move {
            let mut buf = vec![0u8; 2048];
            let n = self.0.recv(&mut buf).await?;
            buf.truncate(n);
            Ok(buf)
        })
    }
}

/// Answers every datagram with `echo:` and the payload.
fn start_udp_echo_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok((n, peer)) = socket.recv_from(&mut buf) {
            let mut reply = b"echo:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            let _ = socket.send_to(&reply, peer);
        }
    });
    addr
}

fn settings() -> TunnelSettings {
    TunnelSettings {
        mtu: 1500,
        tcp_window_bytes: 64 * 1024,
        max_tcp_connections: 8,
        max_dns_in_flight: 4,
        idle_timeout: Duration::from_secs(30),
        connect_timeout: Duration::from_secs(5),
        dns: Arc::new(DnsPolicy::tcp(
            SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)),
            Duration::from_secs(5),
        )),
    }
}

fn capture() -> (PacketSink, Receiver<Vec<u8>>) {
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let sink: PacketSink = Box::new(move |packet: &[u8]| {
        let _ = tx.lock().unwrap().send(packet.to_vec());
    });
    (sink, rx)
}

/// Waits for the first emitted packet accepted by `pick`.
fn wait_for<T>(rx: &Receiver<Vec<u8>>, mut pick: impl FnMut(&SlicedPacket<'_>) -> Option<T>) -> T {
    let deadline = Instant::now() + WAIT;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let packet = rx
            .recv_timeout(left)
            .expect("expected packet was not emitted");
        if let Ok(sliced) = SlicedPacket::from_ip(&packet) {
            if let Some(found) = pick(&sliced) {
                return found;
            }
        }
    }
}

fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            thread::spawn(move || {
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 || stream.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// DNS-over-TCP server that answers each query with the query itself, QR bit set.
fn start_dns_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            thread::spawn(move || {
                let mut length = [0u8; 2];
                if stream.read_exact(&mut length).is_err() {
                    return;
                }
                let mut query = vec![0u8; usize::from(u16::from_be_bytes(length))];
                if stream.read_exact(&mut query).is_err() {
                    return;
                }
                query[2] |= 0x80;
                let _ = stream.write_all(&length);
                let _ = stream.write_all(&query);
            });
        }
    });
    addr
}

fn dns_query() -> Vec<u8> {
    let mut query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    query.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    query
}

#[test]
fn udp_dns_query_is_answered_over_tcp() {
    let dns_server = start_dns_server();
    let (sink, rx) = capture();
    let mut tunnel = Tunnel::start(settings(), Arc::new(Redirect(dns_server)), sink).unwrap();

    let query = dns_query();
    let mut packet = Vec::new();
    PacketBuilder::ipv4(APP, DNS, 64)
        .udp(5353, 53)
        .write(&mut packet, &query)
        .unwrap();
    assert!(tunnel.input_packet(&packet));

    let response = wait_for(&rx, |sliced| match &sliced.transport {
        Some(TransportSlice::Udp(udp)) if udp.destination_port() == 5353 => {
            assert_eq!(udp.source_port(), 53);
            Some(udp.payload().to_vec())
        }
        _ => None,
    });
    assert_eq!(&response[..2], &query[..2]);
    assert_eq!(response[2] & 0x80, 0x80);
    assert_eq!(&response[3..], &query[3..]);

    let stats = tunnel.stats();
    assert_eq!(stats.dns_queries, 1);
    assert_eq!(stats.dns_failed, 0);
    assert_eq!(stats.dns_last_failure, None);
    tunnel.stop();
    tunnel.stop();
}

/// Server that accepts and closes every connection, like a proxy that drops a
/// request it cannot authenticate.
fn start_closing_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            drop(stream);
        }
    });
    addr
}

#[test]
fn dns_failure_reports_its_stage() {
    let (sink, _rx) = capture();
    let mut tunnel =
        Tunnel::start(settings(), Arc::new(Redirect(start_closing_server())), sink).unwrap();

    let mut packet = Vec::new();
    PacketBuilder::ipv4(APP, DNS, 64)
        .udp(5353, 53)
        .write(&mut packet, &dns_query())
        .unwrap();
    assert!(tunnel.input_packet(&packet));

    let deadline = Instant::now() + WAIT;
    while tunnel.stats().dns_failed == 0 {
        assert!(Instant::now() < deadline, "DNS query should fail");
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(tunnel.stats().dns_last_failure, Some("reply_closed"));
    tunnel.stop();
}

/// Sends `query` from the app to the tunnel's DNS address and returns the
/// reply it emits.
fn ask(tunnel: &Tunnel, rx: &Receiver<Vec<u8>>, query: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    PacketBuilder::ipv4(APP, DNS, 64)
        .udp(5353, 53)
        .write(&mut packet, query)
        .unwrap();
    assert!(tunnel.input_packet(&packet));
    wait_for(rx, |sliced| match &sliced.transport {
        Some(TransportSlice::Udp(udp)) if udp.destination_port() == 5353 => {
            Some(udp.payload().to_vec())
        }
        _ => None,
    })
}

#[test]
fn dns_hosts_are_answered_without_the_outbound() {
    let config = DnsConfig {
        hosts: BTreeMap::from([(
            "example.com".to_string(),
            vec!["192.0.2.7".parse().unwrap()],
        )]),
        ..DnsConfig::default()
    };
    let settings = TunnelSettings {
        dns: Arc::new(DnsPolicy::from_config(&config).unwrap()),
        ..settings()
    };
    let (sink, rx) = capture();
    let mut tunnel =
        Tunnel::start(settings, Arc::new(Redirect(start_closing_server())), sink).unwrap();

    let response = ask(&tunnel, &rx, &dns_query());
    assert_eq!(&response[..2], &[0x12, 0x34]);
    assert_eq!(&response[6..8], &[0, 1], "one answer");
    assert!(response.ends_with(&[192, 0, 2, 7]));
    let stats = tunnel.stats();
    assert_eq!(stats.dns_queries, 1);
    assert_eq!(stats.dns_failed, 0);
    tunnel.stop();
}

#[test]
fn dns_rules_send_names_to_a_direct_server() {
    let local = start_dns_server();
    let config = DnsConfig {
        servers: vec![
            DnsServerConfig {
                name: "remote".into(),
                url: "tcp://8.8.8.8".into(),
                server_name: None,
                via: DnsVia::Proxy,
            },
            DnsServerConfig {
                name: "local".into(),
                url: format!("tcp://{local}"),
                server_name: None,
                via: DnsVia::Direct,
            },
        ],
        rules: vec![DnsRuleConfig {
            domain_suffix: vec!["com".into()],
            server: "local".into(),
            ..DnsRuleConfig::default()
        }],
        ..DnsConfig::default()
    };
    let settings = TunnelSettings {
        dns: Arc::new(DnsPolicy::from_config(&config).unwrap()),
        ..settings()
    };
    let (sink, rx) = capture();
    // The proxy drops everything; only the direct server can answer.
    let mut tunnel =
        Tunnel::start(settings, Arc::new(Redirect(start_closing_server())), sink).unwrap();

    let query = dns_query();
    let response = ask(&tunnel, &rx, &query);
    assert_eq!(&response[..2], &query[..2]);
    assert_eq!(response[2] & 0x80, 0x80);
    assert_eq!(tunnel.stats().dns_failed, 0);
    tunnel.stop();
}

#[test]
fn udp_is_dropped_when_the_outbound_has_no_udp() {
    let (sink, _rx) = capture();
    let mut tunnel =
        Tunnel::start(settings(), Arc::new(Redirect(start_echo_server())), sink).unwrap();
    let mut packet = Vec::new();
    PacketBuilder::ipv4(APP, REMOTE, 64)
        .udp(40001, 443)
        .write(&mut packet, b"quic")
        .unwrap();
    assert!(tunnel.input_packet(&packet));

    let deadline = Instant::now() + WAIT;
    while tunnel.stats().udp_dropped == 0 {
        assert!(
            Instant::now() < deadline,
            "UDP/443 should be counted as dropped"
        );
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(tunnel.stats().udp_failed, 1);
    assert_eq!(tunnel.stats().udp_flows, 0);
    tunnel.stop();
}

#[test]
fn udp_flow_is_relayed_through_the_outbound() {
    let echo = start_udp_echo_server();
    let (sink, rx) = capture();
    let mut tunnel = Tunnel::start(settings(), Arc::new(UdpRedirect(echo)), sink).unwrap();

    for payload in [&b"first"[..], &b"second"[..]] {
        let mut packet = Vec::new();
        PacketBuilder::ipv4(APP, REMOTE, 64)
            .udp(40001, 443)
            .write(&mut packet, payload)
            .unwrap();
        assert!(tunnel.input_packet(&packet));

        let mut expected = b"echo:".to_vec();
        expected.extend_from_slice(payload);
        wait_for(&rx, |sliced| match (&sliced.net, &sliced.transport) {
            (Some(etherparse::NetSlice::Ipv4(ip)), Some(TransportSlice::Udp(udp)))
                if udp.source_port() == 443
                    && udp.destination_port() == 40001
                    && udp.payload() == expected.as_slice() =>
            {
                assert_eq!(ip.header().source(), REMOTE);
                assert_eq!(ip.header().destination(), APP);
                Some(())
            }
            _ => None,
        });
    }
    // Both datagrams shared one flow.
    assert_eq!(tunnel.stats().udp_flows, 1);
    assert_eq!(tunnel.stats().udp_dropped, 0);
    tunnel.stop();
}

#[test]
fn tcp_flow_is_relayed_through_the_outbound() {
    let echo = start_echo_server();
    let (sink, rx) = capture();
    let mut tunnel = Tunnel::start(settings(), Arc::new(Redirect(echo)), sink).unwrap();

    let client_isn: u32 = 1000;
    let mut syn = Vec::new();
    PacketBuilder::ipv4(APP, REMOTE, 64)
        .tcp(40000, 80, client_isn, 65535)
        .syn()
        .write(&mut syn, &[])
        .unwrap();
    assert!(tunnel.input_packet(&syn));

    let server_isn = wait_for(&rx, |sliced| match &sliced.transport {
        Some(TransportSlice::Tcp(tcp))
            if tcp.syn() && tcp.ack() && tcp.destination_port() == 40000 =>
        {
            Some(tcp.sequence_number())
        }
        _ => None,
    });

    let mut data = Vec::new();
    PacketBuilder::ipv4(APP, REMOTE, 64)
        .tcp(40000, 80, client_isn + 1, 65535)
        .ack(server_isn.wrapping_add(1))
        .psh()
        .write(&mut data, b"ping")
        .unwrap();
    assert!(tunnel.input_packet(&data));

    let echoed = wait_for(&rx, |sliced| match &sliced.transport {
        Some(TransportSlice::Tcp(tcp))
            if tcp.destination_port() == 40000 && !tcp.payload().is_empty() =>
        {
            Some(tcp.payload().to_vec())
        }
        _ => None,
    });
    assert_eq!(echoed, b"ping");

    let stats = tunnel.stats();
    assert_eq!(stats.tcp_total, 1);
    assert_eq!(stats.tcp_connect_failed, 0);
    tunnel.stop();
}
