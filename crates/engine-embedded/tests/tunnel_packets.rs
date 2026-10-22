//! Packet-level tunnel tests: raw IP packets in, raw IP packets out.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use engine_embedded::tunnel::{PacketSink, Tunnel, TunnelSettings};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
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

fn settings() -> TunnelSettings {
    TunnelSettings {
        mtu: 1500,
        tcp_window_bytes: 64 * 1024,
        max_tcp_connections: 8,
        max_dns_in_flight: 4,
        idle_timeout: Duration::from_secs(30),
        connect_timeout: Duration::from_secs(5),
        dns_upstream: SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)),
        dns_timeout: Duration::from_secs(5),
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
    tunnel.stop();
    tunnel.stop();
}

#[test]
fn non_dns_udp_is_dropped() {
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
