//! Proxy chains (`via`, docs/architecture/outbound-via.md): the config
//! checks, and a Shadowsocks-2022 node reached through an iWAN line.
//!
//! `inbound-iwan` stands in for the Panabit line: its TCP and UDP outbounds
//! act as the line's NAT exit, which reaches the 落地 node at [`LAND`] (in
//! fact a Shadowsocks-2022 server on loopback) and records every target.

#![cfg(all(feature = "shadowsocks", feature = "iwan"))]

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use engine_embedded::config::RuntimeConfig;
use engine_embedded::protocols::default_registry;
use engine_embedded::routing::RoutedOutbound;
use engine_inbound::registry::{PacketInboundFactory, Settings};
use engine_inbound::server::{serve, InboundStats, ServeSettings};
use engine_inbound::udp::{BoundUdpOutbound, UdpOutbound, UdpSession};
use engine_inbound::{PacketInbound, StreamInbound};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpDialer, TcpOutbound};
use inbound_iwan::IwanInboundFactory;
use inbound_shadowsocks::{Method, Ss2022Inbound};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

/// The 落地 node's public address as the line's exit sees it.
const LAND: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);
const WAIT: Duration = Duration::from_secs(10);

type Targets = Arc<Mutex<Vec<TargetAddr>>>;

fn envelope(outbounds: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema_version": 1,
        "profile_id": "via",
        "routing": {"outbounds": outbounds, "rules": ["FINAL,a"]},
    }))
    .unwrap()
}

fn build_routed(bytes: &[u8]) -> Result<Arc<RoutedOutbound>, &'static str> {
    let config = RuntimeConfig::from_json(bytes).map_err(|error| error.message)?;
    config
        .build_routed(&default_registry(), Arc::new(TcpDialer))
        .map(|routed| routed.expect("a routing config"))
        .map_err(|error| error.message)
}

fn rejection(outbounds: serde_json::Value) -> &'static str {
    match build_routed(&envelope(outbounds)) {
        Ok(_) => panic!("the config should be rejected"),
        Err(message) => message,
    }
}

fn direct_via(via: &str) -> serde_json::Value {
    json!({"type": "direct", "via": via})
}

#[test]
fn via_must_name_a_routing_outbound() {
    for via in ["missing", "DIRECT", "REJECT"] {
        let message = rejection(json!({"a": direct_via(via)}));
        assert!(message.contains("does not exist"), "{via}: {message}");
    }
}

#[test]
fn via_loops_are_rejected() {
    let message = rejection(json!({"a": direct_via("b"), "b": direct_via("a")}));
    assert!(message.contains("loop"), "{message}");
    let message = rejection(json!({"a": direct_via("a")}));
    assert!(message.contains("loop"), "{message}");
}

#[test]
fn via_chains_are_at_most_four_outbounds() {
    let four = json!({
        "a": direct_via("b"),
        "b": direct_via("c"),
        "c": direct_via("d"),
        "d": {"type": "direct"},
    });
    assert!(build_routed(&envelope(four)).is_ok());
    let five = json!({
        "a": direct_via("b"),
        "b": direct_via("c"),
        "c": direct_via("d"),
        "d": direct_via("e"),
        "e": {"type": "direct"},
    });
    assert!(rejection(five).contains("longer than 4"));
    // An inline via counts too.
    let inline = json!({
        "a": direct_via("b"),
        "b": direct_via("c"),
        "c": {"type": "direct", "via": {"type": "direct", "via": {"type": "direct"}}},
    });
    assert!(rejection(inline).contains("longer than 4"));
}

#[test]
fn protocols_with_their_own_sockets_cannot_use_a_via() {
    let mut kinds = vec!["iwan"];
    if cfg!(feature = "hysteria2") {
        kinds.push("hysteria2");
    }
    if cfg!(feature = "tuic") {
        kinds.push("tuic");
    }
    for kind in kinds {
        let message = rejection(json!({
            "a": {"type": kind, "via": "b"},
            "b": {"type": "direct"},
        }));
        assert!(message.contains("own sockets"), "{kind}: {message}");
    }
}

#[test]
fn a_single_outbound_takes_only_an_inline_via() {
    let registry = default_registry();
    let single = |outbound: serde_json::Value| {
        let bytes = serde_json::to_vec(&json!({
            "schema_version": 1,
            "profile_id": "via",
            "outbound": outbound,
        }))
        .unwrap();
        RuntimeConfig::from_json(&bytes)
            .unwrap()
            .build_outbound(&registry, Arc::new(TcpDialer))
            .map(|_| ())
            .map_err(|error| error.message)
    };
    assert!(single(json!({"type": "direct", "via": {"type": "direct"}})).is_ok());
    let message = single(direct_via("other")).unwrap_err();
    assert!(message.contains("only in routing"), "{message}");
}

fn key() -> String {
    base64::engine::general_purpose::STANDARD.encode([7u8; 16])
}

struct Direct;

impl TcpOutbound for Direct {
    fn protocol(&self) -> &'static str {
        "direct"
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let stream = TcpStream::connect((target.host(), target.port())).await?;
            Ok(Box::new(stream) as BoxStream)
        })
    }
}

/// The line's NAT exit for TCP: [`LAND`] is the loopback server.
struct ExitTcp {
    targets: Targets,
}

impl TcpOutbound for ExitTcp {
    fn protocol(&self) -> &'static str {
        "exit"
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            self.targets.lock().unwrap().push(target.clone());
            let port = land_port(target)?;
            let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await?;
            Ok(Box::new(stream) as BoxStream)
        })
    }
}

fn land_port(target: &TargetAddr) -> io::Result<u16> {
    match target {
        TargetAddr::Ip(address) if address.ip() == LAND => Ok(address.port()),
        _ => Err(io::ErrorKind::ConnectionRefused.into()),
    }
}

/// The line's NAT exit for UDP.
struct ExitUdp {
    targets: Targets,
}

impl UdpOutbound for ExitUdp {
    fn bind(&self) -> BoxFuture<'_, io::Result<Arc<dyn UdpSession>>> {
        Box::pin(async move {
            let socket = UdpSocket::bind("127.0.0.1:0").await?;
            Ok(Arc::new(ExitSession {
                socket,
                targets: self.targets.clone(),
            }) as Arc<dyn UdpSession>)
        })
    }
}

struct ExitSession {
    socket: UdpSocket,
    targets: Targets,
}

impl UdpSession for ExitSession {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        target: &'a TargetAddr,
    ) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            self.targets.lock().unwrap().push(target.clone());
            let port = land_port(target)?;
            self.socket
                .send_to(payload, (Ipv4Addr::LOCALHOST, port))
                .await
                .map(|_| ())
        })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, io::Result<(usize, SocketAddr)>> {
        Box::pin(async move {
            let (len, from) = self.socket.recv_from(buf).await?;
            Ok((len, SocketAddr::from((LAND, from.port()))))
        })
    }
}

async fn tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    address
}

async fn udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((len, from)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..len], from).await;
        }
    });
    address
}

/// The 落地 node: Shadowsocks-2022 on one loopback port for TCP and UDP.
async fn start_land() -> (u16, Arc<InboundStats>) {
    let inbound = Arc::new(Ss2022Inbound::new(Method::Aes128Gcm, &key(), false).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let stats = Arc::new(InboundStats::default());
    tokio::spawn(serve(
        listener,
        inbound.clone(),
        Arc::new(Direct),
        ServeSettings::default(),
        stats.clone(),
    ));
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
    tokio::spawn(inbound.datagram().expect("udp side").serve(
        socket,
        Arc::new(BoundUdpOutbound::new("127.0.0.1:0".parse().unwrap())),
        stats.clone(),
    ));
    (port, stats)
}

/// The iWAN line; returns its port and the targets its exit reached.
fn start_line() -> (u16, Targets, Targets) {
    let settings: Settings = serde_json::from_value(json!({
        "pool": "10.66.0.0/24",
        "mtu": 1400,
        "dns_upstream": "192.0.2.53:53",
        "users": [{"name": "1001", "username": "alice", "password": "pw-alice"}],
    }))
    .unwrap();
    let line: Arc<dyn PacketInbound> = IwanInboundFactory.build(&settings).ok().unwrap();
    let tcp_targets = Targets::default();
    let udp_targets = Targets::default();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    tokio::spawn(line.serve(
        socket,
        Arc::new(ExitTcp {
            targets: tcp_targets.clone(),
        }),
        Some(Arc::new(ExitUdp {
            targets: udp_targets.clone(),
        })),
        ServeSettings::default(),
        Arc::new(InboundStats::default()),
    ));
    (port, tcp_targets, udp_targets)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shadowsocks_node_runs_through_an_iwan_line() {
    let echo = tcp_echo().await;
    let echo_udp = udp_echo().await;
    let (land_port, land_stats) = start_land().await;
    let (line_port, tcp_targets, udp_targets) = start_line();
    let land = TargetAddr::Ip(SocketAddr::from((LAND, land_port)));

    let routed = build_routed(&envelope(json!({
        "a": {
            "type": "shadowsocks",
            "server": LAND.to_string(),
            "port": land_port,
            "method": "2022-blake3-aes-128-gcm",
            "password": key(),
            "via": "line",
        },
        "line": {
            "type": "iwan",
            "server": "127.0.0.1",
            "port": line_port,
            "username": "alice",
            "password": "pw-alice",
        },
    })))
    .unwrap();

    let mut stream = timeout(WAIT, routed.connect(&TargetAddr::Ip(echo)))
        .await
        .expect("connect timed out")
        .expect("connect through the line");
    let payload = b"from the app, through the line, out of the land node";
    stream.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    timeout(WAIT, stream.read_exact(&mut echoed))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(&echoed, payload);
    assert_eq!(
        tcp_targets.lock().unwrap().as_slice(),
        std::slice::from_ref(&land),
        "the line's exit dialed the land node and nothing else"
    );

    let mut flow = timeout(WAIT, routed.open_udp(&TargetAddr::Ip(echo_udp)))
        .await
        .expect("udp open timed out")
        .expect("udp through the line");
    let reply = timeout(WAIT, async {
        loop {
            flow.send.send(b"datagram").await.unwrap();
            if let Ok(reply) = timeout(Duration::from_millis(500), flow.recv.recv()).await {
                break reply.unwrap();
            }
        }
    })
    .await
    .expect("udp echo timed out");
    assert_eq!(reply, b"datagram");
    assert!(
        udp_targets
            .lock()
            .unwrap()
            .iter()
            .all(|target| *target == land),
        "the line's exit sent datagrams only to the land node"
    );
    assert!(!udp_targets.lock().unwrap().is_empty());
    assert!(
        land_stats.accepted.load(Ordering::Relaxed) > 0,
        "the land node served the chain"
    );
}
