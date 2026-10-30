//! Fixed-target forwards (`"type": "forward"`), as a panel forwarding rule
//! creates them: TCP and UDP to one target, through the inbound's base
//! outbound, with per-inbound traffic and target health from the management
//! API.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use node_runtime::{api, default_registry, DirectOutbound, Node, NodeOutbound};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const TIMEOUT: Duration = Duration::from_secs(10);
const TOKEN: &str = "test-token";

/// Connects directly and counts the connections it opened.
struct Counting {
    direct: DirectOutbound,
    connects: AtomicU64,
}

impl TcpOutbound for Counting {
    fn protocol(&self) -> &'static str {
        "counting"
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, std::io::Result<BoxStream>> {
        self.connects.fetch_add(1, Ordering::Relaxed);
        self.direct.connect(target)
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

/// Answers every datagram with itself.
async fn udp_echo_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], peer).await;
        }
    });
    addr
}

async fn start_api(node: Node) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(api::serve(listener, Arc::new(node), TOKEN.to_owned()));
    addr
}

/// One HTTP request; returns the status and the JSON body.
async fn call(api: SocketAddr, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
    let body = body.map(|body| body.to_string()).unwrap_or_default();
    let mut stream = TcpStream::connect(api).await.unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: node\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(TIMEOUT, stream.read_to_end(&mut response))
        .await
        .expect("api timed out")
        .unwrap();
    let response = String::from_utf8(response).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, serde_json::from_str(body).unwrap())
}

async fn add_forward(api: SocketAddr, config: Value) -> SocketAddr {
    let (status, body) = call(api, "POST", "/v1/inbounds", Some(config)).await;
    assert_eq!(status, 201, "{body}");
    body["listen"].as_str().unwrap().parse().unwrap()
}

async fn tcp_round_trip(server: SocketAddr, payload: &[u8]) {
    let mut stream = TcpStream::connect(server).await.unwrap();
    stream.write_all(payload).await.unwrap();
    let mut received = vec![0u8; payload.len()];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut received))
        .await
        .expect("tcp echo timed out")
        .unwrap();
    assert_eq!(received, payload);
}

async fn udp_round_trip(server: SocketAddr, payload: &[u8]) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buf = vec![0u8; 2048];
    // UDP may drop the first datagram while the session opens; retry.
    for _ in 0..5 {
        socket.send_to(payload, server).await.unwrap();
        if let Ok(Ok((n, source))) =
            tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await
        {
            assert_eq!(&buf[..n], payload);
            assert_eq!(source.port(), server.port());
            return;
        }
    }
    panic!("udp echo timed out");
}

async fn inbound_traffic(api: SocketAddr, tag: &str, reset: bool) -> (u64, u64) {
    let query = if reset { "?reset=true" } else { "" };
    let (status, body) = call(
        api,
        "GET",
        &format!("/v1/inbounds/{tag}/traffic{query}"),
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["traffic"], json!([]));
    (
        body["inbound"]["up"].as_u64().unwrap(),
        body["inbound"]["down"].as_u64().unwrap(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwards_tcp_and_udp_to_a_private_target() {
    // Private targets are refused for users, but a forward's own target is
    // the operator's and goes through.
    let api = start_api(Node::new(default_registry(), false)).await;
    let tcp_target = echo_server().await;
    let udp_target = udp_echo_server().await;

    let (_, body) = call(api, "GET", "/v1/status", None).await;
    assert!(body["types"]
        .as_array()
        .unwrap()
        .contains(&json!("forward")));

    let tcp = add_forward(
        api,
        json!({"tag": "f-tcp", "type": "forward", "listen": "127.0.0.1", "listen_port": 0,
               "server": "127.0.0.1", "server_port": tcp_target.port(), "network": "tcp"}),
    )
    .await;
    tcp_round_trip(tcp, b"forwarded over tcp").await;

    let udp = add_forward(
        api,
        json!({"tag": "f-udp", "type": "forward", "listen": "127.0.0.1", "listen_port": 0,
               "server": "127.0.0.1", "server_port": udp_target.port()}),
    )
    .await;
    udp_round_trip(udp, b"forwarded over udp").await;

    // The relay charges a write just after handing it to the socket.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(inbound_traffic(api, "f-tcp", true).await, (18, 18));
    assert_eq!(inbound_traffic(api, "f-tcp", false).await, (0, 0));
    tcp_round_trip(tcp, b"again").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(inbound_traffic(api, "f-tcp", false).await, (5, 5));
    let (up, down) = inbound_traffic(api, "f-udp", true).await;
    // Retries may have sent the datagram more than once.
    assert!(up >= 18 && up % 18 == 0, "udp up {up}");
    assert!(down >= 18 && down % 18 == 0, "udp down {down}");

    // A forward has no users.
    let (status, _) = call(
        api,
        "POST",
        "/v1/inbounds/f-tcp/users",
        Some(json!({"users": [{"name": "1001", "password": "x"}]})),
    )
    .await;
    assert_eq!(status, 400);
    let (status, _) = call(
        api,
        "POST",
        "/v1/inbounds",
        Some(json!({"tag": "bad", "type": "forward", "listen_port": 0, "server": "127.0.0.1"})),
    )
    .await;
    assert_eq!(status, 400);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwards_through_the_named_outbound() {
    let target = echo_server().await;
    let counting = Arc::new(Counting {
        direct: DirectOutbound::new(true, Vec::new()),
        connects: AtomicU64::new(0),
    });
    let udp = Arc::new(DirectOutbound::new(true, Vec::new()));
    let node = Node::new(default_registry(), false)
        .with_outbound("anx-line:7", NodeOutbound::new(counting.clone(), udp));
    let api = start_api(node).await;

    let server = add_forward(
        api,
        json!({"tag": "rule-7", "type": "forward", "listen": "127.0.0.1", "listen_port": 0,
               "outbound": "anx-line:7", "health": {"disabled": true},
               "server": "127.0.0.1", "server_port": target.port()}),
    )
    .await;
    tcp_round_trip(server, b"through the line").await;
    assert_eq!(counting.connects.load(Ordering::Relaxed), 1);

    let (_, body) = call(api, "GET", "/v1/inbounds", None).await;
    let rule = &body["inbounds"][0];
    assert_eq!(rule["type"], "forward");
    assert_eq!(rule["outbound"], "anx-line:7");
}

/// Accepts connections, answers each with `tag` and the first line it got,
/// then ends its side.
async fn tagged_server(tag: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut line = Vec::new();
                let mut byte = [0u8; 1];
                while stream.read_exact(&mut byte).await.is_ok() {
                    line.push(byte[0]);
                    if byte[0] == b'\n' {
                        break;
                    }
                }
                let mut reply = tag.as_bytes().to_vec();
                reply.push(b' ');
                reply.extend_from_slice(&line);
                let _ = stream.write_all(&reply).await;
                // Close after the client did: unread input would reset the
                // connection and could drop the reply.
                let _ = stream.shutdown().await;
                let _ = tokio::io::copy(&mut stream, &mut tokio::io::sink()).await;
            });
        }
    });
    addr
}

/// A port nothing listens on.
async fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// Sends `line` and returns what came back until the target closed.
async fn ask(server: SocketAddr, line: &[u8]) -> String {
    let mut stream = TcpStream::connect(server).await.unwrap();
    stream.write_all(line).await.unwrap();
    let mut reply = Vec::new();
    tokio::time::timeout(TIMEOUT, stream.read_to_end(&mut reply))
        .await
        .expect("reply timed out")
        .unwrap();
    String::from_utf8(reply).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn balances_over_several_targets() {
    let api = start_api(Node::new(default_registry(), false)).await;
    let (a, b) = (tagged_server("a").await, tagged_server("b").await);
    let dead = closed_port().await;

    // Round robin alternates.
    let server = add_forward(
        api,
        json!({"tag": "rr", "type": "forward", "listen": "127.0.0.1", "listen_port": 0,
               "network": "tcp", "balance": "round_robin",
               "targets": [{"server": "127.0.0.1", "server_port": a.port()},
                           {"server": "127.0.0.1", "server_port": b.port()}]}),
    )
    .await;
    let mut tags = Vec::new();
    for _ in 0..4 {
        tags.push(ask(server, b"hi\n").await);
    }
    assert_eq!(tags.iter().filter(|tag| tag.starts_with("a ")).count(), 2);
    assert_eq!(tags.iter().filter(|tag| tag.starts_with("b ")).count(), 2);
    assert_ne!(tags[0], tags[1]);

    // Failover skips a target that does not answer, on the same connection.
    let server = add_forward(
        api,
        json!({"tag": "fo", "type": "forward", "listen": "127.0.0.1", "listen_port": 0,
               "network": "tcp", "balance": "failover", "health": {"disabled": true},
               "targets": [{"server": "127.0.0.1", "server_port": dead, "priority": 0},
                           {"server": "127.0.0.1", "server_port": b.port(), "priority": 1}]}),
    )
    .await;
    for _ in 0..4 {
        assert_eq!(ask(server, b"hi\n").await, "b hi\n");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn writes_the_proxy_protocol_header() {
    let api = start_api(Node::new(default_registry(), false)).await;
    let target = tagged_server("t").await;
    let server = add_forward(
        api,
        json!({"tag": "pp", "type": "forward", "listen": "127.0.0.1", "listen_port": 0,
               "network": "tcp", "proxy_protocol": "v1",
               "server": "127.0.0.1", "server_port": target.port()}),
    )
    .await;
    let mut stream = TcpStream::connect(server).await.unwrap();
    let client = stream.local_addr().unwrap();
    stream.write_all(b"payload\n").await.unwrap();
    let mut reply = Vec::new();
    tokio::time::timeout(TIMEOUT, stream.read_to_end(&mut reply))
        .await
        .expect("reply timed out")
        .unwrap();
    // The target's first line is the header, ahead of the client's bytes.
    assert_eq!(
        String::from_utf8(reply).unwrap(),
        format!(
            "t PROXY TCP4 127.0.0.1 127.0.0.1 {} {}\r\n",
            client.port(),
            server.port()
        )
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caps_concurrent_connections() {
    let api = start_api(Node::new(default_registry(), false)).await;
    let target = echo_server().await;
    let server = add_forward(
        api,
        json!({"tag": "cap", "type": "forward", "listen": "127.0.0.1", "listen_port": 0,
               "network": "tcp", "max_conns": 1, "bandwidth_bps": 80_000_000,
               "server": "127.0.0.1", "server_port": target.port()}),
    )
    .await;
    let mut first = TcpStream::connect(server).await.unwrap();
    first.write_all(b"one").await.unwrap();
    let mut buf = [0u8; 3];
    tokio::time::timeout(TIMEOUT, first.read_exact(&mut buf))
        .await
        .expect("first timed out")
        .unwrap();

    // The second is closed while the first is open.
    let mut second = TcpStream::connect(server).await.unwrap();
    let _ = second.write_all(b"two").await;
    let mut rest = Vec::new();
    let read = tokio::time::timeout(TIMEOUT, second.read_to_end(&mut rest))
        .await
        .expect("second was not closed");
    assert!(read.is_err() || rest.is_empty());

    drop(first);
    tokio::time::sleep(Duration::from_millis(300)).await;
    tcp_round_trip(server, b"three").await;
}

async fn target_health(api: SocketAddr, tag: &str) -> Vec<Value> {
    let (status, body) = call(api, "GET", &format!("/v1/inbounds/{tag}/targets"), None).await;
    assert_eq!(status, 200, "{body}");
    body["targets"].as_array().unwrap().clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reports_target_health() {
    let api = start_api(Node::new(default_registry(), false)).await;
    let live = echo_server().await;
    let dead = closed_port().await;
    add_forward(
        api,
        json!({"tag": "hc", "type": "forward", "listen": "127.0.0.1", "listen_port": 0,
               "network": "tcp", "health": {"interval_ms": 50, "timeout_ms": 1000},
               "circuit_breaker": {"failure_threshold": 2, "open_ms": 60000},
               "targets": [{"server": "127.0.0.1", "server_port": live.port()},
                           {"server": "127.0.0.1", "server_port": dead}]}),
    )
    .await;
    // One target is checked too.
    add_forward(
        api,
        json!({"tag": "one", "type": "forward", "listen": "127.0.0.1", "listen_port": 0,
               "network": "tcp", "health": {"interval_ms": 50},
               "server": "127.0.0.1", "server_port": live.port()}),
    )
    .await;

    let deadline = tokio::time::Instant::now() + TIMEOUT;
    loop {
        let targets = target_health(api, "hc").await;
        let one = target_health(api, "one").await;
        if targets[1]["state"] == "circuit_open" && one[0]["state"] == "healthy" {
            assert_eq!(targets[0]["address"], "127.0.0.1");
            assert_eq!(targets[0]["port"], live.port());
            assert_eq!(targets[0]["state"], "healthy");
            assert!(targets[0]["rtt_us"].as_u64().unwrap() > 0);
            assert!(targets[0]["checked_at_unix_ms"].as_u64().unwrap() > 0);
            assert_eq!(targets[1]["port"], dead);
            assert_eq!(targets[1]["rtt_us"], 0);
            assert!(targets[1]["consecutive_failures"].as_u64().unwrap() >= 2);
            assert!(targets[1]["circuit_open_until_unix_ms"].as_u64().unwrap() > 0);
            assert!(one[0]["rtt_us"].as_u64().unwrap() > 0);
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "health never settled: {targets:?} {one:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // A UDP-only forward runs no checks; its target stays unknown.
    add_forward(
        api,
        json!({"tag": "u", "type": "forward", "listen": "127.0.0.1", "listen_port": 0,
               "network": "udp", "server": "127.0.0.1", "server_port": dead}),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(target_health(api, "u").await[0]["state"], "unknown");

    let (status, _) = call(api, "GET", "/v1/inbounds/missing/targets", None).await;
    assert_eq!(status, 404);
}
