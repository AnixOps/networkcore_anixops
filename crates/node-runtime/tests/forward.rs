//! Fixed-target forwards (`"type": "forward"`), as a panel forwarding rule
//! creates them: TCP and UDP to one target, through the inbound's base
//! outbound, with per-inbound traffic from the management API.

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
               "outbound": "anx-line:7",
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
