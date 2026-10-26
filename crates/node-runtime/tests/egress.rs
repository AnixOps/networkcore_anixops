//! Domain egress routes between two nodes, as the panel sets them up: the
//! exit node serves a Shadowsocks-2022 relay, the source node sends the
//! route's domains there and everything else directly.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use engine_outbound::{TargetAddr, TcpDialer, TcpOutbound};
use node_runtime::{api, default_registry, Node};
use outbound_shadowsocks::{Method, Ss2022Outbound};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TIMEOUT: Duration = Duration::from_secs(10);
const TOKEN: &str = "test-token";
const SERVER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQ==";
const USER_KEY: &str = "AgICAgICAgICAgICAgICAg==";
const RELAY_KEY: &str = "BAQEBAQEBAQEBAQEBAQEBA==";

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

async fn start_api() -> SocketAddr {
    let node = Arc::new(Node::new(default_registry(), true));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(api::serve(listener, node, TOKEN.to_owned()));
    addr
}

async fn call(api: SocketAddr, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
    let body = body.map(|body| body.to_string()).unwrap_or_default();
    let mut stream = TcpStream::connect(api).await.unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: node\r\nAuthorization: Bearer {TOKEN}\r\nContent-Length: {}\r\n\r\n{body}",
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

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// Opens `target` through the source node, sends `first` and reads it back.
async fn round_trip(server: SocketAddr, target: TargetAddr, first: &[u8]) {
    let client = Ss2022Outbound::new(
        server.ip().to_string(),
        server.port(),
        Method::Aes128Gcm,
        &format!("{SERVER_KEY}:{USER_KEY}"),
        Arc::new(TcpDialer),
    )
    .unwrap();
    let mut stream = client.connect(&target).await.unwrap();
    stream.write_all(first).await.unwrap();
    let mut received = vec![0u8; first.len()];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut received))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(received, first);
}

async fn relay_accepted(exit: SocketAddr) -> u64 {
    let (status, body) = call(exit, "GET", "/v1/egress", None).await;
    assert_eq!(status, 200, "{body}");
    body["relays"][0]["accepted"].as_u64().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn routes_domains_through_the_exit_relay() {
    let target = echo_server().await;
    let (exit, source) = (start_api().await, start_api().await);
    let relay_port = free_port();

    let relay = json!({"id": 7, "protocol": "shadowsocks", "port": relay_port,
                       "method": "2022-blake3-aes-128-gcm", "password": RELAY_KEY});
    let (status, body) = call(exit, "PUT", "/v1/egress", Some(json!({"relays": [relay]}))).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["relays"][0]["id"], 7);
    assert!(!body.to_string().contains(RELAY_KEY));

    let route = json!({"routes": [{"id": 7, "domains": ["localhost", "keyword:never"],
        "server": {"protocol": "shadowsocks", "host": "127.0.0.1", "port": relay_port,
                   "method": "2022-blake3-aes-128-gcm", "password": RELAY_KEY}}]});
    let (status, body) = call(source, "PUT", "/v1/egress", Some(route.clone())).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["routes"], json!([7]));
    let inbound = json!({
        "tag": "ss", "type": "shadowsocks", "listen": "127.0.0.1", "listen_port": 0,
        "method": "2022-blake3-aes-128-gcm", "password": SERVER_KEY,
        "users": [{"name": "1001", "password": USER_KEY}]
    });
    let (status, body) = call(source, "POST", "/v1/inbounds", Some(inbound)).await;
    assert_eq!(status, 201, "{body}");
    let server: SocketAddr = body["listen"].as_str().unwrap().parse().unwrap();

    // A name the route matches goes through the relay.
    let named = TargetAddr::Domain("localhost".into(), target.port());
    round_trip(server, named, b"by name").await;
    assert_eq!(relay_accepted(exit).await, 1);

    // An address with an HTTP Host the route matches does too.
    let request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    round_trip(server, TargetAddr::Ip(target), request).await;
    assert_eq!(relay_accepted(exit).await, 2);

    // Other traffic leaves directly.
    round_trip(server, TargetAddr::Ip(target), b"plain bytes").await;
    let other = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
    round_trip(server, TargetAddr::Ip(target), other).await;
    assert_eq!(relay_accepted(exit).await, 2);

    // Applying the same relay again keeps it (and its counters).
    let (status, _) = call(exit, "PUT", "/v1/egress", Some(json!({"relays": [relay]}))).await;
    assert_eq!(status, 200);
    assert_eq!(relay_accepted(exit).await, 2);

    // An invalid body changes nothing; `{}` removes everything.
    let bad = json!({"routes": [{"id": 8, "domains": ["geosite:x"], "server": route["routes"][0]["server"]}]});
    let (status, body) = call(source, "PUT", "/v1/egress", Some(bad)).await;
    assert_eq!(status, 400, "{body}");
    assert!(!body.to_string().contains(RELAY_KEY));
    let (_, body) = call(source, "GET", "/v1/egress", None).await;
    assert_eq!(body["routes"], json!([7]));
    let (status, body) = call(source, "PUT", "/v1/egress", Some(json!({}))).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["routes"], json!([]));
    let named = TargetAddr::Domain("localhost".into(), target.port());
    round_trip(server, named, b"direct again").await;
    assert_eq!(relay_accepted(exit).await, 2);

    let (status, body) = call(exit, "PUT", "/v1/egress", Some(json!({}))).await;
    assert_eq!(status, 200);
    assert_eq!(body["relays"], json!([]));
    assert!(tokio::net::TcpStream::connect(("127.0.0.1", relay_port))
        .await
        .is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_on_a_taken_port_fails_alone() {
    let api = start_api().await;
    // An inbound on every address holds the port, as a relay would.
    let inbound = json!({"tag": "ss", "type": "shadowsocks", "listen_port": 0,
                         "method": "2022-blake3-aes-128-gcm", "password": SERVER_KEY});
    let (status, body) = call(api, "POST", "/v1/inbounds", Some(inbound)).await;
    assert_eq!(status, 201, "{body}");
    let taken: SocketAddr = body["listen"].as_str().unwrap().parse().unwrap();
    let taken_port = taken.port();
    let free = free_port();
    let relay = |id: u64, port: u16| {
        json!({"id": id, "port": port, "method": "2022-blake3-aes-128-gcm", "password": RELAY_KEY})
    };
    let body = json!({"relays": [relay(1, taken_port), relay(2, free)]});
    let (status, body) = call(api, "PUT", "/v1/egress", Some(body)).await;
    assert_eq!(status, 500, "{body}");
    assert!(body["error"].as_str().unwrap().contains("egress relay 1"));
    let (_, body) = call(api, "GET", "/v1/egress", None).await;
    assert_eq!(body["relays"].as_array().unwrap().len(), 1);
    assert_eq!(body["relays"][0]["id"], 2);
}
