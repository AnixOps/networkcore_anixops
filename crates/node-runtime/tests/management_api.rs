//! Drives a node through the management API the way a node agent does:
//! create an inbound, add and remove users, read traffic and online IPs.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use engine_inbound::server::ServeSettings;
use engine_outbound::{TargetAddr, TcpDialer, TcpOutbound};
use node_runtime::{api, default_registry, Node};
use outbound_shadowsocks::{Method, Ss2022Outbound};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TIMEOUT: Duration = Duration::from_secs(10);
const TOKEN: &str = "test-token";
const SERVER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQ==";
const ALICE_KEY: &str = "AgICAgICAgICAgICAgICAg==";
const BOB_KEY: &str = "AwMDAwMDAwMDAwMDAwMDAw==";

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

async fn start_api(allow_private_targets: bool) -> SocketAddr {
    let node = Arc::new(
        Node::new(default_registry(), allow_private_targets).with_serve_settings(ServeSettings {
            reject_hold: Duration::from_millis(200),
            ..ServeSettings::default()
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(api::serve(listener, node, TOKEN.to_owned()));
    addr
}

/// One HTTP request; returns the status and the JSON body.
async fn call(api: SocketAddr, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
    call_with_token(api, method, path, body, TOKEN).await
}

async fn call_with_token(
    api: SocketAddr,
    method: &str,
    path: &str,
    body: Option<Value>,
    token: &str,
) -> (u16, Value) {
    let body = body.map(|body| body.to_string()).unwrap_or_default();
    let mut stream = TcpStream::connect(api).await.unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: node\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
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

fn client(server: SocketAddr, user_key: &str) -> Ss2022Outbound {
    Ss2022Outbound::new(
        server.ip().to_string(),
        server.port(),
        Method::Aes128Gcm,
        &format!("{SERVER_KEY}:{user_key}"),
        Arc::new(TcpDialer),
    )
    .unwrap()
}

async fn echo(
    outbound: &Ss2022Outbound,
    target: SocketAddr,
    payload: &[u8],
) -> std::io::Result<()> {
    echo_to(outbound, &TargetAddr::Ip(target), payload).await
}

async fn echo_to(
    outbound: &Ss2022Outbound,
    target: &TargetAddr,
    payload: &[u8],
) -> std::io::Result<()> {
    let mut stream = outbound.connect(target).await?;
    stream.write_all(payload).await?;
    let mut received = vec![0u8; payload.len()];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut received))
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
    assert_eq!(received, payload);
    Ok(())
}

fn ss_inbound(tag: &str) -> Value {
    json!({
        "tag": tag,
        "type": "shadowsocks",
        "listen": "127.0.0.1",
        "listen_port": 0,
        "method": "2022-blake3-aes-128-gcm",
        "password": SERVER_KEY,
        "users": [{"name": "1001", "password": ALICE_KEY}]
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_workflow() {
    let api = start_api(true).await;
    let target = echo_server().await;

    let (status, body) = call(api, "GET", "/v1/status", None).await;
    assert_eq!(status, 200);
    assert!(body["types"]
        .as_array()
        .unwrap()
        .contains(&json!("shadowsocks")));
    assert!(body["features"]
        .as_array()
        .unwrap()
        .contains(&json!("user_limits")));
    assert!(body["features"]
        .as_array()
        .unwrap()
        .contains(&json!("block_rules")));
    assert!(body["features"].as_array().unwrap().contains(&json!("qos")));

    // Traffic priorities: an invalid entry refuses the body, a valid one
    // answers its classes, `{}` turns them off.
    let (status, _) = call(
        api,
        "PUT",
        "/v1/qos",
        Some(json!({"classes": [{"priority": "low", "domains": ["bad domain"]}]})),
    )
    .await;
    assert_eq!(status, 400);
    let (status, body) = call(
        api,
        "PUT",
        "/v1/qos",
        Some(json!({"classes": [{"name": "steam", "priority": "low", "limit_mbps": 5, "domains": ["qos-test.invalid"]}]})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["active"], json!(true));
    assert_eq!(body["classes"][0]["limit_mbps"], json!(5));
    assert_eq!(body["classes"][0]["domains"], json!(1));
    let (status, body) = call(api, "PUT", "/v1/qos", Some(json!({}))).await;
    assert_eq!(status, 200, "{body}");
    let (_, body) = call(api, "GET", "/v1/qos", None).await;
    assert_eq!(body["active"], json!(false));

    let (status, body) = call(api, "POST", "/v1/inbounds", Some(ss_inbound("ss"))).await;
    assert_eq!(status, 201, "{body}");
    let server: SocketAddr = body["listen"].as_str().unwrap().parse().unwrap();
    let (status, _) = call(api, "POST", "/v1/inbounds", Some(ss_inbound("ss"))).await;
    assert_eq!(status, 409);

    echo(&client(server, ALICE_KEY), target, b"alice")
        .await
        .unwrap();
    assert!(echo(&client(server, BOB_KEY), target, b"bob")
        .await
        .is_err());

    let (status, body) = call(
        api,
        "POST",
        "/v1/inbounds/ss/users",
        Some(json!({"users": [{"name": "1002", "password": BOB_KEY}]})),
    )
    .await;
    assert_eq!((status, body["users"].as_u64()), (200, Some(1)));
    let bob = client(server, BOB_KEY);
    let mut open = bob.connect(&TargetAddr::Ip(target)).await.unwrap();
    open.write_all(b"bob!").await.unwrap();
    let mut buf = [0u8; 4];
    open.read_exact(&mut buf).await.unwrap();

    let (_, body) = call(api, "GET", "/v1/inbounds/ss/online", None).await;
    let online = body["online"].as_array().unwrap();
    assert!(online
        .iter()
        .any(|entry| entry["name"] == "1002" && entry["ip"] == "127.0.0.1"));

    // The relay charges a write just after handing it to the socket, so the
    // client can see the echo a moment before it is counted.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (_, body) = call(api, "GET", "/v1/inbounds/ss/traffic?reset=true", None).await;
    let mut traffic: Vec<(String, u64, u64)> = body["traffic"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry["name"].as_str().unwrap().to_owned(),
                entry["up"].as_u64().unwrap(),
                entry["down"].as_u64().unwrap(),
            )
        })
        .collect();
    traffic.sort();
    assert_eq!(traffic, vec![("1001".into(), 5, 5), ("1002".into(), 4, 4)]);
    assert_eq!(body["inbound"], json!({"up": 9, "down": 9}));
    let (_, body) = call(api, "GET", "/v1/inbounds/ss/traffic", None).await;
    assert_eq!(body["inbound"], json!({"up": 0, "down": 0}));
    assert!(body["traffic"]
        .as_array()
        .unwrap()
        .iter()
        .all(|entry| entry["up"] == 0 && entry["down"] == 0));

    let (status, body) = call(
        api,
        "POST",
        "/v1/inbounds/ss/users/remove",
        Some(json!({"names": ["1002", "nobody"]})),
    )
    .await;
    assert_eq!((status, body["removed"].as_u64()), (200, Some(1)));
    let read = tokio::time::timeout(TIMEOUT, open.read(&mut buf))
        .await
        .expect("removed user's connection should close");
    assert!(matches!(read, Ok(0) | Err(_)));

    let (_, body) = call(api, "GET", "/v1/inbounds", None).await;
    assert_eq!(body["inbounds"][0]["tag"], "ss");
    assert_eq!(body["inbounds"][0]["users"], 1);

    let (status, _) = call(api, "DELETE", "/v1/inbounds/ss", None).await;
    assert_eq!(status, 200);
    let (status, _) = call(api, "GET", "/v1/inbounds/ss/users", None).await;
    assert_eq!(status, 404);
    assert!(echo(&client(server, ALICE_KEY), target, b"gone")
        .await
        .is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_rules_refuse_domains_and_protocols() {
    let api = start_api(true).await;
    let target = echo_server().await;
    let (status, body) = call(api, "POST", "/v1/inbounds", Some(ss_inbound("ss"))).await;
    assert_eq!(status, 201, "{body}");
    let server: SocketAddr = body["listen"].as_str().unwrap().parse().unwrap();
    let alice = client(server, ALICE_KEY);
    let by_name = TargetAddr::Domain("localhost".into(), target.port());
    let http = b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n";

    let (status, body) = call(api, "GET", "/v1/rules", None).await;
    assert_eq!(status, 200);
    assert_eq!(body, json!({"block_domains": [], "block_protocols": []}));
    echo_to(&alice, &by_name, b"named").await.unwrap();
    echo(&alice, target, http).await.unwrap();

    let rules = json!({"block_domains": ["full:localhost"], "block_protocols": ["http"]});
    let (status, body) = call(api, "PUT", "/v1/rules", Some(rules.clone())).await;
    assert_eq!((status, &body), (200, &rules));
    assert!(echo_to(&alice, &by_name, b"named").await.is_err());
    assert!(echo(&alice, target, http).await.is_err());
    echo(&alice, target, b"not http").await.unwrap();

    // A bad entry is refused and the rules in force stay.
    let (status, _) = call(
        api,
        "PUT",
        "/v1/rules",
        Some(json!({"block_domains": ["regexp:("], "block_protocols": []})),
    )
    .await;
    assert_eq!(status, 400);
    let (status, _) = call(
        api,
        "PUT",
        "/v1/rules",
        Some(json!({"block_protocols": ["carrier-pigeon"]})),
    )
    .await;
    assert_eq!(status, 400);
    let (_, body) = call(api, "GET", "/v1/rules", None).await;
    assert_eq!(body, rules);

    let (status, _) = call(api, "PUT", "/v1/rules", Some(json!({}))).await;
    assert_eq!(status, 200);
    echo_to(&alice, &by_name, b"named").await.unwrap();
    echo(&alice, target, http).await.unwrap();
}

#[tokio::test]
async fn rejects_bad_requests() {
    let api = start_api(false).await;
    let (status, _) = call_with_token(api, "GET", "/v1/inbounds", None, "wrong").await;
    assert_eq!(status, 401);
    let (status, _) = call(api, "GET", "/v1/nothing", None).await;
    assert_eq!(status, 404);
    let mut unknown = ss_inbound("x");
    unknown["type"] = json!("carrier-pigeon");
    let (status, _) = call(api, "POST", "/v1/inbounds", Some(unknown)).await;
    assert_eq!(status, 400);
    let (status, _) = call(api, "POST", "/v1/inbounds", Some(ss_inbound("a/b"))).await;
    assert_eq!(status, 400);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_targets_are_refused_by_default() {
    let api = start_api(false).await;
    let target = echo_server().await;
    let (status, body) = call(api, "POST", "/v1/inbounds", Some(ss_inbound("ss"))).await;
    assert_eq!(status, 201);
    let server: SocketAddr = body["listen"].as_str().unwrap().parse().unwrap();
    assert!(echo(&client(server, ALICE_KEY), target, b"x")
        .await
        .is_err());
}
