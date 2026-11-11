//! Conditional fallbacks (`"fallbacks"`) of Trojan, AnyTLS and VLESS
//! inbounds behind TLS: a client that is not a user of the protocol reaches
//! the site that its server name, ALPN protocol and HTTP path select, with
//! the PROXY protocol header the rule asks for.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use engine_inbound::proxy_protocol::ProxyProtocol;
use node_runtime::{api, default_registry, Node};
use rcgen::{CertificateParams, KeyPair};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use transport_tls::{TlsConnector, TlsSettings};

const TIMEOUT: Duration = Duration::from_secs(10);
const TOKEN: &str = "test-token";
/// What every request of these tests ends with.
const END: &[u8] = b"\r\n\r\n";

/// A site behind a fallback: answers a request with `name` and every byte
/// that reached it, a PROXY protocol header included.
async fn site(name: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut got = Vec::new();
                let mut buf = [0u8; 1024];
                // A version 2 header starts with the bytes that end a
                // request, so the shortest request is read first.
                while got.len() < 16 || !got.ends_with(END) {
                    match stream.read(&mut buf).await {
                        Ok(n) if n > 0 => got.extend_from_slice(&buf[..n]),
                        _ => return,
                    }
                }
                let mut answer = name.as_bytes().to_vec();
                answer.extend_from_slice(&got);
                let _ = stream.write_all(&answer).await;
                // Close after the client did, as a reset could drop the
                // answer.
                let _ = stream.shutdown().await;
                let _ = tokio::io::copy(&mut stream, &mut tokio::io::sink()).await;
            });
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

/// Sends `request` over TLS, asking for `server_name` and offering `alpn`,
/// as a client that is no user of the inbound. Returns the client's address
/// and the answer.
async fn ask(
    server: SocketAddr,
    server_name: &str,
    alpn: &[&str],
    request: &[u8],
) -> (SocketAddr, Vec<u8>) {
    let connector = TlsConnector::new(&TlsSettings {
        server_name: server_name.into(),
        alpn: alpn.iter().map(|protocol| (*protocol).to_owned()).collect(),
        insecure: true,
    })
    .unwrap();
    let tcp = TcpStream::connect(server).await.unwrap();
    let client = tcp.local_addr().unwrap();
    let mut stream = connector.connect(Box::new(tcp)).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(TIMEOUT, stream.read_to_end(&mut answer)).await;
    (client, answer)
}

/// `parts` in a row, as text for readable failures.
fn text(parts: &[&[u8]]) -> String {
    String::from_utf8_lossy(&parts.concat()).into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_clients_reach_the_site_their_connection_selects() {
    // Private targets are refused for users, but the destinations of an
    // inbound's fallbacks are the operator's and go through.
    let api = start_api(Node::new(default_registry(), false)).await;
    let (_, status) = call(api, "GET", "/v1/status", None).await;
    assert!(status["features"]
        .as_array()
        .unwrap()
        .contains(&json!("fallbacks")));

    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["node.test".to_string(), "blog.test".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let default = site("default ").await;
    let h2 = site("h2 ").await;
    let ws = site("ws ").await;
    let blog = site("blog ").await;
    let blog_ws = site("blog-ws ").await;

    let get = b"GET / HTTP/1.1\r\n\r\n";
    let get_ws = b"GET /ws?ed=2048 HTTP/1.1\r\n\r\n";
    let preface = b"PRI * HTTP/2.0\r\n\r\n";
    for (kind, user) in [
        ("trojan", json!({"name": "u", "password": "secret"})),
        ("anytls", json!({"name": "u", "password": "secret"})),
        (
            "vless",
            json!({"name": "u", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"}),
        ),
    ] {
        let (status, body) = call(
            api,
            "POST",
            "/v1/inbounds",
            Some(json!({
                "tag": kind, "type": kind, "listen": "127.0.0.1", "listen_port": 0,
                "users": [user],
                "tls": {"certificate": cert.pem(), "key": key.serialize_pem(),
                        "alpn": ["h2", "http/1.1"]},
                "fallback": {"server": "127.0.0.1", "server_port": default.port()},
                "fallbacks": [
                    {"alpn": "h2", "dest": h2.port()},
                    {"path": "/ws", "dest": ws.to_string(), "xver": 1},
                    {"name": "blog.test", "dest": blog.port().to_string()},
                    {"name": "blog.test", "path": "/ws", "dest": blog_ws.to_string(), "xver": 2}
                ]
            })),
        )
        .await;
        assert_eq!(status, 201, "{kind}: {body}");
        let server: SocketAddr = body["listen"].as_str().unwrap().parse().unwrap();

        // No condition holds: the single `fallback`.
        let (_, answer) = ask(server, "node.test", &[], get).await;
        assert_eq!(text(&[&answer]), text(&[b"default ", get]), "{kind}");

        let (_, answer) = ask(server, "node.test", &["h2"], preface).await;
        assert_eq!(text(&[&answer]), text(&[b"h2 ", preface]), "{kind}");

        let (client, answer) = ask(server, "node.test", &["http/1.1"], get_ws).await;
        let header = format!(
            "PROXY TCP4 127.0.0.1 127.0.0.1 {} {}\r\n",
            client.port(),
            server.port()
        );
        assert_eq!(
            text(&[&answer]),
            text(&[b"ws ", header.as_bytes(), get_ws]),
            "{kind}"
        );

        let (_, answer) = ask(server, "blog.test", &[], get).await;
        assert_eq!(text(&[&answer]), text(&[b"blog ", get]), "{kind}");

        // Two conditions beat one, and the rule asks for a version 2 header.
        let (client, answer) = ask(server, "blog.test", &["http/1.1"], get_ws).await;
        let header = ProxyProtocol::V2.header(client, server);
        let expected: [&[u8]; 3] = [b"blog-ws ", &header, get_ws];
        assert_eq!(answer, expected.concat(), "{kind}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refuses_invalid_fallbacks() {
    let api = start_api(Node::new(default_registry(), false)).await;
    for fallbacks in [
        json!([{"dest": "nowhere"}]),
        json!([{"dest": 80, "xver": 3}]),
        json!([{"dest": 80, "path": "ws"}]),
        json!([{"alpn": "h2"}]),
    ] {
        let (status, body) = call(
            api,
            "POST",
            "/v1/inbounds",
            Some(
                json!({"tag": "bad", "type": "trojan", "listen": "127.0.0.1",
                        "listen_port": 0, "users": [], "fallbacks": fallbacks}),
            ),
        )
        .await;
        assert_eq!(status, 400, "{body}");
    }
}
