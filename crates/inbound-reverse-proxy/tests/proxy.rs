//! The reverse proxy behind the real serve loop, against small HTTP
//! upstreams on loopback.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use engine_inbound::registry::{InboundFactory, Settings};
use engine_inbound::server::{serve, InboundStats, ServeSettings};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use inbound_reverse_proxy::ReverseProxyInboundFactory;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TIMEOUT: Duration = Duration::from_secs(10);

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

/// Reads one request head and its `Content-Length` or chunked body.
async fn read_request(stream: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    let mut data = Vec::new();
    let mut byte = [0u8; 1];
    while !data.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await.ok()? == 0 {
            return None;
        }
        data.push(byte[0]);
    }
    let head = String::from_utf8(data).unwrap();
    let lower = head.to_ascii_lowercase();
    let mut body = Vec::new();
    if let Some(line) = lower.lines().find(|l| l.starts_with("content-length:")) {
        let n: usize = line[15..].trim().parse().unwrap();
        body.resize(n, 0);
        stream.read_exact(&mut body).await.ok()?;
    } else if lower.contains("transfer-encoding: chunked") {
        // Raw chunked bytes up to and including the last chunk.
        while !body.ends_with(b"0\r\n\r\n") {
            stream.read_exact(&mut byte).await.ok()?;
            body.push(byte[0]);
        }
    }
    Some((head, body))
}

/// Answers each request with `<name>` and the request head and body
/// echoed back, on a kept-alive connection; `/ws` upgrades and then echoes
/// raw bytes.
async fn start_upstream(name: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                while let Some((head, body)) = read_request(&mut stream).await {
                    if head.starts_with("GET /ws ") {
                        stream
                            .write_all(
                                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                            )
                            .await
                            .unwrap();
                        let (mut r, mut w) = stream.split();
                        let _ = tokio::io::copy(&mut r, &mut w).await;
                        return;
                    }
                    let mut payload = format!("{name}\n{head}").into_bytes();
                    payload.extend_from_slice(&body);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nX-Upstream: {name}\r\n\r\n",
                        payload.len()
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                    stream.write_all(&payload).await.unwrap();
                }
            });
        }
    });
    addr
}

async fn start_proxy(settings: String) -> SocketAddr {
    let settings: Settings = serde_json::from_str(&settings).unwrap();
    let inbound = ReverseProxyInboundFactory.build(&settings).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(
        listener,
        inbound,
        Arc::new(Direct),
        ServeSettings::default(),
        Arc::new(InboundStats::default()),
    ));
    addr
}

/// Reads one response; returns the head and body.
async fn read_response(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut data = Vec::new();
    let mut byte = [0u8; 1];
    while !data.ends_with(b"\r\n\r\n") {
        assert_eq!(stream.read(&mut byte).await.unwrap(), 1, "closed early");
        data.push(byte[0]);
    }
    let head = String::from_utf8(data).unwrap();
    let length = head
        .to_ascii_lowercase()
        .lines()
        .find(|l| l.starts_with("content-length:"))
        .map(|l| l[15..].trim().parse::<usize>().unwrap())
        .unwrap_or(0);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await.unwrap();
    (head, body)
}

fn settings(a: SocketAddr, b: SocketAddr) -> String {
    format!(
        r#"{{"sites":[
            {{"hosts":["a.example"],"routes":[
                {{"path":"/api","strip_prefix":true,
                  "upstreams":[{{"server":"127.0.0.1","server_port":{b}}}],
                  "headers":{{"X-Route":"api"}}}},
                {{"upstreams":[{{"server":"127.0.0.1","server_port":{a}}}]}}]}},
            {{"hosts":["*.b.example"],"routes":[
                {{"upstreams":[{{"server":"127.0.0.1","server_port":{b}}}]}}]}},
            {{"hosts":["plain.example"],"redirect_https":true}}]}}"#,
        a = a.port(),
        b = b.port()
    )
}

#[tokio::test]
async fn routes_by_host_and_path_on_one_connection() {
    let a = start_upstream("a").await;
    let b = start_upstream("b").await;
    let proxy = start_proxy(settings(a, b)).await;
    tokio::time::timeout(TIMEOUT, async {
        let mut client = TcpStream::connect(proxy).await.unwrap();

        client
            .write_all(b"GET /index.html HTTP/1.1\r\nHost: a.example\r\nX-Forwarded-For: 198.51.100.7\r\n\r\n")
            .await
            .unwrap();
        let (head, body) = read_response(&mut client).await;
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
        let body = String::from_utf8(body).unwrap();
        assert!(body.starts_with("a\nGET /index.html HTTP/1.1\r\n"), "{body}");
        assert!(body.contains("Host: a.example\r\n"), "{body}");
        assert!(body.contains("X-Forwarded-For: 198.51.100.7, 127.0.0.1\r\n"), "{body}");
        assert!(body.contains("X-Real-IP: 127.0.0.1\r\n"), "{body}");
        assert!(body.contains("X-Forwarded-Proto: http\r\n"), "{body}");

        // Same connection: the api route, with its prefix stripped.
        client
            .write_all(b"POST /api/items?x=1 HTTP/1.1\r\nHost: A.Example:8080\r\nContent-Length: 5\r\nConnection: keep-alive, X-Secret\r\nX-Secret: s\r\n\r\nhello")
            .await
            .unwrap();
        let (_, body) = read_response(&mut client).await;
        let body = String::from_utf8(body).unwrap();
        assert!(body.starts_with("b\nPOST /items?x=1 HTTP/1.1\r\n"), "{body}");
        assert!(body.contains("X-Route: api\r\n"), "{body}");
        assert!(!body.contains("X-Secret"), "{body}");
        assert!(!body.to_ascii_lowercase().contains("keep-alive"), "{body}");
        assert!(body.ends_with("hello"), "{body}");

        // A wildcard site, chunked request body.
        client
            .write_all(b"PUT /up HTTP/1.1\r\nHost: x.b.example\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
            .await
            .unwrap();
        let (_, body) = read_response(&mut client).await;
        let body = String::from_utf8(body).unwrap();
        assert!(body.starts_with("b\nPUT /up HTTP/1.1\r\n"), "{body}");
        assert!(body.ends_with("5\r\nhello\r\n0\r\n\r\n"), "{body}");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn answers_unknown_hosts_redirects_and_bad_framing() {
    let a = start_upstream("a").await;
    let b = start_upstream("b").await;
    let proxy = start_proxy(settings(a, b)).await;
    tokio::time::timeout(TIMEOUT, async {
        let mut client = TcpStream::connect(proxy).await.unwrap();
        client
            .write_all(b"GET /x?y HTTP/1.1\r\nHost: plain.example:80\r\n\r\n")
            .await
            .unwrap();
        let (head, _) = read_response(&mut client).await;
        assert!(head.starts_with("HTTP/1.1 308 "), "{head}");
        assert!(head.contains("Location: https://plain.example/x?y\r\n"), "{head}");

        client
            .write_all(b"GET / HTTP/1.1\r\nHost: nobody.example\r\n\r\n")
            .await
            .unwrap();
        let (head, _) = read_response(&mut client).await;
        assert!(head.starts_with("HTTP/1.1 421 "), "{head}");

        let mut client = TcpStream::connect(proxy).await.unwrap();
        client
            .write_all(b"POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await
            .unwrap();
        let (head, _) = read_response(&mut client).await;
        assert!(head.starts_with("HTTP/1.1 400 "), "{head}");

        let mut client = TcpStream::connect(proxy).await.unwrap();
        client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let (head, _) = read_response(&mut client).await;
        assert!(head.starts_with("HTTP/1.1 400 "), "{head}");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn relays_upgrades() {
    let a = start_upstream("a").await;
    let b = start_upstream("b").await;
    let proxy = start_proxy(settings(a, b)).await;
    tokio::time::timeout(TIMEOUT, async {
        let mut client = TcpStream::connect(proxy).await.unwrap();
        client
            .write_all(b"GET /ws HTTP/1.1\r\nHost: a.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
            .await
            .unwrap();
        let (head, _) = read_response(&mut client).await;
        assert!(head.starts_with("HTTP/1.1 101 "), "{head}");
        assert!(head.contains("Upgrade: websocket\r\n"), "{head}");
        client.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn answers_502_when_upstreams_are_down() {
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    };
    let proxy = start_proxy(format!(
        r#"{{"sites":[{{"hosts":["*"],"routes":[{{"upstreams":[{{"server":"127.0.0.1","server_port":{}}}],"health":{{"disabled":true}}}}]}}]}}"#,
        closed.port()
    ))
    .await;
    tokio::time::timeout(TIMEOUT, async {
        let mut client = TcpStream::connect(proxy).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: anything\r\n\r\n")
            .await
            .unwrap();
        let (head, _) = read_response(&mut client).await;
        assert!(head.starts_with("HTTP/1.1 502 "), "{head}");
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn terminates_tls_and_reports_https() {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["a.example".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let a = start_upstream("a").await;
    let settings = format!(
        r#"{{"sites":[{{"hosts":["a.example"],"routes":[{{"upstreams":[{{"server":"127.0.0.1","server_port":{}}}]}}]}}],
            "tls":{{"certificate":{},"key":{}}}}}"#,
        a.port(),
        serde_json::to_string(&cert.pem()).unwrap(),
        serde_json::to_string(&key.serialize_pem()).unwrap()
    );
    let parsed: Settings = serde_json::from_str(&settings).unwrap();
    let inbound = ReverseProxyInboundFactory.build(&parsed).unwrap();
    // The TLS wrapper still reports the upstreams' health.
    assert!(inbound.target_health().is_some());
    let proxy = start_proxy(settings).await;
    tokio::time::timeout(TIMEOUT, async {
        let connector = transport_tls::TlsConnector::new(&transport_tls::TlsSettings {
            server_name: "a.example".into(),
            alpn: vec!["http/1.1".into()],
            insecure: true,
        })
        .unwrap();
        let tcp: BoxStream = Box::new(TcpStream::connect(proxy).await.unwrap());
        let mut client = connector.connect(tcp).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut answer = Vec::new();
        let _ = client.read_to_end(&mut answer).await;
        let answer = String::from_utf8_lossy(&answer);
        assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
        assert!(answer.contains("X-Forwarded-Proto: https\r\n"), "{answer}");
    })
    .await
    .unwrap();
}

#[test]
fn refuses_h2_alpn() {
    let settings: Settings = serde_json::from_str(
        r#"{"sites":[{"hosts":["*"],"routes":[{"upstreams":[{"server":"127.0.0.1","server_port":1}]}]}],
            "tls":{"certificate":"x","key":"y","alpn":["h2"]}}"#,
    )
    .unwrap();
    assert!(ReverseProxyInboundFactory.build(&settings).is_err());
}
