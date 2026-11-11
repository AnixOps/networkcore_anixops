//! The NaiveProxy server inbound against a minimal client written from the
//! protocol: TLS, HTTP/2 `CONNECT` with Basic credentials and the payload
//! padding, framed and unframed here by hand.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use bytes::Bytes;
use engine_inbound::registry::InboundFactory;
use engine_inbound::server::{serve, InboundStats, ServeSettings};
use engine_inbound::StreamInbound;
use engine_outbound::{BoxFuture, BoxStream, TargetAddr};
use h2::client::SendRequest;
use h2::{RecvStream, SendStream};
use http::header::PROXY_AUTHORIZATION;
use http::{Method, Request, Response};
use inbound_naive::NaiveInboundFactory;
use rcgen::{CertificateParams, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use transport_tls::{TlsConnector, TlsSettings};

const TIMEOUT: Duration = Duration::from_secs(10);
const REJECT_HOLD: Duration = Duration::from_millis(300);
/// Reads and writes that are framed, in each direction.
const FRAMES: usize = 8;
const ALICE: &str = "alice:alice-secret";
/// What a current client sends, and one from before the type headers.
const PADDING: &[(&str, &str)] = &[("padding", "~~~~~~~~"), ("padding-type-request", "1, 0")];
const OLD_PADDING: &[(&str, &str)] = &[("padding", "~~~~~~~~")];

async fn within<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(TIMEOUT, future)
        .await
        .expect("timed out")
}

struct Direct;

impl engine_outbound::TcpOutbound for Direct {
    fn protocol(&self) -> &'static str {
        "direct"
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, std::io::Result<BoxStream>> {
        Box::pin(async move {
            let stream = TcpStream::connect((target.host(), target.port())).await?;
            Ok(Box::new(stream) as BoxStream)
        })
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

/// An HTTP/1.1 web site.
async fn h1_site() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await;
            });
        }
    });
    addr
}

/// A cleartext HTTP/2 web site: a page is its request's method, path and
/// body; `CONNECT` is not allowed.
async fn h2_site() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(mut connection) = h2::server::handshake(stream).await else {
                    return;
                };
                while let Some(Ok((request, mut respond))) = connection.accept().await {
                    let (head, mut body) = request.into_parts();
                    if head.method == Method::CONNECT {
                        let refusal = Response::builder().status(405).body(()).unwrap();
                        respond.send_response(refusal, true).unwrap();
                        continue;
                    }
                    tokio::spawn(async move {
                        let mut page = format!("{} {} ", head.method, head.uri.path()).into_bytes();
                        while let Some(Ok(chunk)) = body.data().await {
                            let _ = body.flow_control().release_capacity(chunk.len());
                            page.extend_from_slice(&chunk);
                        }
                        let found = Response::builder()
                            .header("server", "site")
                            .body(())
                            .unwrap();
                        let mut send = respond.send_response(found, false).unwrap();
                        send.send_data(Bytes::from(page), true).unwrap();
                    });
                }
            });
        }
    });
    addr
}

struct Server {
    addr: SocketAddr,
    inbound: Arc<dyn StreamInbound>,
    stats: Arc<InboundStats>,
}

async fn start(fallback: Option<SocketAddr>) -> Server {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["naive.test".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let mut settings = serde_json::json!({
        "users": [
            {"name": "1001", "username": "alice", "password": "alice-secret"},
            {"name": "bob", "password": "bob-secret"}
        ],
        "tls": {"certificate": cert.pem(), "key": key.serialize_pem()}
    });
    if let Some(fallback) = fallback {
        settings["fallback"] = serde_json::json!({
            "server": fallback.ip().to_string(),
            "server_port": fallback.port()
        });
    }
    let inbound = NaiveInboundFactory
        .build(settings.as_object().unwrap())
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stats = Arc::new(InboundStats::default());
    tokio::spawn(serve(
        listener,
        inbound.clone(),
        Arc::new(Direct),
        ServeSettings {
            reject_hold: REJECT_HOLD,
            ..ServeSettings::default()
        },
        stats.clone(),
    ));
    Server {
        addr,
        inbound,
        stats,
    }
}

async fn tls(server: SocketAddr, alpn: &[&str]) -> BoxStream {
    let tcp = TcpStream::connect(server).await.unwrap();
    TlsConnector::new(&TlsSettings {
        server_name: "naive.test".into(),
        alpn: alpn.iter().map(|protocol| (*protocol).to_owned()).collect(),
        insecure: true,
    })
    .unwrap()
    .connect(Box::new(tcp))
    .await
    .unwrap()
}

/// One HTTP/2 connection to the server.
struct Client {
    sender: SendRequest<Bytes>,
}

impl Client {
    async fn connect(server: SocketAddr) -> Self {
        let (sender, connection) = h2::client::handshake(tls(server, &["h2"]).await)
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Self { sender }
    }

    async fn send(
        &self,
        request: Request<()>,
        end: bool,
    ) -> (h2::client::ResponseFuture, SendStream<Bytes>) {
        let mut sender = within(self.sender.clone().ready()).await.unwrap();
        sender.send_request(request, end).unwrap()
    }

    /// A page of the site: the status and the body.
    async fn page(&self, method: Method, path: &str, body: &'static [u8]) -> (u16, Vec<u8>) {
        let request = Request::builder()
            .method(method)
            .uri(format!("https://naive.test{path}"))
            .body(())
            .unwrap();
        let (response, mut send) = self.send(request, body.is_empty()).await;
        if !body.is_empty() {
            send.send_data(Bytes::from_static(body), true).unwrap();
        }
        let (head, mut body) = within(response).await.unwrap().into_parts();
        let mut page = Vec::new();
        while let Some(chunk) = within(body.data()).await {
            let chunk = chunk.unwrap();
            let _ = body.flow_control().release_capacity(chunk.len());
            page.extend_from_slice(&chunk);
        }
        (head.status.as_u16(), page)
    }

    /// A `CONNECT` for `target` with `credentials` (`username:password`)
    /// and the padding `headers`.
    async fn request_tunnel(
        &self,
        target: &str,
        credentials: &str,
        headers: &[(&str, &str)],
    ) -> (h2::client::ResponseFuture, SendStream<Bytes>) {
        let token = base64::engine::general_purpose::STANDARD.encode(credentials);
        let mut request = Request::builder()
            .method(Method::CONNECT)
            .uri(target)
            .header(PROXY_AUTHORIZATION, format!("Basic {token}"));
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        self.send(request.body(()).unwrap(), false).await
    }

    /// Opens a tunnel that the server accepts; `padded` is what the
    /// headers are expected to settle.
    async fn tunnel(
        &self,
        target: &str,
        credentials: &str,
        headers: &[(&str, &str)],
        padded: bool,
    ) -> (http::response::Parts, Tunnel) {
        let (response, send) = self.request_tunnel(target, credentials, headers).await;
        let (head, recv) = within(response).await.unwrap().into_parts();
        let tunnel = Tunnel {
            send,
            recv,
            padded,
            writes: 0,
            reads: 0,
            wire: Vec::new(),
        };
        (head, tunnel)
    }
}

/// The client's end of a tunnel.
struct Tunnel {
    send: SendStream<Bytes>,
    recv: RecvStream,
    padded: bool,
    writes: usize,
    /// Frames unframed so far.
    reads: usize,
    /// Received bytes that are not unframed yet.
    wire: Vec<u8>,
}

impl Tunnel {
    fn write(&mut self, payload: &[u8]) {
        let mut data = Vec::new();
        if self.padded && self.writes < FRAMES {
            let padding = [0usize, 255, 7, 100, 1, 31, 200, 64][self.writes];
            data.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            data.push(padding as u8);
            data.extend_from_slice(payload);
            data.resize(data.len() + padding, 0);
        } else {
            data.extend_from_slice(payload);
        }
        self.writes += 1;
        self.send.send_data(Bytes::from(data), false).unwrap();
    }

    /// Payload from the server, once at least `len` bytes of it are here.
    async fn read(&mut self, len: usize) -> Vec<u8> {
        let mut payload = Vec::new();
        while payload.len() < len {
            let framed = self.padded && self.reads < FRAMES;
            if framed && self.wire.len() >= 3 {
                let size = usize::from(u16::from_be_bytes([self.wire[0], self.wire[1]]));
                let end = 3 + size + usize::from(self.wire[2]);
                if self.wire.len() >= end {
                    let frame: Vec<u8> = self.wire.drain(..end).collect();
                    assert!(frame[3 + size..].iter().all(|byte| *byte == 0));
                    payload.extend_from_slice(&frame[3..3 + size]);
                    self.reads += 1;
                    continue;
                }
            } else if !framed && !self.wire.is_empty() {
                payload.append(&mut self.wire);
                continue;
            }
            let chunk = within(self.recv.data())
                .await
                .expect("the tunnel ended")
                .unwrap();
            let _ = self.recv.flow_control().release_capacity(chunk.len());
            self.wire.extend_from_slice(&chunk);
        }
        payload
    }

    /// Sends `payload` and takes its echo.
    async fn echo(&mut self, payload: &[u8]) {
        self.write(payload);
        assert_eq!(self.read(payload.len()).await, payload);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relays_tunnels_with_and_without_padding_and_charges_the_user() {
    let server = start(None).await;
    let echo = echo_server().await;
    let client = Client::connect(server.addr).await;

    let (head, mut tunnel) = client.tunnel(&echo.to_string(), ALICE, PADDING, true).await;
    assert_eq!(head.status, 200);
    assert_eq!(head.headers["padding-type-reply"], "1");
    assert!((30..=62).contains(&head.headers["padding"].len()));
    // More writes than are framed, in both directions.
    let payload: Vec<u8> = (0..108_000).map(|i| (i % 251) as u8).collect();
    for chunk in payload.chunks(9000) {
        tunnel.echo(chunk).await;
    }
    assert_eq!((tunnel.writes, tunnel.reads), (12, FRAMES));

    // The other tunnels share the connection.
    let target = format!("localhost:{}", echo.port());
    let (head, mut old) = client.tunnel(&target, ALICE, OLD_PADDING, true).await;
    assert_eq!(head.status, 200);
    assert!(head.headers.get("padding-type-reply").is_none());
    assert!(head.headers.contains_key("padding"));
    old.echo(b"from an older client").await;
    assert_ne!(old.reads, 0);

    let (head, mut plain) = client.tunnel(&target, "bob:bob-secret", &[], false).await;
    assert_eq!(head.status, 200);
    plain.echo(b"no padding").await;
    let unframed = [("padding", "~~"), ("padding-type-request", "0")];
    let (head, mut plain) = client.tunnel(&target, ALICE, &unframed, false).await;
    assert_eq!(head.headers["padding-type-reply"], "0");
    plain.echo(b"none chosen").await;

    tokio::time::sleep(Duration::from_millis(50)).await;
    let traffic = server.inbound.users().traffic(true);
    let charged: Vec<_> = traffic
        .iter()
        .map(|user| (user.name.as_str(), user.up, user.down))
        .collect();
    // Payload only: neither headers nor padding.
    let alice = (payload.len() + "from an older client".len() + "none chosen".len()) as u64;
    assert_eq!(charged, [("1001", alice, alice), ("bob", 10, 10)]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreachable_targets_get_502() {
    let server = start(None).await;
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = closed.local_addr().unwrap();
    drop(closed);
    let client = Client::connect(server.addr).await;
    let (response, _send) = client
        .request_tunnel(&target.to_string(), ALICE, PADDING)
        .await;
    assert_eq!(within(response).await.unwrap().status(), 502);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn other_requests_are_held_then_reset_without_a_fallback() {
    let server = start(None).await;
    let echo = echo_server().await;
    let client = Client::connect(server.addr).await;
    let started = Instant::now();
    let (wrong, _send) = client
        .request_tunnel(&echo.to_string(), "alice:wrong", PADDING)
        .await;
    let get = Request::get("https://naive.test/").body(()).unwrap();
    let (page, _) = client.send(get, true).await;
    assert!(within(wrong).await.is_err());
    assert!(within(page).await.is_err());
    assert!(started.elapsed() >= REJECT_HOLD);
    assert_eq!(server.stats.handshake_failed.load(Ordering::Relaxed), 2);

    // The connection goes on serving its user.
    let (_, mut tunnel) = client.tunnel(&echo.to_string(), ALICE, PADDING, true).await;
    tunnel.echo(b"still here").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn other_requests_get_the_fallback_site() {
    let server = start(Some(h2_site().await)).await;
    let echo = echo_server().await;
    let client = Client::connect(server.addr).await;
    assert_eq!(
        client.page(Method::GET, "/index.html", b"").await,
        (200, b"GET /index.html ".to_vec())
    );
    assert_eq!(
        client.page(Method::POST, "/submit", b"a form").await,
        (200, b"POST /submit a form".to_vec())
    );
    // A proxy request with unknown credentials is the site's to refuse.
    let (wrong, _send) = client
        .request_tunnel(&echo.to_string(), "alice:wrong", PADDING)
        .await;
    assert_eq!(within(wrong).await.unwrap().status(), 405);
    assert_eq!(server.stats.handshake_failed.load(Ordering::Relaxed), 0);

    let (_, mut tunnel) = client.tunnel(&echo.to_string(), ALICE, PADDING, true).await;
    tunnel.echo(b"beside the site").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http1_clients_go_to_the_fallback_unchanged() {
    let server = start(Some(h1_site().await)).await;
    let mut stream = tls(server.addr, &["http/1.1"]).await;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: naive.test\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(TIMEOUT, stream.read_to_end(&mut response)).await;
    assert!(response.starts_with(b"HTTP/1.1 200 OK"), "{response:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removing_the_user_ends_its_tunnels() {
    let server = start(None).await;
    let echo = echo_server().await;
    let client = Client::connect(server.addr).await;
    let (_, mut tunnel) = client
        .tunnel(&echo.to_string(), "bob:bob-secret", PADDING, true)
        .await;
    tunnel.echo(b"hi").await;
    assert!(server.inbound.users().remove("bob"));
    let ended = within(tunnel.recv.data()).await;
    assert!(!matches!(ended, Some(Ok(_))), "the tunnel stayed open");
}
