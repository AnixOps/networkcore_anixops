//! Both Shadowsocks inbounds behind the built-in SIP003 plugin layers, built
//! by the factory: simple-obfs (`http` and `tls`) against a client written
//! here that skips the server's answer by size the way obfs clients do, and
//! v2ray-plugin's WebSocket mode (with and without TLS) through the engine's
//! WebSocket and TLS clients.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use engine_inbound::registry::InboundFactory;
use engine_inbound::server::{serve, InboundStats, ServeSettings};
use engine_inbound::StreamInbound;
use engine_outbound::{BoxFuture, BoxStream, Dialer, TargetAddr, TcpDialer, TcpOutbound};
use inbound_shadowsocks::ShadowsocksInboundFactory;
use outbound_shadowsocks::{AeadMethod, AeadOutbound, Method, Ss2022Outbound};
use rcgen::{CertificateParams, KeyPair};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use transport_tls::{TlsConnector, TlsSettings};
use transport_ws::{WsConnector, WsSettings};

const TIMEOUT: Duration = Duration::from_secs(10);
const PASSWORD: &str = "alice-secret";
const SERVER_KEY: &str = "AQIDBAUGBwgJCgsMDQ4PEA==";
const USER_KEY: &str = "EA8ODQwLCgkIBwYFBAMCAQ==";
const HOST: &str = "cdn.example";

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

/// A simple-obfs client: the stream it returns is one end of a pipe, and
/// two tasks carry the other end to the server in the disguise.
struct ObfsDialer {
    tls: bool,
}

impl Dialer for ObfsDialer {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let (tcp_read, tcp_write) = TcpStream::connect((host, port)).await?.into_split();
            let (plain, pipe) = tokio::io::duplex(64 * 1024);
            let (pipe_read, pipe_write) = tokio::io::split(pipe);
            if self.tls {
                tokio::spawn(tls_up(pipe_read, tcp_write));
                tokio::spawn(tls_down(tcp_read, pipe_write));
            } else {
                tokio::spawn(http_up(pipe_read, tcp_write));
                tokio::spawn(http_down(tcp_read, pipe_write));
            }
            Ok(Box::new(plain) as BoxStream)
        })
    }
}

async fn http_up(mut plain: ReadHalf<DuplexStream>, mut tcp: OwnedWriteHalf) -> io::Result<()> {
    let mut first = vec![0u8; 16 * 1024];
    let n = plain.read(&mut first).await?;
    let head = format!(
        "GET / HTTP/1.1\r\nHost: {HOST}:8388\r\nUser-Agent: curl/8.5.0\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Content-Length: {n}\r\n\r\n"
    );
    tcp.write_all(head.as_bytes()).await?;
    tcp.write_all(&first[..n]).await?;
    tokio::io::copy(&mut plain, &mut tcp).await?;
    tcp.shutdown().await
}

async fn http_down(mut tcp: OwnedReadHalf, mut plain: WriteHalf<DuplexStream>) -> io::Result<()> {
    // The response has to end within the first read.
    let mut first = vec![0u8; 16 * 1024];
    let n = tcp.read(&mut first).await?;
    let head = first[..n]
        .windows(4)
        .position(|window| window == b"\r\n\r\n");
    let end = head.ok_or(io::ErrorKind::InvalidData)? + 4;
    plain.write_all(&first[end..n]).await?;
    tokio::io::copy(&mut tcp, &mut plain).await?;
    plain.shutdown().await
}

/// A ClientHello record with `payload` as its session ticket, then the
/// server name.
fn client_hello(payload: &[u8]) -> Vec<u8> {
    let mut extensions = vec![0, 35];
    extensions.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    extensions.extend_from_slice(payload);
    extensions.extend_from_slice(&[0, 0]);
    extensions.extend_from_slice(&(HOST.len() as u16 + 5).to_be_bytes());
    extensions.extend_from_slice(&(HOST.len() as u16 + 3).to_be_bytes());
    extensions.push(0);
    extensions.extend_from_slice(&(HOST.len() as u16).to_be_bytes());
    extensions.extend_from_slice(HOST.as_bytes());

    let mut body = vec![3, 3];
    body.extend_from_slice(&[7; 32]);
    body.push(32);
    body.extend_from_slice(&[9; 32]);
    body.extend_from_slice(&[0, 2, 0xcc, 0xa8, 1, 0]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut record = vec![0x16, 3, 1];
    record.extend_from_slice(&(body.len() as u16 + 4).to_be_bytes());
    record.extend_from_slice(&[1, 0]);
    record.extend_from_slice(&(body.len() as u16).to_be_bytes());
    record.extend_from_slice(&body);
    record
}

async fn tls_up(mut plain: ReadHalf<DuplexStream>, mut tcp: OwnedWriteHalf) -> io::Result<()> {
    let mut buf = vec![0u8; 16 * 1024];
    let n = plain.read(&mut buf).await?;
    tcp.write_all(&client_hello(&buf[..n])).await?;
    loop {
        let n = plain.read(&mut buf).await?;
        if n == 0 {
            return tcp.shutdown().await;
        }
        let mut record = vec![0x17, 3, 3];
        record.extend_from_slice(&(n as u16).to_be_bytes());
        record.extend_from_slice(&buf[..n]);
        tcp.write_all(&record).await?;
    }
}

async fn tls_down(mut tcp: OwnedReadHalf, mut plain: WriteHalf<DuplexStream>) -> io::Result<()> {
    // The ServerHello (96 bytes) and ChangeCipherSpec (6) are skipped by
    // size, as are the type and version of every record.
    tcp.read_exact(&mut [0u8; 96 + 6]).await?;
    let mut buf = vec![0u8; 65_535];
    loop {
        let mut header = [0u8; 5];
        tcp.read_exact(&mut header).await?;
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        tcp.read_exact(&mut buf[..len]).await?;
        plain.write_all(&buf[..len]).await?;
    }
}

/// What a v2ray-plugin client without multiplexing puts on a connection: a
/// WebSocket, under TLS or not.
struct WsDialer {
    tls: Option<TlsConnector>,
    ws: WsConnector,
}

impl WsDialer {
    fn new(tls: bool) -> Self {
        let tls = tls.then(|| {
            TlsConnector::new(&TlsSettings {
                server_name: "ss.test".to_owned(),
                alpn: Vec::new(),
                insecure: true,
            })
            .unwrap()
        });
        let ws = WsSettings {
            path: "/ss".to_owned(),
            host: HOST.to_owned(),
            headers: Vec::new(),
        };
        Self {
            tls,
            ws: WsConnector::new(&ws, "").unwrap(),
        }
    }
}

impl Dialer for WsDialer {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let mut stream = TcpDialer.dial(host, port).await?;
            if let Some(tls) = &self.tls {
                stream = tls.connect(stream).await?;
            }
            self.ws.connect(stream).await
        })
    }
}

/// A client of the protocol in `settings` whose connections `dialer` opens.
fn client(settings: &Value, server: SocketAddr, dialer: Arc<dyn Dialer>) -> Arc<dyn TcpOutbound> {
    let (host, port) = (server.ip().to_string(), server.port());
    if settings["method"] == "aes-256-gcm" {
        let method = AeadMethod::Aes256Gcm;
        Arc::new(AeadOutbound::new(host, port, method, PASSWORD, dialer).unwrap())
    } else {
        let keys = format!("{SERVER_KEY}:{USER_KEY}");
        Arc::new(Ss2022Outbound::new(host, port, Method::Aes128Gcm, &keys, dialer).unwrap())
    }
}

async fn echo_through(outbound: &dyn TcpOutbound, target: SocketAddr, payload: &[u8]) {
    let stream = tokio::time::timeout(TIMEOUT, outbound.connect(&TargetAddr::Ip(target)))
        .await
        .expect("connect timed out")
        .unwrap();
    let (mut reader, mut writer) = tokio::io::split(stream);
    let write = async {
        writer.write_all(payload).await?;
        writer.flush().await
    };
    let mut received = vec![0u8; payload.len()];
    let read = reader.read_exact(&mut received);
    let (written, read) = tokio::time::timeout(TIMEOUT, async { tokio::join!(write, read) })
        .await
        .expect("echo timed out");
    written.unwrap();
    read.unwrap();
    assert!(received == payload, "echoed bytes differ");
}

/// Runs Shadowsocks AEAD and Shadowsocks-2022, each with one user, behind
/// `layer` (inbound settings) and relays through a client using `dialer`.
async fn relays(layer: Value, dialer: Arc<dyn Dialer>) {
    let echo = echo_server().await;
    let protocols = [
        json!({"method": "aes-256-gcm", "users": [{"name": "alice", "password": PASSWORD}]}),
        json!({"method": "2022-blake3-aes-128-gcm", "password": SERVER_KEY,
            "users": [{"name": "alice", "password": USER_KEY}]}),
    ];
    for mut settings in protocols {
        let object = settings.as_object_mut().unwrap();
        object.extend(layer.as_object().unwrap().clone());
        let inbound: Arc<dyn StreamInbound> = ShadowsocksInboundFactory.build(object).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        tokio::spawn(serve(
            listener,
            inbound.clone(),
            Arc::new(Direct),
            ServeSettings::default(),
            Arc::new(InboundStats::default()),
        ));

        let outbound = client(&settings, server, dialer.clone());
        let payload: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
        tokio::join!(
            echo_through(outbound.as_ref(), echo, &payload),
            echo_through(outbound.as_ref(), echo, b"second"),
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        let traffic = inbound.users().traffic(false);
        assert_eq!(traffic.len(), 1);
        assert_eq!(traffic[0].name, "alice");
        let expected = payload.len() as u64 + 6;
        assert!(traffic[0].up >= expected && traffic[0].down >= expected);
        // The plugins are for TCP: UDP on the port stays the protocol's.
        assert!(inbound.datagram().is_some());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn simple_obfs_http_relays() {
    let layer = json!({"obfs": {"type": "http", "host": HOST}});
    relays(layer, Arc::new(ObfsDialer { tls: false })).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn simple_obfs_tls_relays() {
    let layer = json!({"obfs": {"type": "tls", "host": HOST}});
    relays(layer, Arc::new(ObfsDialer { tls: true })).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v2ray_plugin_websocket_relays() {
    let layer = json!({"transport": {"type": "ws", "path": "/ss", "host": HOST}});
    relays(layer, Arc::new(WsDialer::new(false))).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v2ray_plugin_websocket_relays_under_tls() {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["ss.test".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let layer = json!({
        "transport": {"type": "ws", "path": "/ss"},
        "tls": {"certificate": cert.pem(), "key": key.serialize_pem()},
    });
    relays(layer, Arc::new(WsDialer::new(true))).await;
}
