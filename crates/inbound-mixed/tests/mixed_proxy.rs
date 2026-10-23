//! End-to-end tests: a client speaks SOCKS5 or HTTP to the mixed inbound, which
//! relays through a direct test outbound to a local server.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use inbound_mixed::{serve, Credentials, MixedSettings, MixedStats};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const WAIT: Duration = Duration::from_secs(10);

struct Direct;

impl TcpOutbound for Direct {
    fn protocol(&self) -> &'static str {
        "test-direct"
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let stream = TcpStream::connect((target.host().as_str(), target.port())).await?;
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

/// An unused port: bound once, then released.
async fn closed_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

async fn proxy(credentials: Option<Credentials>) -> (SocketAddr, Arc<MixedStats>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stats = Arc::new(MixedStats::default());
    let settings = MixedSettings {
        credentials,
        ..MixedSettings::default()
    };
    tokio::spawn(serve(listener, Arc::new(Direct), settings, stats.clone()));
    (addr, stats)
}

fn credentials() -> Credentials {
    Credentials {
        username: "user".into(),
        password: "pa:ss".into(),
    }
}

async fn read_n(stream: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    tokio::time::timeout(WAIT, stream.read_exact(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    buf
}

async fn read_to_end(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    tokio::time::timeout(WAIT, stream.read_to_end(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    String::from_utf8(buf).unwrap()
}

fn socks_connect_ipv4(target: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(v4) = target else {
        panic!("ipv4 target expected");
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&v4.ip().octets());
    request.extend_from_slice(&v4.port().to_be_bytes());
    request
}

async fn assert_echo(stream: &mut TcpStream) {
    stream.write_all(b"ping through proxy").await.unwrap();
    assert_eq!(read_n(stream, 18).await, b"ping through proxy");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_connect_relays_bytes() {
    let echo = echo_server().await;
    let (proxy, stats) = proxy(None).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    assert_eq!(read_n(&mut client, 2).await, [0x05, 0x00]);
    client.write_all(&socks_connect_ipv4(echo)).await.unwrap();
    assert_eq!(read_n(&mut client, 10).await[..2], [0x05, 0x00]);
    assert_echo(&mut client).await;
    assert_eq!(stats.accepted.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_domain_targets_are_passed_to_the_outbound() {
    let echo = echo_server().await;
    let (proxy, _) = proxy(None).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    read_n(&mut client, 2).await;
    let host = b"127.0.0.1";
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&echo.port().to_be_bytes());
    client.write_all(&request).await.unwrap();
    assert_eq!(read_n(&mut client, 10).await[1], 0x00);
    assert_echo(&mut client).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_password_auth_is_enforced() {
    let echo = echo_server().await;
    let (proxy, _) = proxy(Some(credentials())).await;

    // No-auth only: refused.
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    assert_eq!(read_n(&mut client, 2).await, [0x05, 0xFF]);

    // Wrong password.
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    assert_eq!(read_n(&mut client, 2).await, [0x05, 0x02]);
    client
        .write_all(&[0x01, 4, b'u', b's', b'e', b'r', 3, b'b', b'a', b'd'])
        .await
        .unwrap();
    assert_eq!(read_n(&mut client, 2).await, [0x01, 0x01]);

    // Right password.
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(&[0x05, 0x02, 0x00, 0x02]).await.unwrap();
    assert_eq!(read_n(&mut client, 2).await, [0x05, 0x02]);
    let mut auth = vec![0x01, 4];
    auth.extend_from_slice(b"user");
    auth.push(5);
    auth.extend_from_slice(b"pa:ss");
    client.write_all(&auth).await.unwrap();
    assert_eq!(read_n(&mut client, 2).await, [0x01, 0x00]);
    client.write_all(&socks_connect_ipv4(echo)).await.unwrap();
    assert_eq!(read_n(&mut client, 10).await[1], 0x00);
    assert_echo(&mut client).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_udp_associate_is_not_supported() {
    let (proxy, _) = proxy(None).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    read_n(&mut client, 2).await;
    client
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    assert_eq!(read_n(&mut client, 10).await[1], 0x07);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_connect_failure_is_reported() {
    let target = closed_port().await;
    let (proxy, stats) = proxy(None).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    read_n(&mut client, 2).await;
    client.write_all(&socks_connect_ipv4(target)).await.unwrap();
    assert_eq!(read_n(&mut client, 10).await[1], 0x01);
    assert_eq!(stats.connect_failed.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_connect_tunnels_bytes_including_early_data() {
    let echo = echo_server().await;
    let (proxy, _) = proxy(None).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    // The first tunnel bytes arrive in the same write as the request head.
    let request = format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\nearly");
    client.write_all(request.as_bytes()).await.unwrap();
    let established = b"HTTP/1.1 200 Connection established\r\n\r\n";
    assert_eq!(read_n(&mut client, established.len()).await, established);
    assert_eq!(read_n(&mut client, 5).await, b"early");
    assert_echo(&mut client).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_proxy_auth_is_enforced() {
    let echo = echo_server().await;
    let (proxy, _) = proxy(Some(credentials())).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    let request = format!("CONNECT {echo} HTTP/1.1\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();
    assert!(read_to_end(&mut client)
        .await
        .starts_with("HTTP/1.1 407 Proxy Authentication Required\r\n"));

    let mut client = TcpStream::connect(proxy).await.unwrap();
    // base64("user:pa:ss")
    let request =
        format!("CONNECT {echo} HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpwYTpzcw==\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();
    let established = b"HTTP/1.1 200 Connection established\r\n\r\n";
    assert_eq!(read_n(&mut client, established.len()).await, established);
    assert_echo(&mut client).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_http_is_forwarded_in_origin_form() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let seen = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
        String::from_utf8(head).unwrap()
    });

    let (proxy, _) = proxy(None).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    let request = format!(
        "GET http://{origin_addr}/path?q=1 HTTP/1.1\r\nHost: {origin_addr}\r\nProxy-Connection: keep-alive\r\nUser-Agent: test\r\n\r\n"
    );
    client.write_all(request.as_bytes()).await.unwrap();
    let response = read_to_end(&mut client).await;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("ok"));

    let head = seen.await.unwrap();
    assert_eq!(
        head,
        format!(
            "GET /path?q=1 HTTP/1.1\r\nHost: {origin_addr}\r\nUser-Agent: test\r\nConnection: close\r\n\r\n"
        )
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_http_gets_400_and_connect_failure_gets_502() {
    let (proxy, _) = proxy(None).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(b"GET /relative HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    assert!(read_to_end(&mut client).await.starts_with("HTTP/1.1 400 "));

    let target = closed_port().await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    let request = format!("CONNECT {target} HTTP/1.1\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();
    assert!(read_to_end(&mut client).await.starts_with("HTTP/1.1 502 "));
}
