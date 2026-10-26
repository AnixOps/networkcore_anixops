//! Interop tests against the official mita server (black box).
//!
//! These tests are ignored by default; the `REALITY interop (Linux)` CI job
//! installs and starts mita and runs them with `--ignored`. Inputs:
//!
//! * `NC_MIERU_SERVER`: `host:port` of a mita TCP port binding
//! * `NC_MIERU_PORT_RANGE`: `low-high` of a mita TCP port range binding
//! * `NC_MIERU_USER`, `NC_MIERU_PASSWORD`
//! * `NC_MIERU_DOMAIN`: a name mita maps to 127.0.0.1 (`dns.hosts`)
//! * `NC_HTTP_TARGET`: plain HTTP/1.0 server serving `/payload.bin`
//! * `NC_TCP_ECHO`: TCP echo server

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use engine_outbound::{TargetAddr, TcpDialer};
use outbound_mieru::{MieruOptions, MieruOutbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PAYLOAD_LEN: usize = 1_000_000;
const TIMEOUT: Duration = Duration::from_secs(60);

fn expected_payload() -> Vec<u8> {
    (0..PAYLOAD_LEN)
        .map(|i| ((i * 7 + 3) % 251) as u8)
        .collect()
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set for interop tests"))
}

fn outbound_with(password: String, port_range: Option<(u16, u16)>) -> MieruOutbound {
    let server: SocketAddr = env("NC_MIERU_SERVER").parse().unwrap();
    MieruOutbound::new(
        server.ip().to_string(),
        server.port(),
        MieruOptions {
            username: env("NC_MIERU_USER"),
            password,
            port_range,
        },
        Arc::new(TcpDialer),
    )
    .unwrap()
}

fn outbound() -> MieruOutbound {
    outbound_with(env("NC_MIERU_PASSWORD"), None)
}

fn target(var: &str) -> TargetAddr {
    TargetAddr::Ip(env(var).parse().unwrap())
}

async fn fetch_payload(outbound: &MieruOutbound, target: &TargetAddr) -> io::Result<Vec<u8>> {
    let mut stream = outbound.connect_stream(target).await?;
    stream
        .write_all(b"GET /payload.bin HTTP/1.0\r\nHost: target\r\n\r\n")
        .await?;
    stream.flush().await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    let _ = stream.shutdown().await;
    let body = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|end| response[end + 4..].to_vec())
        .ok_or_else(|| io::Error::other("no HTTP header in response"))?;
    Ok(body)
}

#[tokio::test]
#[ignore = "needs the official mita server; run by the interop CI job"]
async fn fetches_the_payload_by_ip_and_by_domain() {
    let expected = expected_payload();
    let http: SocketAddr = env("NC_HTTP_TARGET").parse().unwrap();
    let targets = [
        TargetAddr::Ip(http),
        TargetAddr::Domain(env("NC_MIERU_DOMAIN"), http.port()),
    ];
    let range = env("NC_MIERU_PORT_RANGE");
    let (low, high) = range.split_once('-').unwrap();
    let ranged = outbound_with(
        env("NC_MIERU_PASSWORD"),
        Some((low.parse().unwrap(), high.parse().unwrap())),
    );
    for (label, outbound) in [("port", outbound()), ("port range", ranged)] {
        for target in &targets {
            for round in 0..3 {
                let body = tokio::time::timeout(TIMEOUT, fetch_payload(&outbound, target))
                    .await
                    .unwrap_or_else(|_| panic!("{label} {target}: timed out"))
                    .unwrap_or_else(|err| panic!("{label} {target} round {round}: {err}"));
                assert_eq!(body.len(), expected.len(), "{label} {target}");
                assert!(body == expected, "{label} {target}: payload differs");
            }
            println!("{label} {target}: 3 fetches ok");
        }
    }
}

#[tokio::test]
#[ignore = "needs the official mita server; run by the interop CI job"]
async fn echoes_large_uploads_in_both_directions() {
    let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 253) as u8).collect();
    let stream = tokio::time::timeout(TIMEOUT, outbound().connect_stream(&target("NC_TCP_ECHO")))
        .await
        .unwrap()
        .unwrap();
    let (mut read_half, mut write_half) = tokio::io::split(stream);
    let writer = async {
        for chunk in data.chunks(50_000) {
            write_half.write_all(chunk).await.unwrap();
        }
        write_half.flush().await.unwrap();
    };
    let mut received = vec![0u8; data.len()];
    let reader = async { read_half.read_exact(&mut received).await.unwrap() };
    tokio::time::timeout(TIMEOUT, async { tokio::join!(writer, reader) })
        .await
        .expect("echo timed out");
    assert!(received == data, "echoed data differs");
    println!("echo: {} bytes ok", data.len());
}

#[tokio::test]
#[ignore = "needs the official mita server; run by the interop CI job"]
async fn server_first_targets_work_without_a_client_write() {
    // The HTTP target only answers after a request, so use the echo target and
    // check that a read-only session still opens: the open request goes out at
    // connect time and the first read sees the SOCKS5 reply being consumed.
    let mut stream = outbound()
        .connect_stream(&target("NC_TCP_ECHO"))
        .await
        .unwrap();
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await;
    assert!(read.is_err(), "the echo target sent data before any write");
    stream.write_all(b"x").await.unwrap();
    stream.flush().await.unwrap();
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"x");
}

#[tokio::test]
#[ignore = "needs the official mita server; run by the interop CI job"]
async fn unreachable_targets_are_refused() {
    let closed = TargetAddr::Ip("127.0.0.1:1".parse().unwrap());
    let result = tokio::time::timeout(TIMEOUT, async {
        let mut stream = outbound().connect_stream(&closed).await?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.map(|_| buf)
    })
    .await
    .expect("unreachable target timed out");
    let err = result.expect_err("a closed port must not yield a stream");
    println!("observed: unreachable target: {:?}: {err}", err.kind());
    assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
}

#[tokio::test]
#[ignore = "needs the official mita server; run by the interop CI job"]
async fn a_wrong_password_gets_no_readable_answer() {
    let outbound = outbound_with("not-the-password".to_owned(), None);
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let mut stream = outbound.connect_stream(&target("NC_HTTP_TARGET")).await?;
        stream
            .write_all(b"GET /payload.bin HTTP/1.0\r\nHost: target\r\n\r\n")
            .await?;
        stream.flush().await?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.map(|_| buf)
    })
    .await;
    match &result {
        Err(_) => println!("observed: wrong password: no answer within 10 s"),
        Ok(Ok(data)) => println!(
            "observed: wrong password: end of stream after {} bytes",
            data.len()
        ),
        Ok(Err(err)) => println!("observed: wrong password: {:?}: {err}", err.kind()),
    }
    assert!(
        !matches!(&result, Ok(Ok(data)) if !data.is_empty()),
        "a wrong password yielded data"
    );
}
