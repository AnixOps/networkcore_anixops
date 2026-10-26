//! Interop tests against official snell-server binaries (black box).
//!
//! These tests are ignored by default; the `REALITY interop (Linux)` CI job
//! downloads and starts the servers and runs them with `--ignored`. Inputs:
//!
//! * `NC_SNELL_SERVERS`: `name=host:port:version:mode:obfs,...` where `mode`
//!   is a v6 mode or `-`, and `obfs` is `http` or `none`
//! * `NC_SNELL_PSK`
//! * `NC_HTTP_TARGET`: plain HTTP/1.0 server serving `/payload.bin`
//! * `NC_UDP_ECHO`: UDP echo server
//!
//! Observations the spec marks as "to be measured" are printed with an
//! `observed:` prefix.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use engine_outbound::{TargetAddr, TcpDialer};
use outbound_snell::{HttpObfsSettings, SnellOptions, SnellOutbound, V6Mode};
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

struct Server {
    name: String,
    host: String,
    port: u16,
    version: u8,
    mode: V6Mode,
    obfs: bool,
}

fn servers() -> Vec<Server> {
    let servers: Vec<Server> = env("NC_SNELL_SERVERS")
        .split(',')
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let (name, rest) = entry
                .split_once('=')
                .expect("name=host:port:version:mode:obfs");
            let parts: Vec<&str> = rest.split(':').collect();
            assert_eq!(parts.len(), 5, "{entry}");
            Server {
                name: name.to_owned(),
                host: parts[0].to_owned(),
                port: parts[1].parse().unwrap(),
                version: parts[2].parse().unwrap(),
                mode: match parts[3] {
                    "-" => V6Mode::Default,
                    mode => V6Mode::parse(mode).expect("v6 mode"),
                },
                obfs: parts[4] == "http",
            }
        })
        .collect();
    assert!(
        servers.iter().any(|server| server.version == 6),
        "the v6 server must be part of the run"
    );
    servers
}

fn outbound(server: &Server, reuse: bool) -> SnellOutbound {
    let options = SnellOptions {
        version: server.version,
        mode: server.mode,
        psk: env("NC_SNELL_PSK").into_bytes(),
        obfs: server.obfs.then(|| HttpObfsSettings {
            host: "bing.com".into(),
            uri: "/".into(),
        }),
        reuse,
        user_key: Vec::new(),
    };
    SnellOutbound::new(
        server.host.clone(),
        server.port,
        options,
        Arc::new(TcpDialer),
    )
    .unwrap()
}

fn target(var: &str) -> TargetAddr {
    let addr: SocketAddr = env(var).parse().unwrap();
    TargetAddr::Ip(addr)
}

async fn fetch_payload(outbound: &SnellOutbound) -> io::Result<Vec<u8>> {
    let mut stream = outbound.connect_stream(&target("NC_HTTP_TARGET")).await?;
    stream
        .write_all(b"GET /payload.bin HTTP/1.0\r\nHost: target\r\n\r\n")
        .await?;
    stream.flush().await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    // Ends this request in our direction too, so the connection can be
    // reused. One-shot servers may already have closed the socket.
    let _ = stream.shutdown().await;
    let body = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|end| response[end + 4..].to_vec())
        .ok_or_else(|| io::Error::other("no HTTP header in response"))?;
    Ok(body)
}

#[tokio::test]
#[ignore = "needs official snell-server binaries; run by the interop CI job"]
async fn tcp_streams_fetch_the_payload() {
    let expected = expected_payload();
    for server in servers() {
        let reuse_modes: &[bool] = if server.version >= 2 {
            &[false, true]
        } else {
            &[false]
        };
        for &reuse in reuse_modes {
            let outbound = outbound(&server, reuse);
            for round in 0..3 {
                let body = tokio::time::timeout(TIMEOUT, fetch_payload(&outbound))
                    .await
                    .unwrap_or_else(|_| panic!("{} reuse={reuse}: timed out", server.name))
                    .unwrap_or_else(|err| {
                        panic!("{} reuse={reuse} round {round}: {err}", server.name)
                    });
                assert_eq!(body.len(), expected.len(), "{} reuse={reuse}", server.name);
                assert!(
                    body == expected,
                    "{} reuse={reuse}: payload differs",
                    server.name
                );
            }
            println!("{} reuse={reuse}: 3 fetches ok", server.name);
        }
    }
}

#[tokio::test]
#[ignore = "needs official snell-server binaries; run by the interop CI job"]
async fn unreachable_targets_are_reported() {
    for server in servers() {
        let outbound = outbound(&server, false);
        let closed = TargetAddr::Ip("127.0.0.1:1".parse().unwrap());
        let result = tokio::time::timeout(TIMEOUT, async {
            let mut stream = outbound.connect_stream(&closed).await?;
            stream.write_all(b"hello").await?;
            stream.flush().await?;
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.map(|_| buf)
        })
        .await
        .unwrap_or_else(|_| panic!("{}: timed out", server.name));
        match &result {
            Ok(data) => println!(
                "observed: {} unreachable target: end of stream after {} bytes",
                server.name,
                data.len()
            ),
            Err(err) => println!(
                "observed: {} unreachable target: {:?}: {err}",
                server.name,
                err.kind()
            ),
        }
        assert!(
            !matches!(&result, Ok(data) if !data.is_empty()),
            "{}: data from a closed port",
            server.name
        );
        if server.version == 6 {
            let err = result.expect_err("v6 servers answer with an error reply");
            assert_eq!(
                err.kind(),
                io::ErrorKind::ConnectionRefused,
                "{}",
                server.name
            );
        }
    }
}

#[tokio::test]
#[ignore = "needs official snell-server binaries; run by the interop CI job"]
async fn ping_is_answered_with_pong() {
    for server in servers() {
        let result = tokio::time::timeout(TIMEOUT, outbound(&server, false).ping())
            .await
            .unwrap_or_else(|_| panic!("{}: timed out", server.name));
        println!("observed: {} ping: {result:?}", server.name);
        if server.version == 6 {
            result.unwrap_or_else(|err| panic!("{}: {err}", server.name));
        }
    }
}

#[tokio::test]
#[ignore = "needs official snell-server binaries; run by the interop CI job"]
async fn udp_datagrams_are_relayed() {
    let echo = target("NC_UDP_ECHO");
    let echo_addr: SocketAddr = env("NC_UDP_ECHO").parse().unwrap();
    // Every server and size is tried before failing, so one run reports
    // the full picture.
    let mut failures = Vec::new();
    for server in servers() {
        if server.version < 3 {
            continue;
        }
        let outbound = outbound(&server, false);
        let (mut sender, mut receiver) = tokio::time::timeout(TIMEOUT, outbound.udp())
            .await
            .unwrap_or_else(|_| panic!("{}: timed out", server.name))
            .unwrap_or_else(|err| panic!("{}: udp: {err}", server.name));
        for size in [1usize, 512, 1400, 2048, 4096, 8000] {
            let payload: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            assert!(sender.send_to(&echo, &payload).await.unwrap());
            let (source, echoed) = tokio::time::timeout(TIMEOUT, receiver.recv_from())
                .await
                .unwrap_or_else(|_| panic!("{} udp {size}: timed out", server.name))
                .unwrap_or_else(|err| panic!("{} udp {size}: {err}", server.name));
            if source != echo_addr {
                failures.push(format!("{} udp {size}: source {source}", server.name));
            }
            if echoed != payload {
                let first_diff = echoed
                    .iter()
                    .zip(&payload)
                    .position(|(a, b)| a != b)
                    .unwrap_or(echoed.len().min(payload.len()));
                println!(
                    "observed: {} udp {size}: echoed {} bytes, first difference at {first_diff}",
                    server.name,
                    echoed.len()
                );
                failures.push(format!("{} udp {size}: payload differs", server.name));
                // The echo of this datagram may be split; start over on a
                // fresh session so later sizes are measured cleanly.
                break;
            }
        }
        println!("{}: udp done", server.name);
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// A large datagram as the first one on a fresh session. snell-server
/// v5.0.1 echoed it differently in early runs (while the stepped sizes above
/// pass), so v5 is measured here and only v4/v6 are asserted until the spec
/// settles v5 downstream datagram limits.
#[tokio::test]
#[ignore = "needs official snell-server binaries; run by the interop CI job"]
async fn large_first_udp_datagram() {
    let echo = target("NC_UDP_ECHO");
    let mut failures = Vec::new();
    for server in servers() {
        if server.version < 3 {
            continue;
        }
        let outbound = outbound(&server, false);
        let (mut sender, mut receiver) = tokio::time::timeout(TIMEOUT, outbound.udp())
            .await
            .unwrap_or_else(|_| panic!("{}: timed out", server.name))
            .unwrap_or_else(|err| panic!("{}: udp: {err}", server.name));
        let payload: Vec<u8> = (0..8000).map(|i| (i % 256) as u8).collect();
        assert!(sender.send_to(&echo, &payload).await.unwrap());
        let mut received = Vec::new();
        while let Ok(result) =
            tokio::time::timeout(Duration::from_secs(2), receiver.recv_from()).await
        {
            match result {
                Ok(datagram) => received.push(datagram),
                Err(err) => {
                    println!("observed: {}   receive error: {err}", server.name);
                    break;
                }
            }
        }
        let lengths: Vec<usize> = received.iter().map(|(_, data)| data.len()).collect();
        let intact = received.len() == 1 && received[0].1 == payload;
        let is_prefix = received
            .first()
            .is_some_and(|(_, data)| payload.starts_with(data));
        println!(
            "observed: {} first udp 8000: {} datagram(s) with lengths {lengths:?}, intact={intact}, prefix={is_prefix}",
            server.name,
            received.len()
        );
        for (source, data) in received.iter().skip(1) {
            println!(
                "observed: {}   extra datagram from {source}, first bytes {:02x?}",
                server.name,
                &data[..data.len().min(8)]
            );
        }
        // snell-server v5 speaks protocol version 4, so match it by name.
        if !intact && !server.name.starts_with("snell-v5") {
            failures.push(format!(
                "{} first udp 8000: lengths {lengths:?}",
                server.name
            ));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
