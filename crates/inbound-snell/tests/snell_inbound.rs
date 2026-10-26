//! The Snell server inbound against the engine's Snell client.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use engine_inbound::registry::{InboundFactory, Settings};
use engine_inbound::server::{serve_with_udp, InboundStats, ServeSettings};
use engine_inbound::udp::{UdpOutbound, UdpSession};
use engine_inbound::StreamInbound;
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpDialer, TcpOutbound};
use inbound_snell::SnellInboundFactory;
use outbound_snell::request::{encode_request, Command};
use outbound_snell::{Encoder, Framing, HttpObfsSettings, SnellOptions, SnellOutbound, V6Mode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const PSK: &str = "inbound test psk";
const TIMEOUT: Duration = Duration::from_secs(20);

struct Direct;

impl TcpOutbound for Direct {
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

struct DirectUdp;

impl UdpOutbound for DirectUdp {
    fn bind(&self) -> BoxFuture<'_, std::io::Result<Arc<dyn UdpSession>>> {
        Box::pin(async {
            let socket = UdpSocket::bind("127.0.0.1:0").await?;
            Ok(Arc::new(Socket(socket)) as Arc<dyn UdpSession>)
        })
    }
}

struct Socket(UdpSocket);

impl UdpSession for Socket {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        target: &'a TargetAddr,
    ) -> BoxFuture<'a, std::io::Result<()>> {
        Box::pin(async move {
            self.0
                .send_to(payload, (target.host(), target.port()))
                .await
                .map(|_| ())
        })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, std::io::Result<(usize, SocketAddr)>> {
        Box::pin(self.0.recv_from(buf))
    }
}

async fn udp_echo_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], from).await;
        }
    });
    addr
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

/// Accepts and closes every connection without sending anything.
async fn silent_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            drop(stream);
        }
    });
    addr
}

struct Server {
    addr: SocketAddr,
    stats: Arc<InboundStats>,
}

async fn start(settings: serde_json::Value) -> Server {
    let settings: Settings = serde_json::from_value(settings).unwrap();
    let inbound: Arc<dyn StreamInbound> = SnellInboundFactory.build(&settings).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stats = Arc::new(InboundStats::default());
    tokio::spawn(serve_with_udp(
        listener,
        inbound,
        Arc::new(Direct),
        Some(Arc::new(DirectUdp)),
        ServeSettings::default(),
        stats.clone(),
    ));
    Server { addr, stats }
}

fn client(server: &Server, version: u8, mode: V6Mode, obfs: bool, reuse: bool) -> SnellOutbound {
    client_with_key(server, version, mode, obfs, reuse, b"")
}

fn client_with_key(
    server: &Server,
    version: u8,
    mode: V6Mode,
    obfs: bool,
    reuse: bool,
    user_key: &[u8],
) -> SnellOutbound {
    let options = SnellOptions {
        version,
        mode,
        psk: PSK.as_bytes().to_vec(),
        obfs: obfs.then(|| HttpObfsSettings {
            host: "bing.com".into(),
            uri: "/".into(),
        }),
        reuse,
        user_key: user_key.to_vec(),
    };
    SnellOutbound::new(
        server.addr.ip().to_string(),
        server.addr.port(),
        options,
        Arc::new(TcpDialer),
    )
    .unwrap()
}

/// Sends `payload` through the echo target and reads it back.
async fn round_trip(outbound: &SnellOutbound, echo: SocketAddr, payload: &[u8]) -> Vec<u8> {
    tokio::time::timeout(TIMEOUT, async {
        let mut stream = outbound.connect_stream(&TargetAddr::Ip(echo)).await?;
        stream.write_all(payload).await?;
        stream.flush().await?;
        let mut back = vec![0u8; payload.len()];
        stream.read_exact(&mut back).await?;
        stream.shutdown().await?;
        Ok::<_, std::io::Error>(back)
    })
    .await
    .expect("round trip timed out")
    .expect("round trip failed")
}

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

#[tokio::test]
async fn every_version_and_mode_relays_through_the_inbound() {
    let echo = echo_server().await;
    let cases: &[(u8, Option<&str>, bool)] = &[
        (1, None, false),
        (2, None, false),
        (3, None, false),
        (3, None, true),
        (4, None, false),
        (4, None, true),
        (6, Some("default"), false),
        (6, Some("unshaped"), false),
        (6, Some("unsafe-raw"), false),
    ];
    for &(version, mode, obfs) in cases {
        let mut settings = serde_json::json!({ "psk": PSK, "version": version });
        if let Some(mode) = mode {
            settings["mode"] = mode.into();
        }
        if obfs {
            settings["obfs"] = "http".into();
        }
        let server = start(settings).await;
        let mode = mode.and_then(V6Mode::parse).unwrap_or(V6Mode::Default);
        for reuse in [false, true] {
            let outbound = client(&server, version, mode, obfs, reuse);
            for len in [1usize, 1000, 200_000] {
                let data = payload(len);
                let back = round_trip(&outbound, echo, &data).await;
                assert!(
                    back == data,
                    "v{version} {mode:?} obfs={obfs} reuse={reuse}: {len} bytes differ"
                );
            }
        }
    }
}

#[tokio::test]
async fn v5_clients_use_a_v4_server() {
    let echo = echo_server().await;
    let server = start(serde_json::json!({ "psk": PSK, "version": 4 })).await;
    let outbound = client(&server, 5, V6Mode::Default, false, true);
    let data = payload(5000);
    assert!(round_trip(&outbound, echo, &data).await == data);
}

#[tokio::test]
async fn ping_is_answered() {
    for (version, mode) in [(4, None), (6, Some("default")), (6, Some("unsafe-raw"))] {
        let mut settings = serde_json::json!({ "psk": PSK, "version": version });
        if let Some(mode) = mode {
            settings["mode"] = mode.into();
        }
        let server = start(settings).await;
        let mode = mode.and_then(V6Mode::parse).unwrap_or(V6Mode::Default);
        tokio::time::timeout(TIMEOUT, client(&server, version, mode, false, false).ping())
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn users_are_matched_by_user_key() {
    let echo = echo_server().await;
    let server = start(serde_json::json!({
        "psk": PSK,
        "version": 4,
        "users": [{ "name": "alice", "password": "alice-key" }],
    }))
    .await;
    let data = payload(100);
    let alice = client_with_key(&server, 4, V6Mode::Default, false, false, b"alice-key");
    // PING has no clientID and is answered on a multi-user server too.
    tokio::time::timeout(TIMEOUT, alice.ping())
        .await
        .unwrap()
        .unwrap();
    assert!(round_trip(&alice, echo, &data).await == data);

    let stranger = client_with_key(&server, 4, V6Mode::Default, false, false, b"other-key");
    let result = tokio::time::timeout(TIMEOUT, async {
        let mut stream = stranger.connect_stream(&TargetAddr::Ip(echo)).await?;
        stream.write_all(&data).await?;
        stream.flush().await?;
        let mut back = Vec::new();
        stream.read_to_end(&mut back).await.map(|_| back)
    })
    .await
    .unwrap();
    assert!(
        !matches!(&result, Ok(back) if !back.is_empty()),
        "an unknown user key got data back"
    );
    assert!(server.stats.handshake_failed.load(Ordering::Relaxed) >= 1);
}

#[tokio::test]
async fn a_target_that_closes_at_once_ends_the_stream() {
    let silent = silent_server().await;
    for version in [3u8, 4] {
        let server = start(serde_json::json!({ "psk": PSK, "version": version })).await;
        let outbound = client(&server, version, V6Mode::Default, false, false);
        let result = tokio::time::timeout(TIMEOUT, async {
            let mut stream = outbound.connect_stream(&TargetAddr::Ip(silent)).await?;
            stream.write_all(b"hello").await?;
            stream.flush().await?;
            let mut back = Vec::new();
            stream.read_to_end(&mut back).await.map(|_| back)
        })
        .await
        .unwrap();
        // Normally the ERROR reply ends the stream cleanly; a reset of the
        // closed target can end it with an error instead. Either way no data.
        assert!(
            !matches!(&result, Ok(back) if !back.is_empty()),
            "v{version}: data from a silent target"
        );
    }
}

#[tokio::test]
async fn a_replayed_first_frame_is_dropped() {
    let echo = echo_server().await;
    let server = start(serde_json::json!({ "psk": PSK, "version": 4 })).await;
    let mut plaintext = Vec::new();
    encode_request(
        &mut plaintext,
        Command::ConnectV2,
        b"",
        Some(&TargetAddr::Ip(echo)),
    )
    .unwrap();
    plaintext.extend_from_slice(b"replayed");
    let mut wire = Vec::new();
    Encoder::new(Framing::V4, PSK.as_bytes())
        .unwrap()
        .encode(&mut wire, &plaintext)
        .unwrap();

    let mut answers = Vec::new();
    for _ in 0..2 {
        let mut socket = TcpStream::connect(server.addr).await.unwrap();
        socket.write_all(&wire).await.unwrap();
        let mut buf = [0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut buf))
            .await
            .map_or(0, |read| read.unwrap_or(0));
        answers.push(n);
    }
    assert!(answers[0] > 0, "the first connection got no reply");
    assert_eq!(answers[1], 0, "the replayed connection got a reply");
}

#[tokio::test]
async fn garbage_is_closed_without_a_reply() {
    let server = start(serde_json::json!({ "psk": PSK, "version": 6 })).await;
    let mut socket = TcpStream::connect(server.addr).await.unwrap();
    socket.write_all(&[0x42; 600]).await.unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut buf))
        .await
        .map_or(0, |read| read.unwrap_or(0));
    assert_eq!(n, 0);
}

/// One request on a reusable connection, read to the server's zero chunk so
/// the client can pool the connection.
async fn fetch(outbound: &SnellOutbound, echo: SocketAddr, payload: &[u8]) -> Vec<u8> {
    tokio::time::timeout(TIMEOUT, async {
        let mut stream = outbound.connect_stream(&TargetAddr::Ip(echo)).await?;
        stream.write_all(payload).await?;
        stream.shutdown().await?;
        let mut back = Vec::new();
        stream.read_to_end(&mut back).await?;
        Ok::<_, std::io::Error>(back)
    })
    .await
    .expect("fetch timed out")
    .expect("fetch failed")
}

#[tokio::test]
async fn reusing_clients_send_several_requests_on_one_connection() {
    let echo = echo_server().await;
    for (version, mode) in [
        (3u8, None),
        (4, None),
        (6, Some("default")),
        (6, Some("unshaped")),
    ] {
        let mut settings = serde_json::json!({ "psk": PSK, "version": version });
        if let Some(mode) = mode {
            settings["mode"] = mode.into();
        }
        let server = start(settings).await;
        let mode = mode.and_then(V6Mode::parse).unwrap_or(V6Mode::Default);
        let outbound = client(&server, version, mode, false, true);
        for round in 0..4 {
            let data = payload(3000 + round * 7000);
            assert!(
                fetch(&outbound, echo, &data).await == data,
                "v{version} round {round}"
            );
        }
        assert_eq!(
            server.stats.accepted.load(Ordering::Relaxed),
            1,
            "v{version} {mode:?}: requests did not share a connection"
        );
    }
}

#[tokio::test]
async fn unreachable_targets_get_an_error_reply() {
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    };
    for (version, mode) in [(4u8, None), (6, Some("default"))] {
        let mut settings = serde_json::json!({ "psk": PSK, "version": version });
        if let Some(mode) = mode {
            settings["mode"] = mode.into();
        }
        let server = start(settings).await;
        let mode = mode.and_then(V6Mode::parse).unwrap_or(V6Mode::Default);
        let outbound = client(&server, version, mode, false, false);
        let result = tokio::time::timeout(TIMEOUT, async {
            let mut stream = outbound.connect_stream(&TargetAddr::Ip(closed)).await?;
            stream.write_all(b"hello").await?;
            stream.flush().await?;
            let mut back = Vec::new();
            stream.read_to_end(&mut back).await.map(|_| back)
        })
        .await
        .unwrap();
        let err = result.expect_err("a closed port answered");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::ConnectionRefused,
            "v{version}: {err}"
        );
    }
}

#[tokio::test]
async fn udp_datagrams_are_relayed() {
    let echo = udp_echo_server().await;
    for (version, mode) in [
        (3u8, None),
        (4, None),
        (6, Some("default")),
        (6, Some("unsafe-raw")),
    ] {
        let mut settings = serde_json::json!({ "psk": PSK, "version": version });
        if let Some(mode) = mode {
            settings["mode"] = mode.into();
        }
        let server = start(settings).await;
        let mode = mode.and_then(V6Mode::parse).unwrap_or(V6Mode::Default);
        let outbound = client(&server, version, mode, false, false);
        let (mut sender, mut receiver) = tokio::time::timeout(TIMEOUT, outbound.udp())
            .await
            .unwrap()
            .unwrap();
        for size in [1usize, 512, 1400, 8000] {
            let data = payload(size);
            assert!(sender.send_to(&TargetAddr::Ip(echo), &data).await.unwrap());
            let (source, back) = tokio::time::timeout(TIMEOUT, receiver.recv_from())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(source, echo, "v{version}");
            assert!(back == data, "v{version} udp {size}: payload differs");
        }
    }
}
