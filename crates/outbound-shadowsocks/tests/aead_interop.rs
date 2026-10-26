//! Interop: the engine's Shadowsocks AEAD (SIP004) client against the
//! shadowsocks-rust server, and the factory's method dispatch.

#![cfg(unix)]

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use engine_outbound::registry::OutboundRegistry;
use engine_outbound::{TargetAddr, TcpDialer, TcpOutbound};
use outbound_shadowsocks::{AeadMethod, AeadOutbound, ShadowsocksFactory};
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::udprelay::options::UdpSocketControlData;
use shadowsocks::{ProxyListener, ProxySocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TIMEOUT: Duration = Duration::from_secs(10);
const PASSWORD: &str = "interop-password";
const METHODS: [AeadMethod; 3] = [
    AeadMethod::Aes128Gcm,
    AeadMethod::Aes256Gcm,
    AeadMethod::ChaCha20Poly1305,
];

fn kind_for(method: AeadMethod) -> CipherKind {
    match method {
        AeadMethod::Aes128Gcm => CipherKind::AES_128_GCM,
        AeadMethod::Aes256Gcm => CipherKind::AES_256_GCM,
        AeadMethod::ChaCha20Poly1305 => CipherKind::CHACHA20_POLY1305,
    }
}

/// Starts a reference server that relays every session to its requested target.
async fn start_reference_server(method: AeadMethod) -> SocketAddr {
    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config =
        ServerConfig::new(bind, PASSWORD.to_string(), kind_for(method)).expect("server config");
    let context = Context::new_shared(ServerType::Server);
    let listener = ProxyListener::bind(context, &config)
        .await
        .expect("bind reference server");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut session, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let target = match session.handshake().await {
                    Ok(Address::SocketAddress(addr)) => addr,
                    _ => return,
                };
                let Ok(mut upstream) = TcpStream::connect(target).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut session, &mut upstream).await;
            });
        }
    });
    addr
}

/// A reference UDP server that answers each packet with its own payload, as
/// if the target had echoed it.
async fn start_reference_udp_echo(method: AeadMethod) -> SocketAddr {
    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config =
        ServerConfig::new(bind, PASSWORD.to_string(), kind_for(method)).expect("server config");
    let socket = ProxySocket::bind(Context::new_shared(ServerType::Server), &config)
        .await
        .expect("bind reference udp server");
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_536];
        let mut reply = UdpSocketControlData::default();
        loop {
            reply.server_session_id = 0x5e4e_0000_0000_0001;
            let Ok((n, peer, target, _, control)) = socket.recv_from_with_ctrl(&mut buf).await
            else {
                continue;
            };
            if let Some(control) = control {
                reply.client_session_id = control.client_session_id;
                reply.user = control.user;
            }
            reply.packet_id += 1;
            let payload = buf[..n].to_vec();
            let _ = socket
                .send_to_with_ctrl(peer, &target, &reply, &payload)
                .await;
        }
    });
    addr
}

/// Echo server; with `banner` it speaks first.
async fn start_echo_server(banner: Option<&'static [u8]>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                if let Some(banner) = banner {
                    if stream.write_all(banner).await.is_err() {
                        return;
                    }
                }
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    addr
}

fn outbound(method: AeadMethod, server: SocketAddr, password: &str) -> AeadOutbound {
    AeadOutbound::new(
        server.ip().to_string(),
        server.port(),
        method,
        password,
        Arc::new(TcpDialer),
    )
    .expect("valid outbound")
}

async fn echo_round_trip(method: AeadMethod, payload_len: usize) -> io::Result<()> {
    let server = start_reference_server(method).await;
    let echo = start_echo_server(None).await;
    let client = outbound(method, server, PASSWORD);

    let mut stream = client.connect(&TargetAddr::Ip(echo)).await?;
    let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
    let (mut reader, mut writer) = tokio::io::split(&mut stream);
    let expected = payload.clone();
    let write = async move {
        writer.write_all(&payload).await?;
        writer.flush().await?;
        Ok::<_, io::Error>(())
    };
    let read = async move {
        let mut received = vec![0u8; expected.len()];
        reader.read_exact(&mut received).await?;
        Ok::<_, io::Error>(received == expected)
    };
    let (written, matched) = tokio::time::timeout(TIMEOUT, async { tokio::join!(write, read) })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "echo timed out"))?;
    written?;
    assert!(matched?, "echoed bytes differ for {}", method.name());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_method_round_trips_small_and_multi_chunk_payloads() {
    for method in METHODS {
        echo_round_trip(method, 64).await.unwrap();
        echo_round_trip(method, 200 * 1024 + 7).await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_speaks_first_without_client_payload() {
    let method = AeadMethod::ChaCha20Poly1305;
    let server = start_reference_server(method).await;
    let echo = start_echo_server(Some(b"220 ready\r\n")).await;
    let client = outbound(method, server, PASSWORD);

    let mut stream = client.connect(&TargetAddr::Ip(echo)).await.unwrap();
    let mut banner = [0u8; 11];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut banner))
        .await
        .expect("banner timed out")
        .unwrap();
    assert_eq!(&banner, b"220 ready\r\n");

    stream.write_all(b"QUIT\r\n").await.unwrap();
    stream.flush().await.unwrap();
    let mut echoed = [0u8; 6];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut echoed))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(&echoed, b"QUIT\r\n");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_password_gets_no_data() {
    let method = AeadMethod::Aes256Gcm;
    let server = start_reference_server(method).await;
    let echo = start_echo_server(None).await;
    let client = outbound(method, server, "not-the-password");

    let mut stream = client.connect(&TargetAddr::Ip(echo)).await.unwrap();
    stream.write_all(b"hello").await.unwrap();
    stream.flush().await.unwrap();
    let mut buf = [0u8; 5];
    let result = tokio::time::timeout(TIMEOUT, stream.read_exact(&mut buf))
        .await
        .expect("server should close a session it cannot decrypt");
    let err = result.expect_err("a wrong password must not produce data");
    assert!(!err.to_string().contains(PASSWORD));
}

#[test]
fn factory_picks_the_protocol_from_the_method() {
    let mut registry = OutboundRegistry::new();
    registry.register(Arc::new(ShadowsocksFactory));
    let settings = |method: &str, password: &str| {
        serde_json::json!({
            "server": "192.0.2.1",
            "port": 8388,
            "method": method,
            "password": password,
        })
        .as_object()
        .unwrap()
        .clone()
    };
    let key = "AAECAwQFBgcICQoLDA0ODw==";
    for (method, password, protocol) in [
        ("aes-128-gcm", PASSWORD, "shadowsocks"),
        ("chacha20-ietf-poly1305", PASSWORD, "shadowsocks"),
        ("2022-blake3-aes-128-gcm", key, "shadowsocks-2022"),
    ] {
        let outbound = registry
            .build(
                "shadowsocks",
                &settings(method, password),
                Arc::new(TcpDialer),
            )
            .unwrap();
        assert_eq!(outbound.protocol(), protocol, "{method}");
    }
    for (method, password) in [
        ("aes-128-cfb", PASSWORD),
        ("rc4-md5", PASSWORD),
        ("aes-128-gcm", ""),
        ("2022-blake3-aes-128-gcm", PASSWORD),
    ] {
        assert!(registry
            .build(
                "shadowsocks",
                &settings(method, password),
                Arc::new(TcpDialer)
            )
            .is_err());
    }
}

/// Sends two datagrams through a fresh flow and expects each echoed back.
async fn udp_round_trip(outbound: &dyn TcpOutbound, target: TargetAddr) {
    let mut flow = outbound.open_udp(&target).await.expect("udp flow opens");
    for payload in [b"hello".to_vec(), vec![5u8; 1200]] {
        flow.send.send(&payload).await.unwrap();
        let reply = tokio::time::timeout(TIMEOUT, flow.recv.recv())
            .await
            .expect("udp reply timed out")
            .unwrap();
        assert_eq!(reply, payload);
    }
}

fn udp_targets() -> [TargetAddr; 2] {
    [
        TargetAddr::Ip("127.0.0.1:9".parse().unwrap()),
        TargetAddr::Domain("echo.test".into(), 53),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_method_relays_udp() {
    for method in METHODS {
        let server = start_reference_udp_echo(method).await;
        for target in udp_targets() {
            udp_round_trip(&outbound(method, server, PASSWORD), target).await;
        }
    }
}
