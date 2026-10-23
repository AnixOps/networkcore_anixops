//! Interop: the engine's Shadowsocks-2022 client against the shadowsocks-rust server.

#![cfg(unix)]

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use engine_embedded::shadowsocks::{Method, Ss2022Outbound};
use engine_outbound::{TargetAddr, TcpDialer, TcpOutbound};
use shadowsocks::config::{ServerConfig, ServerType, ServerUser, ServerUserManager};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::socks5::Address;
use shadowsocks::ProxyListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TIMEOUT: Duration = Duration::from_secs(10);

fn kind_for(method: Method) -> CipherKind {
    match method {
        Method::Aes128Gcm => CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
        Method::Aes256Gcm => CipherKind::AEAD2022_BLAKE3_AES_256_GCM,
        Method::ChaCha20Poly1305 => CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305,
    }
}

fn test_key(method: Method) -> String {
    let key: Vec<u8> = (0..method.key_len())
        .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
        .collect();
    base64::engine::general_purpose::STANDARD.encode(key)
}

fn other_key(method: Method) -> String {
    let key: Vec<u8> = (0..method.key_len())
        .map(|i| (i as u8).wrapping_mul(53).wrapping_add(7))
        .collect();
    base64::engine::general_purpose::STANDARD.encode(key)
}

/// Starts a reference server that relays every session to its requested target.
async fn start_reference_server(method: Method, password: &str) -> SocketAddr {
    start_reference_server_with_user(method, password, None).await
}

/// With `user_key`, `password` is the server's identity key and sessions must
/// carry an identity header naming that user.
async fn start_reference_server_with_user(
    method: Method,
    password: &str,
    user_key: Option<&str>,
) -> SocketAddr {
    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut config =
        ServerConfig::new(bind, password.to_string(), kind_for(method)).expect("server config");
    if let Some(user_key) = user_key {
        let mut users = ServerUserManager::new();
        users.add_user(ServerUser::with_encoded_key("user", user_key).expect("user key"));
        config.set_user_manager(users);
    }
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

fn outbound(method: Method, server: SocketAddr, password: &str) -> Ss2022Outbound {
    Ss2022Outbound::new(
        server.ip().to_string(),
        server.port(),
        method,
        password,
        Arc::new(TcpDialer),
    )
    .expect("valid outbound")
}

async fn echo_round_trip(method: Method, payload_len: usize) -> io::Result<()> {
    let password = test_key(method);
    let server = start_reference_server(method, &password).await;
    let echo = start_echo_server(None).await;
    let client = outbound(method, server, &password);

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
async fn aes_128_gcm_round_trips_small_payload() {
    echo_round_trip(Method::Aes128Gcm, 64).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aes_256_gcm_round_trips_multi_chunk_payload() {
    echo_round_trip(Method::Aes256Gcm, 300 * 1024)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chacha20_poly1305_round_trips_multi_chunk_payload() {
    echo_round_trip(Method::ChaCha20Poly1305, 100 * 1024 + 7)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_speaks_first_without_client_payload() {
    let method = Method::Aes128Gcm;
    let password = test_key(method);
    let server = start_reference_server(method, &password).await;
    let echo = start_echo_server(Some(b"220 ready\r\n")).await;
    let client = outbound(method, server, &password);

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
async fn wrong_key_fails_without_leaking_it() {
    let method = Method::Aes256Gcm;
    let password = test_key(method);
    let server = start_reference_server(method, &password).await;
    let echo = start_echo_server(None).await;
    let wrong = base64::engine::general_purpose::STANDARD.encode([0x5au8; 32]);
    let client = outbound(method, server, &wrong);

    let mut stream = client.connect(&TargetAddr::Ip(echo)).await.unwrap();
    stream.write_all(b"hello").await.unwrap();
    stream.flush().await.unwrap();
    let mut buf = [0u8; 5];
    let result = tokio::time::timeout(TIMEOUT, stream.read_exact(&mut buf))
        .await
        .expect("server should close a session it cannot decrypt");
    let err = result.expect_err("a wrong key must not produce data");
    assert!(!err.to_string().contains(&wrong));
    assert!(!err.to_string().contains(&password));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn identity_header_reaches_multi_user_server() {
    for method in [Method::Aes128Gcm, Method::Aes256Gcm] {
        let identity_key = test_key(method);
        let user_key = other_key(method);
        let server = start_reference_server_with_user(method, &identity_key, Some(&user_key)).await;
        let echo = start_echo_server(None).await;
        let client = outbound(method, server, &format!("{identity_key}:{user_key}"));

        let mut stream = client.connect(&TargetAddr::Ip(echo)).await.unwrap();
        stream.write_all(b"multi-user").await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = [0u8; 10];
        tokio::time::timeout(TIMEOUT, stream.read_exact(&mut echoed))
            .await
            .expect("echo timed out")
            .unwrap();
        assert_eq!(&echoed, b"multi-user", "{}", method.name());
    }
}
