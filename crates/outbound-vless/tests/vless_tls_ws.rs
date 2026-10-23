//! VLESS without REALITY (plain TCP, standard TLS, TLS + WebSocket) against
//! an in-process VLESS server built from `tokio-rustls` and
//! `tokio-tungstenite`.

use std::net::SocketAddr;
use std::sync::Arc;

use engine_outbound::registry::OutboundRegistry;
use engine_outbound::{TargetAddr, TcpDialer, TcpOutbound};
use futures::{SinkExt, StreamExt};
use outbound_vless::{parse_uuid, VlessFactory};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Plain,
    Tls,
    TlsWs,
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

/// Sends a banner first, to check the response header is stripped before
/// the target's bytes even when the client reads first.
async fn banner_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let _ = stream.write_all(b"220 ready\r\n").await;
        }
    });
    addr
}

fn tls_acceptor() -> tokio_rustls::TlsAcceptor {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["vless.test".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

/// Byte stream view of a WebSocket: binary messages in, binary messages out.
fn websocket_bytes<S>(mut ws: tokio_tungstenite::WebSocketStream<S>) -> DuplexStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (outer, mut inner) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let mut chunk = vec![0u8; 16 * 1024];
        loop {
            tokio::select! {
                message = ws.next() => match message {
                    Some(Ok(Message::Binary(data))) => {
                        if inner.write_all(&data).await.is_err() {
                            return;
                        }
                    }
                    Some(Ok(_)) => {}
                    _ => return,
                },
                read = inner.read(&mut chunk) => match read {
                    Ok(n) if n > 0 => {
                        if ws.send(Message::Binary(chunk[..n].to_vec().into())).await.is_err() {
                            return;
                        }
                    }
                    _ => return,
                },
            }
        }
    });
    outer
}

/// Reads the VLESS request header and relays to the requested target.
async fn serve_vless<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S) {
    let expected = parse_uuid(UUID).unwrap();
    let mut head = [0u8; 18];
    if stream.read_exact(&mut head).await.is_err() || head[0] != 0 || head[1..17] != expected {
        return;
    }
    let mut addons = vec![0u8; usize::from(head[17])];
    let mut fixed = [0u8; 4];
    if stream.read_exact(&mut addons).await.is_err()
        || stream.read_exact(&mut fixed).await.is_err()
        || fixed[0] != 1
    {
        return;
    }
    let port = u16::from_be_bytes([fixed[1], fixed[2]]);
    let host = match fixed[3] {
        1 => {
            let mut ip = [0u8; 4];
            if stream.read_exact(&mut ip).await.is_err() {
                return;
            }
            std::net::Ipv4Addr::from(ip).to_string()
        }
        2 => {
            let mut len = [0u8; 1];
            if stream.read_exact(&mut len).await.is_err() {
                return;
            }
            let mut name = vec![0u8; usize::from(len[0])];
            if stream.read_exact(&mut name).await.is_err() {
                return;
            }
            String::from_utf8(name).unwrap_or_default()
        }
        _ => return,
    };
    let Ok(mut upstream) = TcpStream::connect((host.as_str(), port)).await else {
        return;
    };
    // Response header with one addon byte, to exercise addon skipping.
    if stream.write_all(&[0, 1, 0xaa]).await.is_err() {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
}

async fn vless_server(mode: Mode) -> SocketAddr {
    let acceptor = tls_acceptor();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                match mode {
                    Mode::Plain => serve_vless(stream).await,
                    Mode::Tls => {
                        if let Ok(tls) = acceptor.accept(stream).await {
                            serve_vless(tls).await;
                        }
                    }
                    Mode::TlsWs => {
                        let Ok(tls) = acceptor.accept(stream).await else {
                            return;
                        };
                        if let Ok(ws) = tokio_tungstenite::accept_async(tls).await {
                            serve_vless(websocket_bytes(ws)).await;
                        }
                    }
                }
            });
        }
    });
    addr
}

fn settings(server: SocketAddr, mode: Mode) -> serde_json::Map<String, serde_json::Value> {
    let tls = serde_json::json!({"server_name": "vless.test", "insecure": true});
    let mut value = serde_json::json!({
        "server": server.ip().to_string(),
        "port": server.port(),
        "uuid": UUID,
    });
    if mode != Mode::Plain {
        value["tls"] = tls;
    }
    if mode == Mode::TlsWs {
        value["transport"] = serde_json::json!({"type": "ws", "path": "/vl"});
    }
    value.as_object().unwrap().clone()
}

fn registry() -> OutboundRegistry {
    let mut registry = OutboundRegistry::new();
    registry.register(Arc::new(VlessFactory));
    registry
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relays_over_plain_tls_and_websocket() {
    let echo = echo_server().await;
    for mode in [Mode::Plain, Mode::Tls, Mode::TlsWs] {
        let server = vless_server(mode).await;
        let vless = registry()
            .build("vless", &settings(server, mode), Arc::new(TcpDialer))
            .unwrap();
        assert_eq!(vless.protocol(), "vless");
        for target in [
            TargetAddr::Ip(echo),
            TargetAddr::Domain("localhost".into(), echo.port()),
        ] {
            let mut stream = vless.connect(&target).await.unwrap();
            stream.write_all(b"hello vless").await.unwrap();
            stream.flush().await.unwrap();
            let mut echoed = [0u8; 11];
            stream.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"hello vless", "{target}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_speaks_first_targets_work() {
    let banner = banner_server().await;
    for mode in [Mode::Plain, Mode::TlsWs] {
        let server = vless_server(mode).await;
        let vless = registry()
            .build("vless", &settings(server, mode), Arc::new(TcpDialer))
            .unwrap();
        let mut stream = vless.connect(&TargetAddr::Ip(banner)).await.unwrap();
        let mut line = [0u8; 11];
        stream.read_exact(&mut line).await.unwrap();
        assert_eq!(&line, b"220 ready\r\n");
    }
}

#[test]
fn factory_rejects_inconsistent_settings() {
    let reality = serde_json::json!({
        "server_name": "www.example.com",
        "public_key": "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw",
    });
    let base = |extra: serde_json::Value| {
        let mut value = serde_json::json!({"server": "192.0.2.1", "port": 443, "uuid": UUID});
        for (key, item) in extra.as_object().unwrap() {
            value[key] = item.clone();
        }
        value.as_object().unwrap().clone()
    };
    for bad in [
        // Vision needs REALITY in this build.
        base(serde_json::json!({"flow": "xtls-rprx-vision", "tls": {}})),
        base(serde_json::json!({"reality": reality.clone(), "tls": {}})),
        base(serde_json::json!({"reality": reality.clone(), "transport": {"type": "ws"}})),
        base(serde_json::json!({"transport": {"type": "grpc"}})),
        base(serde_json::json!({"tls": {"server_name": "a", "spider": 1}})),
    ] {
        assert!(registry()
            .build("vless", &bad, Arc::new(TcpDialer))
            .is_err());
    }
    for good in [
        base(serde_json::json!({})),
        base(serde_json::json!({"tls": {}})),
        base(serde_json::json!({"reality": reality.clone(), "flow": "xtls-rprx-vision"})),
    ] {
        assert!(registry()
            .build("vless", &good, Arc::new(TcpDialer))
            .is_ok());
    }
}
