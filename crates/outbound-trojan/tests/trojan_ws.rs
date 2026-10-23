//! Trojan over WebSocket over TLS, against an in-process server built from
//! `tokio-rustls` and `tokio-tungstenite`.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use engine_outbound::registry::OutboundRegistry;
use engine_outbound::{TargetAddr, TcpDialer, TcpOutbound};
use futures::{SinkExt, StreamExt};
use outbound_trojan::{password_hash, TrojanFactory, TrojanOutbound};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::Message;
use transport_tls::TlsSettings;
use transport_ws::{WsConnector, WsSettings};

const PASSWORD: &str = "correct horse";

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

/// Parses `hash CRLF CMD ATYP ADDR PORT CRLF`; returns the target and the
/// header length once the buffer holds all of it.
fn parse_request(buf: &[u8]) -> Option<(String, u16, usize)> {
    if buf.len() < 60 || buf[..56] != password_hash(PASSWORD) || buf[58] != 1 {
        return None;
    }
    let (host, mut at) = match buf[59] {
        1 if buf.len() >= 64 => (
            std::net::Ipv4Addr::new(buf[60], buf[61], buf[62], buf[63]).to_string(),
            64,
        ),
        3 if buf.len() >= 61 => {
            let len = usize::from(buf[60]);
            let end = 61 + len;
            (String::from_utf8(buf.get(61..end)?.to_vec()).ok()?, end)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([*buf.get(at)?, *buf.get(at + 1)?]);
    at += 2;
    (buf.get(at..at + 2)? == b"\r\n").then_some((host, port, at + 2))
}

async fn trojan_ws_server() -> (SocketAddr, Arc<Mutex<String>>) {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["trojan.test".to_string()])
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
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen_path = Arc::new(Mutex::new(String::new()));
    let record = seen_path.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let record = record.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let callback = move |request: &Request,
                                     response: Response|
                      -> Result<Response, ErrorResponse> {
                    *record.lock().unwrap() = request.uri().path().to_owned();
                    Ok(response)
                };
                let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(tls, callback).await else {
                    return;
                };
                let mut buf = Vec::new();
                let (host, port, used) = loop {
                    match ws.next().await {
                        Some(Ok(Message::Binary(data))) => buf.extend_from_slice(&data),
                        _ => return,
                    }
                    if let Some(parsed) = parse_request(&buf) {
                        break parsed;
                    }
                };
                let Ok(mut upstream) = TcpStream::connect((host.as_str(), port)).await else {
                    return;
                };
                if upstream.write_all(&buf[used..]).await.is_err() {
                    return;
                }
                let mut chunk = vec![0u8; 16 * 1024];
                loop {
                    tokio::select! {
                        message = ws.next() => match message {
                            Some(Ok(Message::Binary(data))) => {
                                if upstream.write_all(&data).await.is_err() {
                                    return;
                                }
                            }
                            Some(Ok(_)) => {}
                            _ => return,
                        },
                        read = upstream.read(&mut chunk) => match read {
                            Ok(n) if n > 0 => {
                                let data = chunk[..n].to_vec();
                                if ws.send(Message::Binary(data.into())).await.is_err() {
                                    return;
                                }
                            }
                            _ => return,
                        },
                    }
                }
            });
        }
    });
    (addr, seen_path)
}

fn tls() -> TlsSettings {
    TlsSettings {
        server_name: "trojan.test".into(),
        alpn: Vec::new(),
        insecure: true,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relays_over_websocket_inside_tls() {
    let echo = echo_server().await;
    let (server, seen_path) = trojan_ws_server().await;
    let websocket = WsConnector::new(
        &WsSettings {
            path: "/trojan-ws".into(),
            ..WsSettings::default()
        },
        "trojan.test",
    )
    .unwrap();
    let trojan = TrojanOutbound::new(
        server.ip().to_string(),
        server.port(),
        PASSWORD,
        &tls(),
        Arc::new(TcpDialer),
    )
    .unwrap()
    .with_websocket(websocket);
    for target in [
        TargetAddr::Ip(echo),
        TargetAddr::Domain("localhost".into(), echo.port()),
    ] {
        let mut stream = trojan.connect(&target).await.unwrap();
        stream.write_all(b"hello trojan ws").await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = [0u8; 15];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello trojan ws", "{target}");
    }
    assert_eq!(*seen_path.lock().unwrap(), "/trojan-ws");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn factory_builds_the_ws_transport_from_settings() {
    let echo = echo_server().await;
    let (server, seen_path) = trojan_ws_server().await;
    let mut registry = OutboundRegistry::new();
    registry.register(Arc::new(TrojanFactory));
    let settings = serde_json::json!({
        "server": server.ip().to_string(),
        "port": server.port(),
        "password": PASSWORD,
        "server_name": "trojan.test",
        "insecure": true,
        "transport": {"type": "ws", "path": "/from-config"},
    });
    let settings = settings.as_object().unwrap().clone();
    let trojan = registry
        .build("trojan", &settings, Arc::new(TcpDialer))
        .unwrap();
    let mut stream = trojan.connect(&TargetAddr::Ip(echo)).await.unwrap();
    stream.write_all(b"cfg").await.unwrap();
    stream.flush().await.unwrap();
    let mut echoed = [0u8; 3];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"cfg");
    assert_eq!(*seen_path.lock().unwrap(), "/from-config");

    for bad in [
        serde_json::json!({"server": "s", "port": 1, "password": "p", "transport": {"type": "grpc"}}),
        serde_json::json!({"server": "s", "port": 1, "password": "p", "transport": {"type": "ws", "path": "no-slash"}}),
    ] {
        let bad = bad.as_object().unwrap().clone();
        assert!(registry.build("trojan", &bad, Arc::new(TcpDialer)).is_err());
    }
}
