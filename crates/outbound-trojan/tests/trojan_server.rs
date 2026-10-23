//! The Trojan client against a minimal in-process Trojan server (TLS with a
//! self-signed certificate, password check, CONNECT to the requested target).

use std::net::SocketAddr;
use std::sync::Arc;

use engine_outbound::registry::OutboundRegistry;
use engine_outbound::{TargetAddr, TcpDialer, TcpOutbound};
use outbound_trojan::{password_hash, TrojanFactory, TrojanOutbound};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use transport_tls::TlsSettings;

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

/// A server that sends a banner first, to check that the client sends its
/// request before reading.
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

async fn read_target<S: AsyncRead + Unpin>(stream: &mut S) -> Option<(String, u16)> {
    let mut atyp = [0u8; 1];
    stream.read_exact(&mut atyp).await.ok()?;
    let host = match atyp[0] {
        1 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await.ok()?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.ok()?;
            let mut name = vec![0u8; usize::from(len[0])];
            stream.read_exact(&mut name).await.ok()?;
            String::from_utf8(name).ok()?
        }
        _ => return None,
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await.ok()?;
    Some((host, u16::from_be_bytes(port)))
}

async fn trojan_server() -> SocketAddr {
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
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut head = [0u8; 59];
                if tls.read_exact(&mut head).await.is_err()
                    || head[..56] != password_hash(PASSWORD)
                    || &head[56..58] != b"\r\n"
                    || head[58] != 1
                {
                    return;
                }
                let Some((host, port)) = read_target(&mut tls).await else {
                    return;
                };
                let mut crlf = [0u8; 2];
                if tls.read_exact(&mut crlf).await.is_err() || &crlf != b"\r\n" {
                    return;
                }
                let Ok(mut upstream) = TcpStream::connect((host.as_str(), port)).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut tls, &mut upstream).await;
            });
        }
    });
    addr
}

fn outbound(server: SocketAddr, password: &str) -> TrojanOutbound {
    TrojanOutbound::new(
        server.ip().to_string(),
        server.port(),
        password,
        &TlsSettings {
            server_name: "trojan.test".into(),
            alpn: Vec::new(),
            insecure: true,
        },
        Arc::new(TcpDialer),
    )
    .unwrap()
}

#[test]
fn password_hash_is_lowercase_hex_sha224() {
    // SHA-224("") from FIPS 180-4.
    assert_eq!(
        &password_hash(""),
        b"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relays_to_ip_and_domain_targets() {
    let echo = echo_server().await;
    let server = trojan_server().await;
    let trojan = outbound(server, PASSWORD);
    for target in [
        TargetAddr::Ip(echo),
        TargetAddr::Domain("localhost".into(), echo.port()),
    ] {
        let mut stream = trojan.connect(&target).await.unwrap();
        stream.write_all(b"hello trojan").await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = [0u8; 12];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello trojan", "{target}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_speaks_first_targets_work() {
    let banner = banner_server().await;
    let server = trojan_server().await;
    let mut stream = outbound(server, PASSWORD)
        .connect(&TargetAddr::Ip(banner))
        .await
        .unwrap();
    let mut line = [0u8; 11];
    stream.read_exact(&mut line).await.unwrap();
    assert_eq!(&line, b"220 ready\r\n");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_password_gets_no_data() {
    let echo = echo_server().await;
    let server = trojan_server().await;
    let mut stream = outbound(server, "wrong")
        .connect(&TargetAddr::Ip(echo))
        .await
        .unwrap();
    stream.write_all(b"hello").await.unwrap();
    stream.flush().await.unwrap();
    let mut buf = [0u8; 5];
    assert!(stream.read_exact(&mut buf).await.is_err());
}

#[test]
fn factory_builds_from_settings_and_rejects_bad_ones() {
    let mut registry = OutboundRegistry::new();
    registry.register(Arc::new(TrojanFactory));
    let settings = |json: &str| serde_json::from_str(json).unwrap();
    let built = registry
        .build(
            "trojan",
            &settings(r#"{"server":"example.com","port":443,"password":"p","alpn":["h2"]}"#),
            Arc::new(TcpDialer),
        )
        .unwrap();
    assert_eq!(built.protocol(), "trojan");
    for bad in [
        r#"{"server":"example.com","port":443}"#,
        r#"{"server":"","port":443,"password":"p"}"#,
        r#"{"server":"example.com","port":443,"password":""}"#,
    ] {
        assert!(registry
            .build("trojan", &settings(bad), Arc::new(TcpDialer))
            .is_err());
    }
}
