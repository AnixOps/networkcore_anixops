//! The TLS client against an in-process rustls server with a self-signed
//! certificate.

use std::net::SocketAddr;
use std::sync::Arc;

use engine_outbound::BoxStream;
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use transport_tls::{TlsConnector, TlsSettings};

/// Echo server over TLS for `localhost` that reports the negotiated ALPN first.
async fn tls_echo_server() -> SocketAddr {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
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
                let alpn = tls.get_ref().1.alpn_protocol().unwrap_or(b"-").to_vec();
                let _ = tls.write_all(&[alpn.len() as u8]).await;
                let _ = tls.write_all(&alpn).await;
                let mut buf = [0u8; 1024];
                while let Ok(n) = tls.read(&mut buf).await {
                    if n == 0 || tls.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

async fn tcp(addr: SocketAddr) -> BoxStream {
    Box::new(TcpStream::connect(addr).await.unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn insecure_mode_accepts_a_self_signed_server_and_negotiates_alpn() {
    let server = tls_echo_server().await;
    let connector = TlsConnector::new(&TlsSettings {
        server_name: "localhost".into(),
        alpn: vec!["http/1.1".into()],
        insecure: true,
    })
    .unwrap();
    let mut stream = connector.connect(tcp(server).await).await.unwrap();
    let mut len = [0u8; 1];
    stream.read_exact(&mut len).await.unwrap();
    let mut alpn = vec![0u8; usize::from(len[0])];
    stream.read_exact(&mut alpn).await.unwrap();
    assert_eq!(alpn, b"http/1.1");

    stream.write_all(b"over tls").await.unwrap();
    let mut echoed = [0u8; 8];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"over tls");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verification_rejects_an_untrusted_certificate() {
    let server = tls_echo_server().await;
    let connector = TlsConnector::new(&TlsSettings {
        server_name: "localhost".into(),
        alpn: Vec::new(),
        insecure: false,
    })
    .unwrap();
    assert!(connector.connect(tcp(server).await).await.is_err());
}

#[test]
fn invalid_server_names_are_rejected() {
    assert!(TlsConnector::new(&TlsSettings {
        server_name: "bad name with spaces".into(),
        ..TlsSettings::default()
    })
    .is_err());
}
