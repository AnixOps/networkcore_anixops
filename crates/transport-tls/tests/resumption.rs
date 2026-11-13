//! Session resumption of the TLS client (P16 in the feature table): one
//! connector dialing the same server over and over, alone and in bursts the
//! way a page load opens connections, resumes at least 80% of its
//! handshakes.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use engine_outbound::BoxStream;
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use transport_tls::{TlsConnector, TlsSettings};

/// A TLS 1.3 server for `localhost` that says "ok" and waits for the end.
/// rustls sends two tickets after every handshake.
async fn server() -> SocketAddr {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
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
                let _ = tls.write_all(b"ok").await;
                let mut rest = Vec::new();
                let _ = tls.read_to_end(&mut rest).await;
            });
        }
    });
    addr
}

/// One connection: handshake, read the greeting (and the tickets in front
/// of it), close.
async fn dial(connector: &TlsConnector, server: SocketAddr) {
    let tcp = TcpStream::connect(server).await.unwrap();
    let mut stream = connector.connect(Box::new(tcp) as BoxStream).await.unwrap();
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"ok");
    let _ = stream.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn most_handshakes_resume_alone_and_in_bursts() {
    let server = server().await;
    let connector = TlsConnector::new(&TlsSettings {
        server_name: "localhost".into(),
        alpn: Vec::new(),
        insecure: true,
    })
    .unwrap();

    timeout(Duration::from_secs(30), async {
        for _ in 0..40 {
            dial(&connector, server).await;
        }
        // Bursts of 24 at once, more than rustls's own cache keeps (8).
        for _ in 0..3 {
            let burst: Vec<_> = (0..24)
                .map(|_| {
                    let connector = connector.clone();
                    tokio::spawn(async move { dial(&connector, server).await })
                })
                .collect();
            for task in burst {
                task.await.unwrap();
            }
        }
    })
    .await
    .expect("handshakes timed out");

    let stats = connector.stats();
    let handshakes = stats.handshakes.load(Ordering::Relaxed);
    let resumed = stats.resumed.load(Ordering::Relaxed);
    let rate = stats.resumption_rate();
    println!("tls resumption: {resumed} of {handshakes} handshakes resumed ({rate:.3})");
    assert_eq!(handshakes, 40 + 3 * 24);
    assert!(rate >= 0.8, "resumption rate {rate}");
    assert_eq!(stats.health_json()["tls_handshakes"], handshakes);
}
