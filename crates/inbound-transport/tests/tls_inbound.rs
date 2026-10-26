//! TLS in front of a toy inbound, with inline and file certificates.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use engine_inbound::server::{serve, InboundStats, ServeSettings};
use engine_inbound::{Accepted, Rejected, StreamInbound, UserStore};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use inbound_transport::{wrap, TlsServerSettings};
use rcgen::{CertificateParams, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use transport_tls::{TlsConnector, TlsSettings};

const TIMEOUT: Duration = Duration::from_secs(10);

/// Sends every client to `target` without a handshake.
struct Passthrough {
    users: Arc<UserStore>,
    target: SocketAddr,
}

impl StreamInbound for Passthrough {
    fn protocol(&self) -> &'static str {
        "passthrough"
    }

    fn users(&self) -> &Arc<UserStore> {
        &self.users
    }

    fn accept<'a>(
        &'a self,
        stream: BoxStream,
        _peer: SocketAddr,
    ) -> BoxFuture<'a, Result<Accepted, Rejected>> {
        Box::pin(async move {
            Ok(Accepted {
                user: None,
                target: TargetAddr::Ip(self.target),
                stream,
                udp: None,
            })
        })
    }
}

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

fn self_signed() -> (String, String) {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["node.test".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    (cert.pem(), key.serialize_pem())
}

async fn start(tls: &TlsServerSettings) -> SocketAddr {
    let inner = Arc::new(Passthrough {
        users: Arc::new(UserStore::default()),
        target: echo_server().await,
    });
    let inbound = wrap(inner, Some(tls)).unwrap_or_else(|err| panic!("{err}"));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(
        listener,
        inbound,
        Arc::new(Direct),
        ServeSettings::default(),
        Arc::new(InboundStats::default()),
    ));
    addr
}

async fn tls_echo(addr: SocketAddr, alpn: &[&str]) {
    let connector = TlsConnector::new(&TlsSettings {
        server_name: "node.test".into(),
        alpn: alpn.iter().map(|p| p.to_string()).collect(),
        insecure: true,
    })
    .unwrap();
    let transport: BoxStream = Box::new(TcpStream::connect(addr).await.unwrap());
    let mut stream = connector.connect(transport).await.unwrap();
    stream.write_all(b"over tls").await.unwrap();
    let mut buf = [0u8; 8];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut buf))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(&buf, b"over tls");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inline_certificate_terminates_tls() {
    let (certificate, key) = self_signed();
    let addr = start(&TlsServerSettings {
        certificate: Some(certificate),
        key: Some(key),
        alpn: vec!["h2".into(), "http/1.1".into()],
        ..TlsServerSettings::default()
    })
    .await;
    tls_echo(addr, &["http/1.1"]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn certificate_files_terminate_tls() {
    let (certificate, key) = self_signed();
    let dir = std::env::temp_dir().join(format!("inbound-transport-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let certificate_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&certificate_path, certificate).unwrap();
    std::fs::write(&key_path, key).unwrap();
    let addr = start(&TlsServerSettings {
        certificate_path: Some(certificate_path),
        key_path: Some(key_path),
        ..TlsServerSettings::default()
    })
    .await;
    tls_echo(addr, &[]).await;
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn rejects_incomplete_or_mismatched_settings() {
    let inner: Arc<dyn StreamInbound> = Arc::new(Passthrough {
        users: Arc::new(UserStore::default()),
        target: "127.0.0.1:1".parse().unwrap(),
    });
    let (certificate, _) = self_signed();
    let (_, other_key) = self_signed();
    let only_cert = TlsServerSettings {
        certificate: Some(certificate.clone()),
        ..TlsServerSettings::default()
    };
    assert!(wrap(inner.clone(), Some(&only_cert)).is_err());
    let mismatched = TlsServerSettings {
        certificate: Some(certificate),
        key: Some(other_key.clone()),
        ..TlsServerSettings::default()
    };
    let err = wrap(inner.clone(), Some(&mismatched)).err().unwrap();
    assert!(!err.contains("PRIVATE KEY"));
    let settings: TlsServerSettings = serde_json::from_str(
        r#"{"certificate_path":"/nonexistent/c.pem","key_path":"/nonexistent/k.pem"}"#,
    )
    .unwrap();
    assert!(wrap(inner.clone(), Some(&settings)).is_err());
    assert!(wrap(inner, None).is_ok());
}
