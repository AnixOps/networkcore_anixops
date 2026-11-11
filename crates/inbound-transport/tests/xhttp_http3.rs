//! XHTTP under TLS with ALPN `h3`: the engine's XHTTP client over HTTP/3
//! against the QUIC side of a toy inbound, and over HTTP/2 against its TCP
//! side on the same port number.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use engine_inbound::server::{serve, InboundStats, ServeSettings};
use engine_inbound::{Accepted, Rejected, StreamInbound, UserStore};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpDialer, TcpOutbound};
use inbound_transport::{wrap_all, TlsServerSettings, TransportSettings};
use rcgen::{CertificateParams, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use transport_tls::{TlsConnector, TlsSettings};
use transport_xhttp::{
    HttpVersion, Mode, Range, Security, XhttpConnector, XhttpSettings, XhttpTarget,
};

const TIMEOUT: Duration = Duration::from_secs(20);
const SERVER_NAME: &str = "node.test";
const LEN: usize = 200_000;

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
                mux: false,
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

async fn inbound(alpn: &[&str]) -> Arc<dyn StreamInbound> {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec![SERVER_NAME.to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let tls = TlsServerSettings {
        certificate: Some(cert.pem()),
        key: Some(key.serialize_pem()),
        alpn: alpn.iter().map(|protocol| protocol.to_string()).collect(),
        ..TlsServerSettings::default()
    };
    let transport = TransportSettings::Xhttp(XhttpSettings {
        path: "/xh".into(),
        ..XhttpSettings::default()
    });
    let inner = Arc::new(Passthrough {
        users: Arc::new(UserStore::default()),
        target: echo_server().await,
    });
    wrap_all(inner, Some(&transport), Some(&tls)).unwrap_or_else(|err| panic!("{err}"))
}

fn tls(alpn: &[&str]) -> TlsSettings {
    TlsSettings {
        server_name: SERVER_NAME.into(),
        alpn: alpn.iter().map(|protocol| protocol.to_string()).collect(),
        insecure: true,
    }
}

async fn round_trip(port: u16, mode: Mode, security: Security, version: HttpVersion) {
    let settings = XhttpSettings {
        path: "/xh".into(),
        mode,
        sc_min_posts_interval_ms: Range::fixed(1),
        ..XhttpSettings::default()
    };
    let connector = XhttpConnector::new(
        &settings,
        XhttpTarget {
            server: "127.0.0.1".into(),
            port,
            default_host: SERVER_NAME.into(),
            security,
            version,
            dialer: Arc::new(TcpDialer),
        },
    )
    .unwrap();
    let stream = tokio::time::timeout(TIMEOUT, connector.connect())
        .await
        .unwrap_or_else(|_| panic!("{mode:?} {version:?} did not connect"))
        .unwrap();
    let (mut reader, mut writer) = tokio::io::split(stream);
    let sent: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();
    let expected = sent.clone();
    let writing = tokio::spawn(async move {
        for piece in sent.chunks(9_973) {
            writer.write_all(piece).await.unwrap();
            writer.flush().await.unwrap();
        }
        writer
    });
    let mut received = vec![0u8; LEN];
    tokio::time::timeout(TIMEOUT, reader.read_exact(&mut received))
        .await
        .unwrap_or_else(|_| panic!("{mode:?} {version:?} timed out"))
        .unwrap();
    assert!(received == expected, "{mode:?} {version:?}");
    drop(writing.await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn alpn_h3_serves_http3_beside_http2() {
    let inbound = inbound(&["h3"]).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let socket = std::net::UdpSocket::bind(("127.0.0.1", port)).unwrap();
    let quic = inbound.packet().expect("alpn h3 gives xhttp a quic side");
    let stats = Arc::new(InboundStats::default());
    tokio::spawn(quic.serve(
        socket,
        Arc::new(Direct),
        None,
        ServeSettings::default(),
        stats.clone(),
    ));
    tokio::spawn(serve(
        listener,
        inbound,
        Arc::new(Direct),
        ServeSettings::default(),
        stats,
    ));

    for mode in [Mode::PacketUp, Mode::StreamUp, Mode::StreamOne] {
        let security = Security::quic("127.0.0.1", port, &tls(&[])).unwrap();
        round_trip(port, mode, security, HttpVersion::Http3).await;
    }
    // The TCP side offers `h2` and `http/1.1`, as without `h3`.
    let security = Security::Tls(TlsConnector::new(&tls(&["h2"])).unwrap());
    round_trip(port, Mode::StreamUp, security, HttpVersion::Http2).await;
}

#[tokio::test]
async fn only_alpn_h3_adds_the_quic_side() {
    assert!(inbound(&[]).await.packet().is_none());
    assert!(inbound(&["h2", "http/1.1"]).await.packet().is_none());
    assert!(inbound(&["h2", "h3"]).await.packet().is_some());
}
