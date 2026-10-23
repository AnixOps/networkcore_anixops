//! The TUIC client against a minimal in-process TUIC v5 server: QUIC with a
//! self-signed certificate, the Authenticate command checked against the
//! server's own TLS exporter, and Connect streams echoed back.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use engine_outbound::registry::OutboundRegistry;
use engine_outbound::{TargetAddr, TcpDialer, TcpOutbound};
use outbound_tuic::{
    auth_token, connect_header, parse_uuid, TuicFactory, TuicOutbound, ADDR_DOMAIN, ADDR_IPV6,
    CMD_AUTHENTICATE, CMD_CONNECT, VERSION,
};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use transport_quic::Congestion;
use transport_tls::TlsSettings;

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const PASSWORD: &str = "correct horse";

struct TestServer {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
}

async fn tuic_server() -> TestServer {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["tuic.test".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(cert.der().to_vec())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
    .unwrap();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto).unwrap(),
    ));
    let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let counter = connections.clone();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let counter = counter.clone();
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                serve_connection(connection).await;
            });
        }
    });
    TestServer { addr, connections }
}

async fn serve_connection(connection: quinn::Connection) {
    // Connect streams wait until the Authenticate command was checked, as
    // TUIC servers do.
    let (authorized_tx, authorized_rx) = watch::channel(None::<bool>);
    let auth_connection = connection.clone();
    tokio::spawn(async move {
        let Ok(mut recv) = auth_connection.accept_uni().await else {
            return;
        };
        let mut command = [0u8; 2 + 16 + 32];
        let ok = recv.read_exact(&mut command).await.is_ok() && {
            let uuid = parse_uuid(UUID).unwrap();
            let expected = auth_token(&auth_connection, &uuid, PASSWORD.as_bytes()).unwrap();
            command[..2] == [VERSION, CMD_AUTHENTICATE]
                && command[2..18] == uuid
                && command[18..] == expected
        };
        let _ = authorized_tx.send(Some(ok));
        if !ok {
            auth_connection.close(quinn::VarInt::from_u32(1), b"auth failed");
        }
    });
    while let Ok((send, recv)) = connection.accept_bi().await {
        let mut authorized = authorized_rx.clone();
        tokio::spawn(async move {
            let ok = match authorized.wait_for(Option::is_some).await {
                Ok(state) => *state == Some(true),
                Err(_) => false,
            };
            if ok {
                serve_connect(send, recv).await;
            }
        });
    }
}

async fn serve_connect(mut send: quinn::SendStream, mut recv: quinn::RecvStream) {
    let mut head = [0u8; 3];
    recv.read_exact(&mut head).await.unwrap();
    assert_eq!(head[..2], [VERSION, CMD_CONNECT]);
    let host = match head[2] {
        ADDR_DOMAIN => {
            let mut len = [0u8; 1];
            recv.read_exact(&mut len).await.unwrap();
            let mut name = vec![0u8; usize::from(len[0])];
            recv.read_exact(&mut name).await.unwrap();
            String::from_utf8(name).unwrap()
        }
        ADDR_IPV6 => {
            let mut ip = [0u8; 16];
            recv.read_exact(&mut ip).await.unwrap();
            format!("[{}]", std::net::Ipv6Addr::from(ip))
        }
        other => panic!("unexpected address type {other}"),
    };
    let mut port = [0u8; 2];
    recv.read_exact(&mut port).await.unwrap();
    // Echo, prefixed with the address the client asked for.
    let prefix = format!("{host}:{}|", u16::from_be_bytes(port));
    send.write_all(prefix.as_bytes()).await.unwrap();
    let _ = tokio::io::copy(&mut recv, &mut send).await;
    let _ = send.finish();
}

fn tls() -> TlsSettings {
    TlsSettings {
        server_name: "tuic.test".to_owned(),
        alpn: Vec::new(),
        insecure: true,
    }
}

fn outbound(port: u16, password: &str) -> TuicOutbound {
    TuicOutbound::new(
        "127.0.0.1",
        port,
        parse_uuid(UUID).unwrap(),
        password,
        &tls(),
        Congestion::Bbr,
    )
    .unwrap()
}

async fn round_trip(outbound: &dyn TcpOutbound, target: TargetAddr, payload: &[u8]) -> Vec<u8> {
    let mut stream = outbound.connect(&target).await.unwrap();
    stream.write_all(payload).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut out = Vec::new();
    stream.read_to_end(&mut out).await.unwrap();
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxies_streams_over_one_authenticated_connection() {
    let server = tuic_server().await;
    let outbound = outbound(server.addr.port(), PASSWORD);

    let echoed = round_trip(
        &outbound,
        TargetAddr::Domain("echo.test".to_owned(), 80),
        b"hello",
    )
    .await;
    assert_eq!(echoed, b"echo.test:80|hello");

    let ipv6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
    let echoed = round_trip(&outbound, TargetAddr::Ip(ipv6), b"again").await;
    assert_eq!(echoed, b"[2001:db8::1]:443|again");

    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_password_gets_no_data() {
    let server = tuic_server().await;
    let outbound = outbound(server.addr.port(), "wrong");
    // TUIC servers do not answer Authenticate; a bad token closes the
    // connection, so the stream ends without the echo.
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let mut stream = outbound
            .connect(&TargetAddr::Domain("echo.test".to_owned(), 80))
            .await?;
        stream.write_all(b"hello").await?;
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await?;
        Ok::<_, std::io::Error>(out)
    })
    .await
    .expect("the server closes the connection");
    match result {
        Ok(out) => assert!(out.is_empty(), "got {out:?}"),
        Err(err) => assert!(!err.to_string().contains("wrong")),
    }
}

#[test]
fn connect_header_encodes_every_address_type() {
    let domain = connect_header(&TargetAddr::Domain("a.example".to_owned(), 443)).unwrap();
    assert_eq!(
        domain,
        [&[0x05, 0x01, 0x00, 9][..], b"a.example", &[0x01, 0xbb]].concat()
    );
    let ipv4 = connect_header(&TargetAddr::Ip("192.0.2.1:80".parse().unwrap())).unwrap();
    assert_eq!(ipv4, [0x05, 0x01, 0x01, 192, 0, 2, 1, 0, 80]);
    let ipv6 = connect_header(&TargetAddr::Ip("[::1]:53".parse().unwrap())).unwrap();
    assert_eq!(ipv6.len(), 2 + 1 + 16 + 2);
    assert_eq!(ipv6[2], 0x02);
    assert!(connect_header(&TargetAddr::Domain(String::new(), 1)).is_err());
}

#[test]
fn uuids_parse_with_or_without_hyphens() {
    let hyphenated = parse_uuid(UUID).unwrap();
    assert_eq!(parse_uuid(&UUID.replace('-', "")), Some(hyphenated));
    assert_eq!(hyphenated[0], 0xb8);
    assert!(parse_uuid("not-a-uuid").is_none());
    assert!(parse_uuid("+831381d-6324-4d53-ad4f-8cda48b30811").is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn factory_builds_from_settings() {
    let server = tuic_server().await;
    let mut registry = OutboundRegistry::new();
    registry.register(Arc::new(TuicFactory));
    let settings = serde_json::json!({
        "server": "127.0.0.1",
        "port": server.addr.port(),
        "uuid": UUID,
        "password": PASSWORD,
        "server_name": "tuic.test",
        "insecure": true,
        "congestion_control": "new_reno",
    });
    let outbound = registry
        .build("tuic", settings.as_object().unwrap(), Arc::new(TcpDialer))
        .unwrap();
    assert_eq!(outbound.protocol(), "tuic");
    let echoed = round_trip(
        outbound.as_ref(),
        TargetAddr::Domain("echo.test".to_owned(), 80),
        b"factory",
    )
    .await;
    assert_eq!(echoed, b"echo.test:80|factory");

    for bad in [
        serde_json::json!({"server": "127.0.0.1", "port": 1, "uuid": "x", "password": "p"}),
        serde_json::json!({"server": "127.0.0.1", "port": 1, "uuid": UUID, "password": "p",
            "congestion_control": "brutal"}),
    ] {
        let err = match registry.build("tuic", bad.as_object().unwrap(), Arc::new(TcpDialer)) {
            Ok(_) => panic!("bad settings built"),
            Err(err) => err,
        };
        assert!(err.starts_with("tuic"));
    }
}
