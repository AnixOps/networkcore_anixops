//! The Hysteria2 client against a minimal in-process server: QUIC with a
//! self-signed certificate, HTTP/3 authentication (h3 server) and TCP request
//! streams read straight from the QUIC connection.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use engine_outbound::registry::OutboundRegistry;
use engine_outbound::{TargetAddr, TcpDialer, TcpOutbound};
use outbound_hysteria2::{
    put_varint, read_varint, Hysteria2Factory, Hysteria2Outbound, AUTH_OK_STATUS, TCP_REQUEST_ID,
};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use transport_tls::TlsSettings;

const PASSWORD: &str = "correct horse";

struct TestServer {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
}

async fn hysteria2_server() -> TestServer {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["hy2.test".to_string()])
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
    let Ok(mut h3) =
        h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection.clone()))
            .await
    else {
        return;
    };
    let Ok(Some(resolver)) = h3.accept().await else {
        return;
    };
    let Ok((request, mut stream)) = resolver.resolve_request().await else {
        return;
    };
    let authorized = request.method() == http::Method::POST
        && request.uri().path() == "/auth"
        && request.uri().host() == Some("hysteria")
        && request
            .headers()
            .get("hysteria-auth")
            .is_some_and(|value| value == PASSWORD)
        && request.headers().contains_key("hysteria-padding");
    let status = if authorized { AUTH_OK_STATUS } else { 404 };
    let response = http::Response::builder()
        .status(status)
        .header("Hysteria-UDP", "false")
        .header("Hysteria-CC-RX", "auto")
        .body(())
        .unwrap();
    if stream.send_response(response).await.is_err() || stream.finish().await.is_err() {
        return;
    }
    if !authorized {
        // Closing now could drop the response; the client closes.
        connection.closed().await;
        return;
    }
    // TCP requests are raw bidirectional streams; the h3 connection stays
    // alive but is not polled again so it does not take them.
    while let Ok((send, recv)) = connection.accept_bi().await {
        tokio::spawn(serve_tcp(send, recv));
    }
    drop(h3);
}

async fn serve_tcp(mut send: quinn::SendStream, mut recv: quinn::RecvStream) {
    let Ok(id) = read_varint(&mut recv).await else {
        return;
    };
    assert_eq!(id, TCP_REQUEST_ID);
    let len = read_varint(&mut recv).await.unwrap();
    let mut address = vec![0u8; len as usize];
    recv.read_exact(&mut address).await.unwrap();
    let padding = read_varint(&mut recv).await.unwrap();
    assert!((64..512).contains(&padding));
    let mut skipped = vec![0u8; padding as usize];
    recv.read_exact(&mut skipped).await.unwrap();

    let address = String::from_utf8(address).unwrap();
    let (status, message) = match address.as_str() {
        "echo.test:80" | "[2001:db8::1]:443" => (0u8, ""),
        _ => (1u8, "target blocked"),
    };
    let mut response = vec![status];
    put_varint(&mut response, message.len() as u64);
    response.extend_from_slice(message.as_bytes());
    put_varint(&mut response, 3);
    response.extend_from_slice(b"pad");
    send.write_all(&response).await.unwrap();
    if status != 0 {
        let _ = send.finish();
        return;
    }
    // Echo, prefixed with the address the client asked for.
    send.write_all(address.as_bytes()).await.unwrap();
    send.write_all(b"|").await.unwrap();
    let _ = tokio::io::copy(&mut recv, &mut send).await;
    let _ = send.finish();
}

fn tls() -> TlsSettings {
    TlsSettings {
        server_name: "hy2.test".to_owned(),
        alpn: Vec::new(),
        insecure: true,
    }
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
    let server = hysteria2_server().await;
    let outbound =
        Hysteria2Outbound::new("127.0.0.1", server.addr.port(), PASSWORD, &tls()).unwrap();

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
async fn rejected_target_reports_the_server_message() {
    let server = hysteria2_server().await;
    let outbound =
        Hysteria2Outbound::new("127.0.0.1", server.addr.port(), PASSWORD, &tls()).unwrap();
    let err = match outbound
        .connect(&TargetAddr::Domain("blocked.test".to_owned(), 1))
        .await
    {
        Ok(_) => panic!("blocked target connected"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
    assert!(err.to_string().contains("target blocked"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_password_is_rejected() {
    let server = hysteria2_server().await;
    let outbound =
        Hysteria2Outbound::new("127.0.0.1", server.addr.port(), "wrong", &tls()).unwrap();
    let err = match outbound
        .connect(&TargetAddr::Domain("echo.test".to_owned(), 80))
        .await
    {
        Ok(_) => panic!("wrong password connected"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(!err.to_string().contains("wrong"));
}

#[tokio::test]
async fn varints_round_trip() {
    for value in [
        0,
        63,
        64,
        16_383,
        16_384,
        (1 << 30) - 1,
        1 << 30,
        (1 << 62) - 1,
    ] {
        let mut out = Vec::new();
        put_varint(&mut out, value);
        let expected_len = match value {
            0..=63 => 1,
            64..=16_383 => 2,
            16_384..=1_073_741_823 => 4,
            _ => 8,
        };
        assert_eq!(out.len(), expected_len, "length of {value}");
        assert_eq!(read_varint(&mut out.as_slice()).await.unwrap(), value);
    }
    // RFC 9000 appendix A.1 examples.
    let mut out = Vec::new();
    put_varint(&mut out, 151_288_809_941_952_652);
    assert_eq!(out, [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]);
    let mut out = Vec::new();
    put_varint(&mut out, 494_878_333);
    assert_eq!(out, [0x9d, 0x7f, 0x3e, 0x7d]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn factory_builds_from_settings_and_rejects_obfs() {
    let server = hysteria2_server().await;
    let mut registry = OutboundRegistry::new();
    registry.register(Arc::new(Hysteria2Factory));
    let settings = serde_json::json!({
        "server": "127.0.0.1",
        "port": server.addr.port(),
        "password": PASSWORD,
        "server_name": "hy2.test",
        "insecure": true,
    });
    let outbound = registry
        .build(
            "hysteria2",
            settings.as_object().unwrap(),
            Arc::new(TcpDialer),
        )
        .unwrap();
    assert_eq!(outbound.protocol(), "hysteria2");
    let echoed = round_trip(
        outbound.as_ref(),
        TargetAddr::Domain("echo.test".to_owned(), 80),
        b"factory",
    )
    .await;
    assert_eq!(echoed, b"echo.test:80|factory");

    let obfs = serde_json::json!({
        "server": "127.0.0.1",
        "port": 443,
        "password": PASSWORD,
        "obfs": {"type": "salamander", "password": "cry me a river"},
    });
    let err = match registry.build("hysteria2", obfs.as_object().unwrap(), Arc::new(TcpDialer)) {
        Ok(_) => panic!("obfs config built"),
        Err(err) => err,
    };
    assert!(err.contains("obfs"));
    assert!(!err.contains("cry me a river"));
}
