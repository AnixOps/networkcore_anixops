//! HTTPS decryption end to end over in-memory streams: a client that trusts
//! the device root, the MITM engine, and a TLS origin behind a test outbound.
#![cfg(feature = "mitm")]

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use engine_embedded::config::MitmConfig;
use engine_embedded::mitm::{p256_pkcs8_from_x963, MitmEngine};
use engine_embedded::tunnel::{FlowInterceptor, InterceptedFlow};
use engine_embedded::{EmbeddedRuntime, RuntimeErrorCode};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

const HOST: &str = "api.example.test";
const POLICY: &str = "[Plugin]\n\
name = NetworkCore MITM Test\n\
\n\
[URL Rewrite]\n\
^https://api\\.example\\.test/blocked reject\n\
\n\
[MITM]\n\
enable = true\n\
hostname = api.example.test\n";
/// A Loon plugin listed next to the policy; its hosts join the merged list.
const PLUGIN: &str = "#!name = Second\n\
[Rewrite]\n\
^https://cdn\\.example\\.test/ads/ reject\n\
\n\
[MITM]\n\
hostname = %APPEND% cdn.example.test\n";

struct Root {
    certificate: CertificateDer<'static>,
    key: KeyPair,
    params: CertificateParams,
}

fn root(name: &str) -> Root {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let certificate = params.self_signed(&key).unwrap().der().clone();
    Root {
        certificate,
        key,
        params,
    }
}

/// The root key the way the Swift side stores it: X9.63 `04 || X || Y || D`.
fn x963(key: &KeyPair) -> Vec<u8> {
    let pkcs8 = key.serialize_der();
    assert_eq!(pkcs8.len(), 138, "ring P-256 PKCS#8 layout");
    let mut raw = pkcs8[73..138].to_vec();
    raw.extend_from_slice(&pkcs8[36..68]);
    raw
}

fn mitm_config(device_root: &Root) -> MitmConfig {
    let base64 = base64::engine::general_purpose::STANDARD;
    MitmConfig {
        policy: POLICY.to_string(),
        plugins: vec![PLUGIN.to_string()],
        ca_certificate: base64.encode(&device_root.certificate),
        ca_private_key: base64.encode(x963(&device_root.key)),
        script_assets: Default::default(),
        script_store_path: None,
    }
}

fn trusting(root: &CertificateDer<'static>, alpn: &[&[u8]]) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.add(root.clone()).unwrap();
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|value| value.to_vec()).collect();
    config
}

/// A TLS origin for `HOST`: records each request head and answers with a
/// fixed body.
struct Origin {
    acceptor: tokio_rustls::TlsAcceptor,
    requests: mpsc::UnboundedSender<String>,
}

impl Origin {
    fn new(origin_root: &Root, requests: mpsc::UnboundedSender<String>) -> Self {
        let key = KeyPair::generate().unwrap();
        let issuer = rcgen::Issuer::from_params(&origin_root.params, &origin_root.key);
        let certificate = CertificateParams::new(vec![HOST.to_string()])
            .unwrap()
            .signed_by(&key, &issuer)
            .unwrap();
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![certificate.der().clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
                )
                .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self {
            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
            requests,
        }
    }
}

impl TcpOutbound for Origin {
    fn protocol(&self) -> &'static str {
        "test-origin"
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let (near, far) = tokio::io::duplex(64 * 1024);
            let acceptor = self.acceptor.clone();
            let requests = self.requests.clone();
            tokio::spawn(async move {
                let mut stream = acceptor.accept(far).await.unwrap();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let n = stream.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                        buf.drain(..end + 4);
                        requests.send(head).unwrap();
                        let body = b"hello from origin";
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
                            body.len()
                        );
                        stream.write_all(response.as_bytes()).await.unwrap();
                        stream.write_all(body).await.unwrap();
                        stream.flush().await.unwrap();
                    }
                }
            });
            Ok(Box::new(near) as BoxStream)
        })
    }
}

async fn read_response(stream: &mut (impl AsyncReadExt + Unpin)) -> (String, String) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).into_owned();
            let length = head
                .lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            while buf.len() < end + 4 + length {
                let n = stream.read(&mut chunk).await.unwrap();
                assert!(n > 0, "response cut short");
                buf.extend_from_slice(&chunk[..n]);
            }
            let body = String::from_utf8_lossy(&buf[end + 4..end + 4 + length]).into_owned();
            return (head, body);
        }
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0, "connection closed before a response");
        buf.extend_from_slice(&chunk[..n]);
    }
}

#[tokio::test]
async fn decrypts_rewrites_and_relays_https_for_listed_hosts() {
    let device_root = root("NetworkCore Test Device Root");
    let origin_root = root("NetworkCore Test Origin Root");
    let engine = Arc::new(
        MitmEngine::new(&mitm_config(&device_root))
            .unwrap()
            .with_upstream_config(trusting(&origin_root.certificate, &[b"http/1.1"])),
    );
    let (requests_tx, mut requests) = mpsc::unbounded_channel();
    let origin = Arc::new(Origin::new(&origin_root, requests_tx));
    let target: SocketAddr = "192.0.2.10:443".parse().unwrap();

    let (app, tunnel_side) = tokio::io::duplex(64 * 1024);
    let client = tokio::spawn({
        let config = trusting(&device_root.certificate, &[b"h2", b"http/1.1"]);
        async move {
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            let mut stream = connector
                .connect(ServerName::try_from(HOST).unwrap(), app)
                .await
                .expect("the client trusts the device root");
            assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));

            stream
                .write_all(b"GET /blocked/ad.js HTTP/1.1\r\nHost: api.example.test\r\n\r\n")
                .await
                .unwrap();
            let (head, _) = read_response(&mut stream).await;
            assert!(head.starts_with("HTTP/1.1 4"), "rejected: {head}");

            stream
                .write_all(
                    b"GET /data HTTP/1.1\r\nHost: api.example.test\r\nAccept-Encoding: gzip, br\r\n\r\n",
                )
                .await
                .unwrap();
            let (head, body) = read_response(&mut stream).await;
            assert!(head.starts_with("HTTP/1.1 200"), "relayed: {head}");
            assert_eq!(body, "hello from origin");
        }
    });

    let mut tunnel_side = tunnel_side;
    let mut first = vec![0u8; 4096];
    let n = tunnel_side.read(&mut first).await.unwrap();
    first.truncate(n);
    let host = engine
        .claim(&first, target)
        .expect("the listed host is intercepted");
    assert_eq!(host, HOST);
    let other: SocketAddr = "192.0.2.10:8443".parse().unwrap();
    assert_eq!(engine.claim(&first, other), None, "only port 443");
    assert!(!engine.intercepts("www.example.test"));
    assert!(
        engine.intercepts("cdn.example.test"),
        "plugin hosts are merged"
    );

    let flow = InterceptedFlow {
        inbound: Box::new(tunnel_side),
        first,
        host,
        target,
    };
    let server = tokio::spawn({
        let engine = engine.clone();
        let origin = origin.clone();
        async move {
            let _ = engine
                .serve_flow(
                    flow,
                    origin.as_ref(),
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                )
                .await;
        }
    });

    tokio::time::timeout(Duration::from_secs(10), client)
        .await
        .expect("client finished")
        .unwrap();
    // Only the second request reached the origin, asking for an identity body.
    let head = requests.recv().await.unwrap();
    assert!(head.starts_with("GET /data HTTP/1.1"), "{head}");
    assert!(head.contains("Accept-Encoding: identity"), "{head}");
    assert!(requests.try_recv().is_err());
    server.abort();
}

#[test]
fn x963_keys_convert_to_ring_pkcs8() {
    let key = KeyPair::generate().unwrap();
    assert_eq!(
        p256_pkcs8_from_x963(&x963(&key)).unwrap(),
        key.serialize_der()
    );
    assert_eq!(p256_pkcs8_from_x963(&[0x04; 96]), None);
}

#[test]
fn runtime_config_accepts_and_validates_the_mitm_section() {
    let device_root = root("NetworkCore Test Device Root");
    let config = mitm_config(&device_root);
    let envelope = |mitm: serde_json::Value| {
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "profile_id": "mitm-test",
            "outbound": { "type": "direct" },
            "mitm": mitm,
        }))
        .unwrap()
    };
    let valid = serde_json::json!({
        "policy": config.policy,
        "ca_certificate": config.ca_certificate,
        "ca_private_key": config.ca_private_key,
    });
    assert!(EmbeddedRuntime::from_json(&envelope(valid.clone())).is_ok());
    let plugins_only = serde_json::json!({
        "plugins": [PLUGIN],
        "ca_certificate": config.ca_certificate,
        "ca_private_key": config.ca_private_key,
    });
    assert!(EmbeddedRuntime::from_json(&envelope(plugins_only.clone())).is_ok());
    let mut empty_plugin = plugins_only;
    empty_plugin["plugins"] = serde_json::json!(["  "]);
    let error = EmbeddedRuntime::from_json(&envelope(empty_plugin))
        .err()
        .unwrap();
    assert_eq!(error.code, RuntimeErrorCode::ConfigRejected);

    let mut bad_key = valid.clone();
    bad_key["ca_private_key"] = serde_json::json!("AAAA");
    let error = EmbeddedRuntime::from_json(&envelope(bad_key))
        .err()
        .unwrap();
    assert_eq!(error.code, RuntimeErrorCode::ConfigRejected);

    let mut unknown = valid;
    unknown["extra"] = serde_json::json!(true);
    let error = EmbeddedRuntime::from_json(&envelope(unknown))
        .err()
        .unwrap();
    assert_eq!(error.code, RuntimeErrorCode::ConfigRejected);
}

/// One request through a TLS client that trusts `device_root`, the engine
/// and `origin`; returns the response head and body.
#[cfg(feature = "scripts")]
async fn exchange(
    engine: Arc<MitmEngine>,
    origin: Arc<Origin>,
    device_root: &Root,
    request: &'static [u8],
) -> (String, String) {
    let target: SocketAddr = "192.0.2.10:443".parse().unwrap();
    let (app, mut tunnel_side) = tokio::io::duplex(64 * 1024);
    let client = tokio::spawn({
        let config = trusting(&device_root.certificate, &[b"http/1.1"]);
        async move {
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            let mut stream = connector
                .connect(ServerName::try_from(HOST).unwrap(), app)
                .await
                .expect("the client trusts the device root");
            stream.write_all(request).await.unwrap();
            read_response(&mut stream).await
        }
    });
    let mut first = vec![0u8; 4096];
    let n = tunnel_side.read(&mut first).await.unwrap();
    first.truncate(n);
    let host = engine.claim(&first, target).expect("intercepted");
    let flow = InterceptedFlow {
        inbound: Box::new(tunnel_side),
        first,
        host,
        target,
    };
    let server = tokio::spawn(async move {
        let _ = engine
            .serve_flow(
                flow,
                origin.as_ref(),
                Duration::from_secs(5),
                Duration::from_secs(5),
            )
            .await;
    });
    let response = tokio::time::timeout(Duration::from_secs(10), client)
        .await
        .expect("client finished")
        .unwrap();
    server.abort();
    response
}

#[cfg(feature = "scripts")]
#[tokio::test]
async fn consented_scripts_rewrite_responses_in_quickjs() {
    let dir = std::env::temp_dir().join(format!("networkcore-mitm-scripts-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("upper.js");
    std::fs::write(
        &script,
        "$persistentStore.write('seen', 'count');\n\
         $done({ body: $response.body.toUpperCase(), headers: { 'X-Script': '1' } });",
    )
    .unwrap();
    let plugin = "#!name = Upper\n\
[Script]\n\
http-response ^https://api\\.example\\.test/data script-path=https://scripts.example.test/upper.js, requires-body=true, tag=upper\n\
\n\
[MITM]\n\
hostname = api.example.test\n";
    let device_root = root("NetworkCore Test Device Root");
    let origin_root = root("NetworkCore Test Origin Root");
    let base64 = base64::engine::general_purpose::STANDARD;
    let config = MitmConfig {
        policy: String::new(),
        plugins: vec![plugin.to_string()],
        ca_certificate: base64.encode(&device_root.certificate),
        ca_private_key: base64.encode(x963(&device_root.key)),
        script_assets: [(
            "https://scripts.example.test/upper.js".to_string(),
            script.display().to_string(),
        )]
        .into(),
        script_store_path: Some(dir.join("store.json").display().to_string()),
    };
    let engine = Arc::new(
        MitmEngine::new(&config)
            .unwrap()
            .with_upstream_config(trusting(&origin_root.certificate, &[b"http/1.1"])),
    );
    let (requests_tx, _requests) = mpsc::unbounded_channel();
    let origin = Arc::new(Origin::new(&origin_root, requests_tx));

    let (head, body) = exchange(
        engine,
        origin,
        &device_root,
        b"GET /data HTTP/1.1\r\nHost: api.example.test\r\n\r\n",
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(head.to_ascii_lowercase().contains("x-script: 1"), "{head}");
    assert_eq!(body, "HELLO FROM ORIGIN");
    let store = std::fs::read_to_string(dir.join("store.json")).unwrap_or_default();
    assert!(store.contains("count"), "persistent store: {store}");

    // Every consented script must exist when the runtime starts.
    let mut missing = config.clone();
    missing.script_assets.insert(
        "https://scripts.example.test/missing.js".to_string(),
        dir.join("missing.js").display().to_string(),
    );
    assert!(MitmEngine::new(&missing).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}
