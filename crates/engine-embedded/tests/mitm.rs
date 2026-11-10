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
        resource_assets: Default::default(),
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
    // No rule reads this response, so it may arrive compressed and streams
    // through as sent.
    assert!(head.contains("Accept-Encoding: gzip, br"), "{head}");
    assert!(requests.try_recv().is_err());
    server.abort();
}

/// A plain HTTP origin: answers every request head it reads with a fixed body.
struct PlainOrigin {
    requests: mpsc::UnboundedSender<String>,
    body: Vec<u8>,
}

impl TcpOutbound for PlainOrigin {
    fn protocol(&self) -> &'static str {
        "test-plain-origin"
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let (near, mut far) = tokio::io::duplex(64 * 1024);
            let requests = self.requests.clone();
            let body = self.body.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let n = far.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                        buf.drain(..end + 4);
                        requests.send(head).unwrap();
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
                            body.len()
                        );
                        far.write_all(response.as_bytes()).await.unwrap();
                        far.write_all(&body).await.unwrap();
                    }
                }
            });
            Ok(Box::new(near) as BoxStream)
        })
    }
}

#[tokio::test]
async fn rewrites_plain_http_without_a_mitm_hostname() {
    let device_root = root("NetworkCore Test Device Root");
    let mut config = mitm_config(&device_root);
    config.plugins.push(
        "#!name = Plain\n[Rewrite]\n^http://plain\\.example\\.test/ads/ reject\n".to_string(),
    );
    let engine = Arc::new(MitmEngine::new(&config).unwrap());
    let (requests_tx, mut requests) = mpsc::unbounded_channel();
    let origin = Arc::new(PlainOrigin {
        requests: requests_tx,
        body: b"plain origin".to_vec(),
    });
    let target: SocketAddr = "192.0.2.20:80".parse().unwrap();

    let first = b"GET /ads/banner.js HTTP/1.1\r\nHost: plain.example.test\r\n\r\n".to_vec();
    assert!(
        !engine.intercepts("plain.example.test"),
        "not a [MITM] host"
    );
    let host = engine
        .claim(&first, target)
        .expect("plain HTTP is relayed through the rewrite hook");
    assert_eq!(host, "plain.example.test");
    assert_eq!(
        engine.claim(
            b"CONNECT a.test:443 HTTP/1.1\r\nHost: a.test\r\n\r\n",
            target
        ),
        None,
        "CONNECT keeps its own path"
    );
    assert_eq!(engine.claim(b"\x00\x01binary", target), None);

    let (mut app, tunnel_side) = tokio::io::duplex(64 * 1024);
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

    let (head, _) = tokio::time::timeout(Duration::from_secs(10), read_response(&mut app))
        .await
        .expect("rejected in time");
    assert!(head.starts_with("HTTP/1.1 4"), "rejected: {head}");

    app.write_all(b"GET /index.html HTTP/1.1\r\nHost: plain.example.test\r\n\r\n")
        .await
        .unwrap();
    let (head, body) = tokio::time::timeout(Duration::from_secs(10), read_response(&mut app))
        .await
        .expect("relayed in time");
    assert!(head.starts_with("HTTP/1.1 200"), "relayed: {head}");
    assert_eq!(body, "plain origin");
    let head = requests.recv().await.unwrap();
    assert!(head.starts_with("GET /index.html HTTP/1.1"), "{head}");
    assert!(
        requests.try_recv().is_err(),
        "the rejected request stayed local"
    );
    server.abort();
}

#[tokio::test]
async fn bodies_no_rule_reads_stream_past_the_body_limit_and_keep_the_connection() {
    let device_root = root("NetworkCore Test Device Root");
    let mut config = mitm_config(&device_root);
    config.plugins.push(
        "#!name = Plain\n[Rewrite]\n^http://plain\\.example\\.test/ads/ reject\n".to_string(),
    );
    let engine = Arc::new(MitmEngine::new(&config).unwrap());
    let (requests_tx, mut requests) = mpsc::unbounded_channel();
    // Twice the limit a body that rules read may have.
    let large = vec![b'z'; 2 * 1024 * 1024];
    let origin = Arc::new(PlainOrigin {
        requests: requests_tx,
        body: large.clone(),
    });
    let target: SocketAddr = "192.0.2.20:80".parse().unwrap();
    let first = b"GET /video.bin HTTP/1.1\r\nHost: plain.example.test\r\n\r\n".to_vec();
    let host = engine.claim(&first, target).expect("plain HTTP is claimed");
    let (mut app, tunnel_side) = tokio::io::duplex(64 * 1024);
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

    let (head, body) = tokio::time::timeout(Duration::from_secs(10), read_response(&mut app))
        .await
        .expect("streamed in time");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body.len(), large.len());
    assert!(body.bytes().all(|byte| byte == b'z'));

    // The same connection still carries requests the rules act on.
    app.write_all(b"GET /ads/banner.js HTTP/1.1\r\nHost: plain.example.test\r\n\r\n")
        .await
        .unwrap();
    let (head, _) = tokio::time::timeout(Duration::from_secs(10), read_response(&mut app))
        .await
        .expect("rejected in time");
    assert!(head.starts_with("HTTP/1.1 4"), "rejected: {head}");
    let head = requests.recv().await.unwrap();
    assert!(head.starts_with("GET /video.bin HTTP/1.1"), "{head}");
    assert!(requests.try_recv().is_err());
    server.abort();
}

#[test]
fn plugins_over_one_mib_are_accepted() {
    let device_root = root("NetworkCore Test Device Root");
    let mut config = mitm_config(&device_root);
    let mut large = String::from("#!name = Large\n[Rule]\n");
    let mut index = 0;
    while large.len() < 3 * 1024 * 1024 {
        large.push_str(&format!("DOMAIN-SUFFIX,ads{index}.example.test,REJECT\n"));
        index += 1;
    }
    large.push_str("[MITM]\nhostname = large.example.test\n");
    config.plugins.push(large);
    let engine = MitmEngine::new(&config).expect("a 3 MiB plugin loads");
    assert!(engine.intercepts("large.example.test"));
    assert_eq!(engine.plugin_rules().len(), index);
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
        resource_assets: Default::default(),
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

#[cfg(feature = "scripts")]
#[tokio::test]
async fn scheduled_scripts_run_by_hand_and_on_network_changes() {
    use engine_embedded::control::ScriptControl;

    let dir = std::env::temp_dir().join(format!("networkcore-mitm-cron-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let checkin = dir.join("checkin.js");
    std::fs::write(
        &checkin,
        "$notification.post('Check-in', $script.type, typeof $request + ',' + $argument);\n$done();",
    )
    .unwrap();
    let net = dir.join("net.js");
    std::fs::write(
        &net,
        "$notification.post('Net', $event.name, '');\n$done();",
    )
    .unwrap();
    let plugin = "#!name = Tasks\n\
[Script]\n\
cron \"0 9 * * *\" script-path=https://scripts.example.test/checkin.js, tag=checkin, argument=a=1\n\
network-changed script-path=https://scripts.example.test/net.js, tag=net\n\
\n\
[MITM]\n\
hostname = api.example.test\n";
    let device_root = root("NetworkCore Test Device Root");
    let base64 = base64::engine::general_purpose::STANDARD;
    let config = MitmConfig {
        policy: String::new(),
        plugins: vec![plugin.to_string()],
        ca_certificate: base64.encode(&device_root.certificate),
        ca_private_key: base64.encode(x963(&device_root.key)),
        script_assets: [
            (
                "https://scripts.example.test/checkin.js".to_string(),
                checkin.display().to_string(),
            ),
            (
                "https://scripts.example.test/net.js".to_string(),
                net.display().to_string(),
            ),
        ]
        .into(),
        resource_assets: Default::default(),
        script_store_path: None,
    };
    let engine = Arc::new(MitmEngine::new(&config).unwrap());
    let scripts = engine.script_control(&ScriptControl::Scripts).unwrap();
    assert_eq!(scripts["scripts"][0]["tag"], "checkin");
    assert_eq!(scripts["scripts"][0]["trigger"], "cron");
    assert!(
        scripts["scripts"][0]["next_run"].as_str().is_some(),
        "{scripts}"
    );
    assert_eq!(scripts["scripts"][1]["trigger"], "network-changed");

    let background = engine.clone().background().expect("scheduled scripts run");
    tokio::spawn(background);
    let run = engine
        .script_control(&ScriptControl::Run {
            tag: "checkin".to_string(),
        })
        .unwrap();
    assert_eq!(run["scheduled"], true);
    let changed = engine
        .script_control(&ScriptControl::NetworkChanged)
        .unwrap();
    assert_eq!(changed["scheduled"], 1);

    let mut seen = Vec::new();
    for _ in 0..200 {
        let notifications = engine
            .script_control(&ScriptControl::Notifications)
            .unwrap();
        for notification in notifications["notifications"].as_array().unwrap() {
            seen.push(format!(
                "{}|{}|{}",
                notification["title"].as_str().unwrap(),
                notification["subtitle"].as_str().unwrap(),
                notification["content"].as_str().unwrap()
            ));
        }
        if seen.len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        seen,
        ["Check-in|cron|undefined,a=1", "Net|network-changed|"],
        "notifications; scripts: {}",
        engine.script_control(&ScriptControl::Scripts).unwrap()
    );
    let scripts = engine.script_control(&ScriptControl::Scripts).unwrap();
    assert_eq!(scripts["scripts"][0]["last_status"], "done");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Desktop: the same `mitm` section on the local SOCKS5/HTTP listener. A
/// listed host is answered with a leaf signed by the device root before any
/// outbound connection exists; other tunnels are relayed untouched.
#[cfg(feature = "local-proxy")]
#[tokio::test]
async fn local_proxy_decrypts_listed_hosts_and_relays_the_rest() {
    use engine_embedded::local_proxy::LocalProxy;
    use inbound_mixed::MixedSettings;
    use tokio::net::{TcpListener, TcpStream};

    const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";
    async fn connect(proxy: SocketAddr, authority: &str) -> TcpStream {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut answer = vec![0u8; ESTABLISHED.len()];
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer, ESTABLISHED);
        stream
    }

    let device_root = root("NetworkCore Test Device Root");
    let config = mitm_config(&device_root);
    let envelope = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "profile_id": "mitm-desktop",
        "outbound": { "type": "direct" },
        "mitm": {
            "policy": config.policy,
            "ca_certificate": config.ca_certificate,
            "ca_private_key": config.ca_private_key,
        },
    }))
    .unwrap();
    let proxy = LocalProxy::start(
        &envelope,
        "127.0.0.1:0".parse().unwrap(),
        MixedSettings::default(),
    )
    .unwrap();
    assert!(proxy.decrypts_https());

    let stream = connect(proxy.local_addr(), &format!("{HOST}:443")).await;
    let trust = trusting(&device_root.certificate, &[b"http/1.1"]);
    let tls = tokio_rustls::TlsConnector::from(Arc::new(trust))
        .connect(ServerName::try_from(HOST).unwrap(), stream)
        .await
        .expect("the listed host is served with a leaf from the device root");
    drop(tls);
    assert_eq!(proxy.mitm_stats().mitm_flows, 1);

    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = echo.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    let mut stream = connect(proxy.local_addr(), &echo_addr.to_string()).await;
    stream.write_all(b"not for decryption").await.unwrap();
    let mut echoed = [0u8; 18];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut echoed))
        .await
        .expect("relayed in time")
        .unwrap();
    assert_eq!(&echoed, b"not for decryption");
    assert_eq!(proxy.mitm_stats().mitm_flows, 1);

    // Without the section the listener only relays.
    let plain = LocalProxy::start(
        br#"{"schema_version":1,"profile_id":"desktop","outbound":{"type":"direct"}}"#,
        "127.0.0.1:0".parse().unwrap(),
        MixedSettings::default(),
    )
    .unwrap();
    assert!(!plain.decrypts_https());
}
