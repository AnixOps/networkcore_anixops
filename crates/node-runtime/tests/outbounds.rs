//! Base outbounds a binary registers by name: an inbound's `outbound` key or
//! the node's default picks one, `"direct"` always means direct, and an
//! unknown name refuses the inbound.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpDialer, TcpOutbound};
use node_runtime::{default_registry, DirectOutbound, InboundConfig, Node, NodeOutbound};
use outbound_shadowsocks::{Method, Ss2022Outbound};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const TIMEOUT: Duration = Duration::from_secs(10);
const SERVER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQ==";
const USER_KEY: &str = "AgICAgICAgICAgICAgICAg==";

/// Connects directly and counts the connections it opened.
struct Counting {
    direct: DirectOutbound,
    connects: AtomicU64,
}

impl TcpOutbound for Counting {
    fn protocol(&self) -> &'static str {
        "counting"
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, std::io::Result<BoxStream>> {
        self.connects.fetch_add(1, Ordering::Relaxed);
        self.direct.connect(target)
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

fn inbound(tag: &str, outbound: Option<&str>) -> InboundConfig {
    let mut value = json!({
        "tag": tag, "type": "shadowsocks", "listen": "127.0.0.1", "listen_port": 0,
        "method": "2022-blake3-aes-128-gcm", "password": SERVER_KEY,
        "users": [{"name": "1001", "password": USER_KEY}]
    });
    if let Some(name) = outbound {
        value["outbound"] = name.into();
    }
    serde_json::from_value(value).unwrap()
}

async fn round_trip(server: SocketAddr, target: SocketAddr) {
    let client = Ss2022Outbound::new(
        server.ip().to_string(),
        server.port(),
        Method::Aes128Gcm,
        &format!("{SERVER_KEY}:{USER_KEY}"),
        Arc::new(TcpDialer),
    )
    .unwrap();
    let mut stream = client.connect(&TargetAddr::Ip(target)).await.unwrap();
    stream.write_all(b"through the base").await.unwrap();
    let mut received = [0u8; 16];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut received))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(&received, b"through the base");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbounds_pick_their_base_outbound() {
    let target = echo_server().await;
    let counting = Arc::new(Counting {
        direct: DirectOutbound::new(true, Vec::new()),
        connects: AtomicU64::new(0),
    });
    let udp = Arc::new(DirectOutbound::new(true, Vec::new()));
    let node = Node::new(default_registry(), true)
        .with_outbound("line", NodeOutbound::new(counting.clone(), udp))
        .with_default_outbound(Some("line".into()));
    assert_eq!(node.outbounds(), vec!["line".to_owned()]);

    // The default applies to an inbound without the key.
    let by_default = node.add_inbound(inbound("default", None)).await.unwrap();
    round_trip(by_default, target).await;
    assert_eq!(counting.connects.load(Ordering::Relaxed), 1);

    // An explicit name does too; "direct" bypasses it.
    let named = node
        .add_inbound(inbound("named", Some("line")))
        .await
        .unwrap();
    round_trip(named, target).await;
    assert_eq!(counting.connects.load(Ordering::Relaxed), 2);
    let direct = node
        .add_inbound(inbound("direct", Some("direct")))
        .await
        .unwrap();
    round_trip(direct, target).await;
    assert_eq!(counting.connects.load(Ordering::Relaxed), 2);

    let listed: Vec<(String, String)> = node
        .list()
        .into_iter()
        .map(|info| (info.tag, info.outbound))
        .collect();
    assert_eq!(
        listed,
        vec![
            ("default".to_owned(), "line".to_owned()),
            ("direct".to_owned(), "direct".to_owned()),
            ("named".to_owned(), "line".to_owned()),
        ]
    );

    // An unknown name refuses the inbound before anything binds.
    let error = node
        .add_inbound(inbound("unknown", Some("nowhere")))
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "inbound names an unknown outbound");
    assert_eq!(node.list().len(), 3);
}
