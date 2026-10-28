//! The network plan: `egress:<id>` outbounds bound to their source, inbounds
//! in an ingress taking its path (a local egress or a transport's
//! registered outbound), and plans refused as a whole.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpDialer, TcpOutbound};
use node_runtime::{
    default_registry, DirectOutbound, InboundConfig, NetworkPlan, Node, NodeOutbound,
};
use outbound_shadowsocks::{Method, Ss2022Outbound};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const TIMEOUT: Duration = Duration::from_secs(10);
const SERVER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQ==";
const USER_KEY: &str = "AgICAgICAgICAgICAgICAg==";

/// Stands in for a transport's outbound; counts its connections.
struct Transport {
    direct: DirectOutbound,
    connects: AtomicU64,
}

impl TcpOutbound for Transport {
    fn protocol(&self) -> &'static str {
        "transport"
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, std::io::Result<BoxStream>> {
        self.connects.fetch_add(1, Ordering::Relaxed);
        self.direct.connect(target)
    }
}

/// An echo server that records the address of its last peer.
async fn echo_server() -> (SocketAddr, Arc<Mutex<Option<SocketAddr>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = Arc::new(Mutex::new(None));
    let last = peer.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, from)) = listener.accept().await {
            *last.lock().unwrap() = Some(from);
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    (addr, peer)
}

fn inbound(tag: &str, key: &str, value: &str) -> InboundConfig {
    let mut config = json!({
        "tag": tag, "type": "shadowsocks", "listen": "127.0.0.1", "listen_port": 0,
        "method": "2022-blake3-aes-128-gcm", "password": SERVER_KEY,
        "users": [{"name": "1001", "password": USER_KEY}]
    });
    config[key] = value.into();
    serde_json::from_value(config).unwrap()
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
    stream.write_all(b"through the path").await.unwrap();
    let mut received = [0u8; 16];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut received))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(&received, b"through the path");
}

/// A local address other than 127.0.0.1 where the OS has one.
fn source() -> IpAddr {
    if cfg!(target_os = "linux") {
        "127.0.0.2"
    } else {
        "127.0.0.1"
    }
    .parse()
    .unwrap()
}

fn plan(value: serde_json::Value) -> NetworkPlan {
    serde_json::from_value(value).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ingresses_take_their_paths() {
    let (target, peer) = echo_server().await;
    let transport = Arc::new(Transport {
        direct: DirectOutbound::new(true, Vec::new()),
        connects: AtomicU64::new(0),
    });
    let udp = Arc::new(DirectOutbound::new(true, Vec::new()));
    let node = Node::new(default_registry(), true)
        .with_outbound("anx-line:7", NodeOutbound::new(transport.clone(), udp));

    let status = node
        .apply_network(&plan(json!({
            "generation": "3",
            "egresses": [{"id": "local-v4", "source": source().to_string(),
                          "kind": "EGRESS_KIND_NAT_DIRECT"}],
            "ingresses": [
                {"id": "via-line", "pairing": {"mode": "PAIRING_MODE_FAILOVER",
                                               "egressIds": ["jp", "local-v4"]}},
                {"id": "local", "pairing": {"mode": "PAIRING_MODE_SAME_LINE",
                                            "egress_ids": ["local-v4"]}}
            ],
            "transports": [{"id": "7", "kind": "TRANSPORT_KIND_ANX_LINE",
                            "anx_line": {"link_id": "7", "link_key": "not kept"}}],
            "paths": [
                {"id": "p-jp", "ingress_id": "via-line", "transport_id": "7",
                 "final_egress_id": "jp"},
                {"id": "p-local", "ingress_id": "via-line", "egress_id": "local-v4"},
                {"id": "p-same", "ingress_id": "local", "egress_id": "local-v4"}
            ]
        })))
        .await
        .unwrap();
    assert_eq!(status.generation, 3);
    let active: Vec<(String, Option<String>)> = status
        .ingresses
        .iter()
        .map(|ingress| (ingress.id.clone(), ingress.active_path_id.clone()))
        .collect();
    assert_eq!(
        active,
        vec![
            ("local".to_owned(), Some("p-same".to_owned())),
            ("via-line".to_owned(), Some("p-jp".to_owned())),
        ]
    );

    // The first path of "via-line" goes into the transport.
    let via_line = node
        .add_inbound(inbound("via-line", "ingress", "via-line"))
        .await
        .unwrap();
    round_trip(via_line, target).await;
    assert_eq!(transport.connects.load(Ordering::Relaxed), 1);

    // A local egress leaves from its source address.
    let local = node
        .add_inbound(inbound("local", "ingress", "local"))
        .await
        .unwrap();
    round_trip(local, target).await;
    assert_eq!(peer.lock().unwrap().unwrap().ip(), source());

    // `egress:<id>` is an outbound name too.
    let named = node
        .add_inbound(inbound("named", "outbound", "egress:local-v4"))
        .await
        .unwrap();
    round_trip(named, target).await;
    assert_eq!(transport.connects.load(Ordering::Relaxed), 1);

    let listed: Vec<(String, String, Option<String>)> = node
        .list()
        .into_iter()
        .map(|info| (info.tag, info.outbound, info.ingress))
        .collect();
    assert_eq!(
        listed[0],
        (
            "local".to_owned(),
            "ingress:local".to_owned(),
            Some("local".to_owned())
        )
    );

    // An inbound takes an ingress or an outbound, not both.
    let mut both = inbound("both", "ingress", "local");
    both.outbound = Some("direct".into());
    assert!(node.add_inbound(both).await.is_err());

    // A path into a transport this binary has no outbound for refuses the
    // whole plan; the running one stays.
    let error = node
        .apply_network(&plan(json!({
            "ingresses": [{"id": "x"}],
            "transports": [{"id": "8", "kind": "anx_line"}],
            "paths": [{"id": "p", "ingress_id": "x", "transport_id": "8"}]
        })))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("anx-line:8"), "{error}");
    assert_eq!(node.network_state().generation, 3);
}

/// The golden plans of anix-control `contracts/network/v1/` (copied into
/// `tests/fixtures/network-v1/`): the kernel reads each one as the agent
/// hands it down.
#[tokio::test]
async fn reads_the_contract_golden_plans() {
    let golden = |name: &str| -> NetworkPlan {
        let path = format!(
            "{}/tests/fixtures/network-v1/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    };
    let udp = Arc::new(DirectOutbound::new(false, Vec::new()));
    let transport = || NodeOutbound::new(udp.clone(), udp.clone());

    // Ingress device: failover between two ANX-Line transports.
    let ingress = Node::new(default_registry(), false)
        .with_outbound("anx-line:tr-jp", transport())
        .with_outbound("anx-line:tr-hk", transport());
    let status = ingress
        .apply_network(&golden("plan-anx-line-ingress"))
        .await
        .unwrap();
    assert_eq!(status.generation, 1);
    assert_eq!(status.ingresses[0].id, "in-ss");
    assert_eq!(status.ingresses[0].active_path_id.as_deref(), Some("pa-jp"));
    assert_eq!(
        status.ingresses[0].active_egress_id.as_deref(),
        Some("eg-jp")
    );
    // Without the transport outbounds the plan is refused.
    assert!(Node::new(default_registry(), false)
        .apply_network(&golden("plan-anx-line-ingress"))
        .await
        .is_err());

    // Egress device: its egresses are probed and bound to their source.
    let egress = Node::new(default_registry(), false);
    let status = egress
        .apply_network(&golden("plan-anx-line-egress"))
        .await
        .unwrap();
    let egresses: Vec<(&str, bool)> = status
        .egresses
        .iter()
        .map(|egress| (egress.id.as_str(), egress.checked))
        .collect();
    assert_eq!(egresses, vec![("eg-jp", true), ("eg-jp6", false)]);

    // One box, two lines: same-line, cross and a local transport.
    let single = Node::new(default_registry(), false);
    let status = single
        .apply_network(&golden("plan-dual-line-single-box"))
        .await
        .unwrap();
    let active: Vec<(&str, Option<&str>)> = status
        .ingresses
        .iter()
        .map(|ingress| (ingress.id.as_str(), ingress.active_egress_id.as_deref()))
        .collect();
    assert_eq!(
        active,
        vec![
            ("in-9929", Some("eg-9929")),
            ("in-cn2-nat", Some("eg-9929")),
            ("in-cn2-v6", Some("eg-cn2")),
        ]
    );
}

/// Outbounds registered by prefix: transports added after the node started
/// (anx-node's `anx-line:<link id>`) are resolved when a plan or an inbound
/// names them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resolves_outbounds_by_prefix() {
    let (target, _) = echo_server().await;
    let transport = Arc::new(Transport {
        direct: DirectOutbound::new(true, Vec::new()),
        connects: AtomicU64::new(0),
    });
    let resolver_transport = transport.clone();
    let node = Node::new(default_registry(), true).with_outbound_prefix(
        "anx-line:",
        Arc::new(move |id: &str| {
            (id != "unknown").then(|| {
                let udp = Arc::new(DirectOutbound::new(true, Vec::new()));
                NodeOutbound::new(resolver_transport.clone(), udp)
            })
        }),
    );
    node.apply_network(&plan(json!({
        "ingresses": [{"id": "i"}],
        "transports": [{"id": "late", "kind": "anx_line"}],
        "paths": [{"id": "p", "ingress_id": "i", "transport_id": "late"}]
    })))
    .await
    .unwrap();
    let ingress = node
        .add_inbound(inbound("in", "ingress", "i"))
        .await
        .unwrap();
    round_trip(ingress, target).await;
    assert_eq!(transport.connects.load(Ordering::Relaxed), 1);

    let named = node
        .add_inbound(inbound("named", "outbound", "anx-line:other"))
        .await
        .unwrap();
    round_trip(named, target).await;
    assert_eq!(transport.connects.load(Ordering::Relaxed), 2);

    // The resolver refuses a name: the plan and the inbound are refused.
    assert!(node
        .apply_network(&plan(json!({
            "ingresses": [{"id": "i"}],
            "transports": [{"id": "unknown", "kind": "anx_line"}],
            "paths": [{"id": "p", "ingress_id": "i", "transport_id": "unknown"}]
        })))
        .await
        .is_err());
    assert!(node
        .add_inbound(inbound("bad", "outbound", "anx-line:unknown"))
        .await
        .is_err());
    // Nothing follows the prefix: no outbound.
    assert!(node
        .add_inbound(inbound("bare", "outbound", "anx-line:"))
        .await
        .is_err());
}
