//! Rule-based outbound dispatch with recording test outbounds.

use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use config_core::routing::{PolicyGroupSpec, RouteOutcome, RoutingSpec};
use engine_embedded::routing::RoutedOutbound;
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};

/// Records the target and fails, so tests see which outbound was chosen.
struct Recording {
    name: &'static str,
    hits: Arc<Mutex<Vec<&'static str>>>,
}

impl TcpOutbound for Recording {
    fn protocol(&self) -> &'static str {
        "test-recording"
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            self.hits.lock().unwrap().push(self.name);
            Err(io::Error::other("recording outbound does not connect"))
        })
    }
}

fn routed(hits: &Arc<Mutex<Vec<&'static str>>>) -> RoutedOutbound {
    let recording = |name| -> Arc<dyn TcpOutbound> {
        Arc::new(Recording {
            name,
            hits: hits.clone(),
        })
    };
    let nodes = BTreeMap::from([
        ("hk-1".to_string(), recording("hk-1")),
        ("jp-1".to_string(), recording("jp-1")),
    ]);
    let spec = RoutingSpec {
        rules: vec![
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve".to_string(),
            "IP-CIDR,198.51.100.0/24,REJECT,no-resolve".to_string(),
            "DOMAIN-SUFFIX,example.jp,jp-1".to_string(),
            "IP-CIDR6,2001:db8::/32,Auto".to_string(),
            "FINAL,Proxy".to_string(),
        ],
        groups: vec![
            PolicyGroupSpec {
                id: "Proxy".to_string(),
                kind: "select".to_string(),
                members: vec!["Auto".to_string(), "jp-1".to_string()],
                default: Some("jp-1".to_string()),
                url: None,
                interval_secs: None,
                tolerance_ms: None,
            },
            PolicyGroupSpec {
                id: "Auto".to_string(),
                kind: "url-test".to_string(),
                members: vec!["hk-1".to_string(), "jp-1".to_string()],
                default: None,
                url: None,
                interval_secs: None,
                tolerance_ms: None,
            },
        ],
    };
    RoutedOutbound::new(&spec, recording("direct"), nodes).expect("spec should validate")
}

fn ip(addr: &str) -> TargetAddr {
    TargetAddr::Ip(addr.parse::<SocketAddr>().unwrap())
}

#[test]
fn routes_targets_by_rules_and_groups() {
    let hits = Arc::new(Mutex::new(Vec::new()));
    let outbound = routed(&hits);

    assert_eq!(outbound.route(&ip("10.1.2.3:443")), RouteOutcome::Direct);
    assert_eq!(
        outbound.route(&ip("198.51.100.7:443")),
        RouteOutcome::Reject
    );
    assert_eq!(
        outbound.route(&ip("[2001:db8::1]:443")),
        RouteOutcome::Node("hk-1".to_string())
    );
    assert_eq!(
        outbound.route(&ip("203.0.113.9:443")),
        RouteOutcome::Node("jp-1".to_string())
    );
    assert_eq!(
        outbound.route(&TargetAddr::Domain("www.example.jp".to_string(), 443)),
        RouteOutcome::Node("jp-1".to_string())
    );
    // A domain that reaches an IP rule is not resolved, so it is rejected.
    assert_eq!(
        outbound.route(&TargetAddr::Domain("other.example".to_string(), 443)),
        RouteOutcome::Reject
    );
}

#[test]
fn connect_dispatches_to_the_routed_outbound() {
    let hits = Arc::new(Mutex::new(Vec::new()));
    let outbound = routed(&hits);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    runtime.block_on(async {
        for target in [
            "10.1.2.3:443",
            "[2001:db8::1]:443",
            "203.0.113.9:443",
            "198.51.100.7:443",
        ] {
            let _ = outbound.connect(&ip(target)).await;
        }
    });

    assert_eq!(*hits.lock().unwrap(), vec!["direct", "hk-1", "jp-1"]);
    let rejected = runtime
        .block_on(outbound.connect(&ip("198.51.100.7:443")))
        .err()
        .expect("rejected target should fail");
    assert_eq!(rejected.kind(), io::ErrorKind::PermissionDenied);
}
