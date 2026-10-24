//! Rule-based outbound dispatch with recording test outbounds.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use config_core::routing::{PolicyGroupSpec, RouteOutcome, RoutingSpec};
use config_core::rule_set::RuleSet;
use engine_embedded::routing::{DomainResolver, RoutedOutbound};
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

/// Answers from a fixed table and records every lookup.
struct FixedResolver {
    lookups: Arc<Mutex<Vec<String>>>,
}

impl DomainResolver for FixedResolver {
    fn resolve<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, io::Result<IpAddr>> {
        Box::pin(async move {
            self.lookups.lock().unwrap().push(domain.to_string());
            match domain {
                "v6.example" => Ok("2001:db8::5".parse().unwrap()),
                "v4.example" => Ok("203.0.113.9".parse().unwrap()),
                _ => Err(io::Error::new(io::ErrorKind::NotFound, "no such domain")),
            }
        })
    }
}

#[test]
fn domains_are_resolved_only_when_an_ip_rule_needs_them() {
    let hits = Arc::new(Mutex::new(Vec::new()));
    let lookups = Arc::new(Mutex::new(Vec::new()));
    let outbound = routed(&hits).with_resolver(Arc::new(FixedResolver {
        lookups: lookups.clone(),
    }));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let domain = |name: &str| TargetAddr::Domain(name.to_string(), 443);

    runtime.block_on(async {
        // A domain rule matches before any IP rule asks for an address.
        assert_eq!(
            outbound.route_resolving(&domain("www.example.jp")).await,
            RouteOutcome::Node("jp-1".to_string())
        );
        // The resolved address matches the IP-CIDR6 rule (Auto -> hk-1).
        assert_eq!(
            outbound.route_resolving(&domain("v6.example")).await,
            RouteOutcome::Node("hk-1".to_string())
        );
        // An address no IP rule holds falls through to FINAL.
        assert_eq!(
            outbound.route_resolving(&domain("v4.example")).await,
            RouteOutcome::Node("jp-1".to_string())
        );
        // A failed lookup rejects the connection, as in sing-box.
        assert_eq!(
            outbound.route_resolving(&domain("missing.example")).await,
            RouteOutcome::Reject
        );
        // IP targets never trigger a lookup.
        assert_eq!(
            outbound.route_resolving(&ip("10.1.2.3:443")).await,
            RouteOutcome::Direct
        );
        let _ = outbound.connect(&domain("v6.example")).await;
    });

    assert_eq!(
        *lookups.lock().unwrap(),
        vec!["v6.example", "v4.example", "missing.example", "v6.example"]
    );
    assert_eq!(*hits.lock().unwrap(), vec!["hk-1"]);
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

#[test]
fn rule_sets_route_large_lists_without_resolving_domains() {
    let hits = Arc::new(Mutex::new(Vec::new()));
    let recording = |name| -> Arc<dyn TcpOutbound> {
        Arc::new(Recording {
            name,
            hits: hits.clone(),
        })
    };
    let nodes = BTreeMap::from([("proxy".to_string(), recording("proxy"))]);
    let spec = RoutingSpec {
        rules: vec![
            "RULE-SET,china,DIRECT".to_string(),
            "FINAL,proxy".to_string(),
        ],
        groups: Vec::new(),
    };
    let domains: Vec<String> = (0..50_000).map(|i| format!("site{i}.cn")).collect();
    let china = RuleSet::new(domains.iter().map(String::as_str), ["192.0.2.0/24"]).unwrap();
    let outbound = RoutedOutbound::with_rule_sets(
        &spec,
        recording("direct"),
        nodes.clone(),
        BTreeMap::from([("china".to_string(), china)]),
    )
    .expect("rule set is configured");

    let domain = |name: &str| TargetAddr::Domain(name.to_string(), 443);
    assert_eq!(
        outbound.route(&domain("www.site49999.cn")),
        RouteOutcome::Direct
    );
    assert_eq!(outbound.route(&ip("192.0.2.9:443")), RouteOutcome::Direct);
    assert_eq!(
        outbound.route(&domain("example.com")),
        RouteOutcome::Node("proxy".to_string())
    );
    assert_eq!(
        outbound.route(&ip("203.0.113.9:443")),
        RouteOutcome::Node("proxy".to_string())
    );

    // A RULE-SET rule naming a set the config does not carry is rejected.
    assert!(RoutedOutbound::new(&spec, recording("direct"), nodes).is_err());
}
