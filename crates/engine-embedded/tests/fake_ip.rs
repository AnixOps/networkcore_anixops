//! Fake-IP through the dispatcher: a flow to a fake address leaves by name,
//! a DIRECT one by the address the `dns` section gives, and an address that
//! maps to nothing is refused.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use config_core::routing::RoutingSpec;
use engine_embedded::config::{FakeIpConfig, RuntimeConfig};
use engine_embedded::connections::Dispatcher;
use engine_embedded::fake_ip::FakeIpPool;
use engine_embedded::routing::{DomainResolver, RoutedOutbound};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Echoes every connection in memory and records the targets it was given.
struct Recording {
    protocol: &'static str,
    targets: Mutex<Vec<TargetAddr>>,
}

impl Recording {
    fn new(protocol: &'static str) -> Arc<Self> {
        Arc::new(Self {
            protocol,
            targets: Mutex::new(Vec::new()),
        })
    }

    fn targets(&self) -> Vec<TargetAddr> {
        self.targets.lock().unwrap().clone()
    }
}

impl TcpOutbound for Recording {
    fn protocol(&self) -> &'static str {
        self.protocol
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        self.targets.lock().unwrap().push(target.clone());
        Box::pin(async {
            let (client, mut server) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = server.read(&mut buf).await {
                    if n == 0 || server.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
            Ok(Box::new(client) as BoxStream)
        })
    }
}

/// Answers every name with one address.
struct Fixed(IpAddr);

impl DomainResolver for Fixed {
    fn resolve<'a>(&'a self, _domain: &'a str) -> BoxFuture<'a, io::Result<IpAddr>> {
        let address = self.0;
        Box::pin(async move { Ok(address) })
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn pool() -> Arc<FakeIpPool> {
    FakeIpPool::from_config(&FakeIpConfig {
        enabled: true,
        ..FakeIpConfig::default()
    })
    .unwrap()
    .unwrap()
}

fn fake(pool: &FakeIpPool, name: &str, port: u16) -> TargetAddr {
    TargetAddr::Ip(SocketAddr::new(IpAddr::V4(pool.assign(name)), port))
}

async fn round_trip(dispatcher: &Dispatcher, target: &TargetAddr, host: Option<&str>) {
    let mut stream = dispatcher.connect_flow(target, host).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");
}

#[test]
fn a_fake_address_goes_out_by_name() {
    let pool = pool();
    let node = Recording::new("test-node");
    let dispatcher = Dispatcher::single(node.clone()).with_fake_ip(Some(pool.clone()));
    let ssh = fake(&pool, "git.example.com", 22);
    runtime().block_on(async {
        round_trip(&dispatcher, &ssh, None).await;
        // A real address is left alone.
        let real = TargetAddr::Ip("192.0.2.1:443".parse().unwrap());
        round_trip(&dispatcher, &real, None).await;
    });
    assert_eq!(
        node.targets(),
        vec![
            TargetAddr::Domain("git.example.com".to_string(), 22),
            TargetAddr::Ip("192.0.2.1:443".parse().unwrap()),
        ]
    );
    let listed = dispatcher.tracker().connections();
    assert!(listed
        .closed
        .iter()
        .chain(listed.active.iter())
        .any(|connection| connection.destination == "git.example.com:22"));
}

#[test]
fn domain_rules_match_the_name_of_a_fake_address() {
    let pool = pool();
    let node = Recording::new("test-node");
    let direct = Recording::new(engine_embedded::direct::PROTOCOL);
    let spec = RoutingSpec {
        rules: vec![
            "DOMAIN-SUFFIX,proxied.test,hk-1".to_string(),
            "FINAL,DIRECT".to_string(),
        ],
        groups: Vec::new(),
    };
    let nodes = BTreeMap::from([("hk-1".to_string(), node.clone() as Arc<dyn TcpOutbound>)]);
    let routed = RoutedOutbound::new(&spec, direct.clone(), nodes)
        .unwrap()
        .with_resolver(Arc::new(Fixed(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)))));
    let dispatcher = Dispatcher::routed(Arc::new(routed)).with_fake_ip(Some(pool.clone()));
    runtime().block_on(async {
        round_trip(&dispatcher, &fake(&pool, "www.proxied.test", 443), None).await;
        round_trip(&dispatcher, &fake(&pool, "cn.example", 8080), None).await;
    });
    assert_eq!(
        node.targets(),
        vec![TargetAddr::Domain("www.proxied.test".to_string(), 443)]
    );
    // DIRECT gets the address of the `dns` section, never the bare name.
    assert_eq!(
        direct.targets(),
        vec![TargetAddr::Ip("203.0.113.9:8080".parse().unwrap())]
    );
}

#[test]
fn a_direct_name_that_resolves_into_the_range_is_refused() {
    let pool = pool();
    let direct = Recording::new(engine_embedded::direct::PROTOCOL);
    let spec = RoutingSpec {
        rules: vec!["FINAL,DIRECT".to_string()],
        groups: Vec::new(),
    };
    let routed = RoutedOutbound::new(&spec, direct.clone(), BTreeMap::new())
        .unwrap()
        .with_resolver(Arc::new(Fixed(IpAddr::V4(Ipv4Addr::new(198, 18, 7, 7)))));
    let dispatcher = Dispatcher::routed(Arc::new(routed)).with_fake_ip(Some(pool.clone()));
    let target = fake(&pool, "loop.example", 80);
    let result = runtime().block_on(dispatcher.connect_flow(&target, None));
    assert!(result.is_err());
    assert!(direct.targets().is_empty());
}

#[test]
fn unknown_fake_addresses_are_refused_or_recovered_by_the_sniffed_name() {
    let pool = pool();
    let node = Recording::new("test-node");
    let dispatcher = Dispatcher::single(node.clone()).with_fake_ip(Some(pool.clone()));
    let unknown = TargetAddr::Ip("198.18.200.1:443".parse().unwrap());
    let stale = fake(&pool, "old.example", 443);
    runtime().block_on(async {
        assert!(dispatcher.connect_flow(&unknown, None).await.is_err());
        round_trip(&dispatcher, &unknown, Some("www.example.org")).await;
        // The app reuses an address that now stands for another name: the
        // SNI it sends wins and the conflict is counted.
        round_trip(&dispatcher, &stale, Some("new.example")).await;
    });
    assert_eq!(
        node.targets(),
        vec![
            TargetAddr::Domain("www.example.org".to_string(), 443),
            TargetAddr::Domain("new.example".to_string(), 443),
        ]
    );
    let stats = pool.stats();
    assert_eq!(stats.misses, 2);
    assert_eq!(stats.recovered, 1);
    assert_eq!(stats.conflicts, 1);
}

#[test]
fn runtime_config_builds_one_pool_and_checks_hosts() {
    let config = |hosts: &str| {
        format!(
            r#"{{
                "schema_version": 1,
                "profile_id": "fake-ip",
                "outbound": {{"type": "direct"}},
                "dns": {{
                    "fake_ip": {{"enabled": true, "max_entries": 1000, "filter": ["+.corp.example"]}},
                    "hosts": {hosts}
                }}
            }}"#
        )
    };
    let parsed =
        RuntimeConfig::from_json(config(r#"{"nas.example": ["192.168.1.2"]}"#).as_bytes()).unwrap();
    let pool = parsed.fake_ip_pool().unwrap().unwrap();
    assert_eq!(pool.capacity(), 1000);
    assert!(!pool.is_fake_name("git.corp.example"));
    assert!(
        RuntimeConfig::from_json(config(r#"{"nas.example": ["198.18.3.4"]}"#).as_bytes()).is_err()
    );
    let off = RuntimeConfig::from_json(
        br#"{"schema_version": 1, "profile_id": "off", "outbound": {"type": "direct"}}"#,
    )
    .unwrap();
    assert!(off.fake_ip_pool().unwrap().is_none());
}
