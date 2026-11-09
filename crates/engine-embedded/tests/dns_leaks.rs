//! No path sends a proxied name to a resolver in the clear.
//!
//! Three paths are checked, each with test outbounds that record every
//! connection and answer DNS over TCP:
//!
//! 1. a name routed to the proxy goes out by name, and a `proxy` DNS server
//!    is never reached DIRECT because a rule (such as `FINAL,DIRECT`) said so;
//! 2. a name an IP rule must resolve first is resolved with the `dns` section
//!    (proxied unless a DNS rule picks a `direct` server), never the system
//!    resolver;
//! 3. only bootstrap names (a `direct` server's own host name) go DIRECT; a
//!    `proxy` server given by name is handed to the node by name.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use config_core::routing::{PolicyGroupSpec, RouteOutcome, RoutingSpec};
use engine_embedded::config::{DnsConfig, DnsRuleConfig, DnsServerConfig, DnsVia};
use engine_embedded::connections::{Dispatcher, Mode};
use engine_embedded::dns_policy::DnsPolicy;
use engine_embedded::dns_resolver::PolicyResolver;
use engine_embedded::routing::{DomainResolver, RoutedOutbound};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// One connection an outbound was asked for: the outbound and the target.
type Hits = Arc<Mutex<Vec<(&'static str, String)>>>;

/// Records each connection and answers DNS over TCP on it with an A record
/// from `answers` (by question name; 192.0.2.1 for any other name).
struct DnsAnswering {
    name: &'static str,
    hits: Hits,
    /// Question names this outbound carried.
    asked: Arc<Mutex<Vec<String>>>,
    answers: BTreeMap<&'static str, [u8; 4]>,
}

impl TcpOutbound for DnsAnswering {
    fn protocol(&self) -> &'static str {
        "test-dns"
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            self.hits
                .lock()
                .unwrap()
                .push((self.name, target_string(target)));
            let (client, mut server) = tokio::io::duplex(4096);
            let asked = self.asked.clone();
            let answers = self.answers.clone();
            tokio::spawn(async move {
                loop {
                    let mut length = [0u8; 2];
                    if server.read_exact(&mut length).await.is_err() {
                        return;
                    }
                    let mut query = vec![0u8; usize::from(u16::from_be_bytes(length))];
                    if server.read_exact(&mut query).await.is_err() {
                        return;
                    }
                    let Some(question) = engine_embedded::dns::question(&query) else {
                        return;
                    };
                    asked.lock().unwrap().push(question.name.clone());
                    let address = answers
                        .get(question.name.as_str())
                        .copied()
                        .unwrap_or([192, 0, 2, 1]);
                    let reply = answer(&query, question.end, question.qtype, address);
                    let mut framed = (reply.len() as u16).to_be_bytes().to_vec();
                    framed.extend_from_slice(&reply);
                    if server.write_all(&framed).await.is_err() {
                        return;
                    }
                }
            });
            Ok(Box::new(client) as BoxStream)
        })
    }
}

/// A reply to `query` with one A record (none for other types).
fn answer(query: &[u8], question_end: usize, qtype: u16, address: [u8; 4]) -> Vec<u8> {
    let a = qtype == engine_embedded::dns::TYPE_A;
    let mut reply = query[..question_end].to_vec();
    reply[2] = 0x81;
    reply[3] = 0x80;
    reply[6..8].copy_from_slice(&u16::from(a).to_be_bytes());
    if a {
        reply.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        reply.extend_from_slice(&address);
    }
    reply
}

fn target_string(target: &TargetAddr) -> String {
    match target {
        TargetAddr::Ip(address) => address.to_string(),
        TargetAddr::Domain(name, port) => format!("{name}:{port}"),
    }
}

struct Outbounds {
    hits: Hits,
    asked: Arc<Mutex<Vec<String>>>,
}

impl Outbounds {
    fn new() -> Self {
        Self {
            hits: Arc::default(),
            asked: Arc::default(),
        }
    }

    fn make(&self, name: &'static str) -> Arc<dyn TcpOutbound> {
        Arc::new(DnsAnswering {
            name,
            hits: self.hits.clone(),
            asked: self.asked.clone(),
            answers: BTreeMap::from([
                ("www.example.cn", [203, 0, 113, 7]),
                ("www.blocked.example", [198, 51, 100, 9]),
            ]),
        })
    }

    fn hits(&self) -> Vec<(&'static str, String)> {
        std::mem::take(&mut *self.hits.lock().unwrap())
    }

    fn asked(&self) -> Vec<String> {
        std::mem::take(&mut *self.asked.lock().unwrap())
    }
}

/// A GFW-list style config: listed names to the proxy, everything else
/// DIRECT, plus a rule that sends one DNS server to a chosen node.
fn gfw_list(outbounds: &Outbounds) -> RoutedOutbound {
    let nodes = BTreeMap::from([
        ("hk-1".to_string(), outbounds.make("hk-1")),
        ("jp-1".to_string(), outbounds.make("jp-1")),
    ]);
    let spec = RoutingSpec {
        rules: vec![
            "DOMAIN-SUFFIX,blocked.example,Proxy".to_string(),
            "IP-CIDR,9.9.9.9/32,jp-1,no-resolve".to_string(),
            "IP-CIDR,223.5.5.0/24,DIRECT".to_string(),
            "FINAL,DIRECT".to_string(),
        ],
        groups: vec![PolicyGroupSpec {
            id: "Proxy".to_string(),
            kind: "select".to_string(),
            members: vec!["hk-1".to_string(), "jp-1".to_string()],
            default: Some("hk-1".to_string()),
            url: None,
            interval_secs: None,
            tolerance_ms: None,
        }],
    };
    RoutedOutbound::new(&spec, outbounds.make("direct"), nodes).expect("spec should validate")
}

/// A resolver that must never be asked: routing a DNS server never resolves.
struct NoLookups;

impl DomainResolver for NoLookups {
    fn resolve<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, io::Result<IpAddr>> {
        panic!("{domain} was resolved while routing a DNS server")
    }
}

fn ip(address: &str) -> TargetAddr {
    TargetAddr::Ip(address.parse::<SocketAddr>().unwrap())
}

fn domain(name: &str, port: u16) -> TargetAddr {
    TargetAddr::Domain(name.to_string(), port)
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Opens a connection to `server` the way the tunnel reaches a DNS server.
async fn connect_via(dispatcher: &Dispatcher, via: DnsVia, server: &TargetAddr) {
    let outbound = dispatcher
        .dns_outbound(via, server)
        .expect("routing should not reject the DNS server");
    let _ = outbound.connect(server).await;
}

// Path 1: a proxied name and a proxied DNS server never go DIRECT.

#[test]
fn proxied_dns_servers_never_go_direct_by_a_rule() {
    let outbounds = Outbounds::new();
    let routed = Arc::new(gfw_list(&outbounds).with_resolver(Arc::new(NoLookups)));
    let dispatcher = Dispatcher::routed(routed);

    runtime().block_on(async {
        // FINAL,DIRECT would send 1.1.1.1 direct; the query goes to the proxy.
        connect_via(&dispatcher, DnsVia::Proxy, &ip("1.1.1.1:53")).await;
        assert_eq!(outbounds.hits(), [("hk-1", "1.1.1.1:53".to_string())]);

        // A domestic resolver an IP rule sends DIRECT is still asked through
        // the proxy when it is configured `via: proxy`.
        connect_via(&dispatcher, DnsVia::Proxy, &ip("223.5.5.5:53")).await;
        assert_eq!(outbounds.hits(), [("hk-1", "223.5.5.5:53".to_string())]);

        // A rule that picks a node for the server is kept.
        connect_via(&dispatcher, DnsVia::Proxy, &ip("9.9.9.9:53")).await;
        assert_eq!(outbounds.hits(), [("jp-1", "9.9.9.9:53".to_string())]);

        // Global mode: the global target; direct mode: DIRECT, as asked.
        dispatcher.set_mode(Mode::Global);
        connect_via(&dispatcher, DnsVia::Proxy, &ip("1.1.1.1:53")).await;
        assert_eq!(outbounds.hits(), [("hk-1", "1.1.1.1:53".to_string())]);
        dispatcher.set_mode(Mode::Direct);
        connect_via(&dispatcher, DnsVia::Proxy, &ip("1.1.1.1:53")).await;
        assert_eq!(outbounds.hits(), [("direct", "1.1.1.1:53".to_string())]);
    });
}

#[test]
fn proxied_names_go_out_by_name() {
    let outbounds = Outbounds::new();
    let routed = gfw_list(&outbounds).with_resolver(Arc::new(NoLookups));

    runtime().block_on(async {
        let _ = routed.connect(&domain("www.blocked.example", 443)).await;
    });
    // The node gets the name itself; nothing resolved it locally.
    assert_eq!(
        outbounds.hits(),
        [("hk-1", "www.blocked.example:443".to_string())]
    );
    assert!(outbounds.asked().is_empty());
}

// Path 2: names an IP rule must resolve first use the `dns` section.

fn dns_config() -> DnsConfig {
    DnsConfig {
        servers: vec![
            DnsServerConfig {
                name: "remote".to_string(),
                url: "tcp://1.1.1.1".to_string(),
                server_name: None,
                via: DnsVia::Proxy,
            },
            DnsServerConfig {
                name: "local".to_string(),
                url: "223.5.5.5".to_string(),
                server_name: None,
                via: DnsVia::Direct,
            },
        ],
        hosts: BTreeMap::from([(
            "router.lan".to_string(),
            vec!["192.168.1.1".parse().unwrap()],
        )]),
        rules: vec![DnsRuleConfig {
            domain_suffix: vec!["cn".to_string()],
            server: "local".to_string(),
            ..DnsRuleConfig::default()
        }],
        ..DnsConfig::default()
    }
}

/// `GEOSITE,cn,DIRECT` / `GEOIP,cn,DIRECT` / `FINAL,Proxy` in miniature: a
/// domestic network DIRECT by address, everything else to the proxy.
fn cn_direct(outbounds: &Outbounds) -> Arc<RoutedOutbound> {
    let nodes = BTreeMap::from([("hk-1".to_string(), outbounds.make("hk-1"))]);
    let spec = RoutingSpec {
        rules: vec![
            "IP-CIDR,203.0.113.0/24,DIRECT".to_string(),
            "FINAL,hk-1".to_string(),
        ],
        groups: Vec::new(),
    };
    let resolver = PolicyResolver::new(Arc::new(DnsPolicy::from_config(&dns_config()).unwrap()));
    let routed = Arc::new(
        RoutedOutbound::new(&spec, outbounds.make("direct"), nodes)
            .unwrap()
            .with_resolver(resolver.clone()),
    );
    resolver.bind(&routed);
    routed
}

#[test]
fn ip_rules_resolve_through_the_dns_section() {
    let outbounds = Outbounds::new();
    let routed = cn_direct(&outbounds);

    runtime().block_on(async {
        // A foreign name is resolved by the proxied server, through the node.
        assert_eq!(
            routed
                .route_resolving(&domain("www.blocked.example", 443))
                .await,
            RouteOutcome::Node("hk-1".to_string())
        );
        assert_eq!(outbounds.hits(), [("hk-1", "1.1.1.1:53".to_string())]);
        assert_eq!(outbounds.asked(), ["www.blocked.example"]);

        // A name a DNS rule gives to the domestic server is asked directly,
        // and its domestic address matches the IP rule.
        assert_eq!(
            routed.route_resolving(&domain("www.example.cn", 443)).await,
            RouteOutcome::Direct
        );
        assert_eq!(outbounds.hits(), [("direct", "223.5.5.5:53".to_string())]);
        assert_eq!(outbounds.asked(), ["www.example.cn"]);

        // Answers are kept: no second query.
        assert_eq!(
            routed
                .route_resolving(&domain("www.blocked.example", 443))
                .await,
            RouteOutcome::Node("hk-1".to_string())
        );
        assert!(outbounds.hits().is_empty());

        // Hosts answer without asking anyone.
        assert_eq!(
            routed.route_resolving(&domain("router.lan", 80)).await,
            RouteOutcome::Node("hk-1".to_string())
        );
        assert!(outbounds.hits().is_empty());
    });
}

#[test]
fn an_unbound_resolver_rejects_instead_of_asking_the_system() {
    let resolver = PolicyResolver::new(Arc::new(DnsPolicy::from_config(&dns_config()).unwrap()));
    let result = runtime().block_on(resolver.resolve("www.blocked.example"));
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotConnected);
}

// Path 3: only bootstrap names go DIRECT.

#[test]
fn only_direct_servers_and_their_rule_names_go_direct() {
    let policy = DnsPolicy::from_config(&dns_config()).unwrap();
    // Only names a DNS rule picks reach the `direct` server.
    assert_eq!(policy.server_for("www.example.cn", None), 1);
    assert_eq!(policy.server_for("www.blocked.example", None), 0);
    assert_eq!(policy.server_for("cn.blocked.example", None), 0);

    let outbounds = Outbounds::new();
    let dispatcher = Dispatcher::routed(Arc::new(
        gfw_list(&outbounds).with_resolver(Arc::new(NoLookups)),
    ));
    runtime().block_on(async {
        // A proxied DoH server given by name goes to the node by name.
        connect_via(&dispatcher, DnsVia::Proxy, &domain("dns.google", 443)).await;
        assert_eq!(outbounds.hits(), [("hk-1", "dns.google:443".to_string())]);
        // A direct server's own name is the one name resolved locally.
        connect_via(&dispatcher, DnsVia::Direct, &domain("dns.alidns.com", 443)).await;
        assert_eq!(
            outbounds.hits(),
            [("direct", "dns.alidns.com:443".to_string())]
        );
    });
}
