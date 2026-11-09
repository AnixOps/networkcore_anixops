//! `redirects`: matching flows go to another destination before routing.

use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use config_core::redirect::RedirectTable;
use config_core::routing::RoutingSpec;
use engine_embedded::connections::{Dispatcher, Mode};
use engine_embedded::routing::RoutedOutbound;
use engine_embedded::EmbeddedRuntime;
use engine_outbound::{
    BoxFuture, BoxStream, DatagramRecv, DatagramSend, TargetAddr, TcpOutbound, UdpFlow,
};

/// Accepts every TCP connection and UDP flow, recording where it went.
#[derive(Default)]
struct Record {
    name: &'static str,
    seen: Mutex<Vec<String>>,
}

impl Record {
    fn named(name: &'static str) -> Arc<Self> {
        Arc::new(Self {
            name,
            seen: Mutex::default(),
        })
    }

    fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

struct Nothing;

impl DatagramSend for Nothing {
    fn send<'a>(&'a mut self, _payload: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl DatagramRecv for Nothing {
    fn recv(&mut self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        Box::pin(std::future::pending())
    }
}

impl TcpOutbound for Record {
    fn protocol(&self) -> &'static str {
        self.name
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            self.seen.lock().unwrap().push(format!("tcp {target}"));
            let (client, _server) = tokio::io::duplex(64);
            Ok(Box::new(client) as BoxStream)
        })
    }

    fn open_udp<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(async move {
            self.seen.lock().unwrap().push(format!("udp {target}"));
            Ok(UdpFlow::new(Box::new(Nothing), Box::new(Nothing)))
        })
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn ip(addr: &str) -> TargetAddr {
    TargetAddr::Ip(addr.parse::<SocketAddr>().unwrap())
}

fn table(lines: &[&str]) -> RedirectTable {
    RedirectTable::parse(lines).unwrap()
}

#[test]
fn tcp_and_udp_flows_go_to_the_new_destination() {
    runtime().block_on(async {
        let out = Record::named("test-record");
        let dispatcher = Dispatcher::single(out.clone()).with_redirects(table(&[
            "AND,((IP-CIDR,203.0.113.10/32),(PROTOCOL,UDP)),10.8.0.5:7777",
            "IP-CIDR,203.0.113.10/32,10.8.0.5",
            "DOMAIN-SUFFIX,game.example.com,dev.example.com:9000",
            "DST-PORT,8000,:18000",
        ]));

        let _a = dispatcher
            .connect_flow(&ip("203.0.113.10:443"), None)
            .await
            .unwrap();
        let _b = dispatcher
            .open_udp_flow(&ip("203.0.113.10:7000"), None)
            .await
            .unwrap();
        // The sniffed host selects the line; the new destination is a name.
        let _c = dispatcher
            .connect_flow(&ip("198.51.100.7:443"), Some("login.game.example.com"))
            .await
            .unwrap();
        let _d = dispatcher
            .connect_flow(
                &TargetAddr::Domain("api.example.org".to_string(), 8000),
                None,
            )
            .await
            .unwrap();
        let _e = dispatcher
            .connect_flow(&ip("198.51.100.8:443"), None)
            .await
            .unwrap();

        assert_eq!(
            out.seen(),
            [
                "tcp 10.8.0.5:443",
                "udp 10.8.0.5:7777",
                "tcp dev.example.com:9000",
                "tcp api.example.org:18000",
                "tcp 198.51.100.8:443",
            ]
        );

        // The list keeps the requested destination and shows the rewrite.
        let list = dispatcher.tracker().connections();
        let first = &list.active[0];
        assert_eq!(first.destination, "203.0.113.10:443");
        let redirect = first.redirect.as_ref().unwrap();
        assert_eq!(redirect.destination, "10.8.0.5:443");
        assert_eq!(redirect.rule, "IP-CIDR,203.0.113.10/32,10.8.0.5");
        assert!(list.active[4].redirect.is_none());
        let json = serde_json::to_value(&list).unwrap();
        assert_eq!(
            json["active"][1]["redirect"]["destination"],
            "10.8.0.5:7777"
        );
        assert!(json["active"][4].get("redirect").is_none());
    });
}

#[test]
fn routing_sees_the_new_destination_in_every_mode() {
    runtime().block_on(async {
        let lan = Record::named("test-lan");
        let direct = Record::named("test-direct");
        let nodes = BTreeMap::from([(
            "office-vpn".to_string(),
            lan.clone() as Arc<dyn TcpOutbound>,
        )]);
        let spec = RoutingSpec {
            rules: vec![
                // Would catch the original flow by its sniffed host.
                "DOMAIN-SUFFIX,game.example.com,REJECT".to_string(),
                "IP-CIDR,10.8.0.0/16,office-vpn".to_string(),
                "FINAL,DIRECT".to_string(),
            ],
            groups: Vec::new(),
        };
        let routed = RoutedOutbound::new(&spec, direct.clone(), nodes).unwrap();
        let dispatcher = Dispatcher::routed(Arc::new(routed))
            .with_redirects(table(&["DOMAIN-SUFFIX,game.example.com,10.8.0.5"]));

        let _flow = dispatcher
            .connect_flow(&ip("198.51.100.7:443"), Some("login.game.example.com"))
            .await
            .unwrap();
        assert_eq!(lan.seen(), ["tcp 10.8.0.5:443"]);
        let list = dispatcher.tracker().connections();
        assert_eq!(list.active[0].rule, "IP-CIDR,10.8.0.0/16");
        assert_eq!(list.active[0].outbound, "office-vpn");
        assert_eq!(
            list.active[0].host.as_deref(),
            Some("login.game.example.com")
        );

        dispatcher.set_mode(Mode::Direct);
        let _flow = dispatcher
            .open_udp_flow(&ip("198.51.100.7:7000"), Some("login.game.example.com"))
            .await
            .unwrap();
        assert_eq!(direct.seen(), ["udp 10.8.0.5:7000"]);
    });
}

#[test]
fn the_config_carries_redirects_and_rejects_bad_ones() {
    let config = |redirects: &str| {
        format!(
            r#"{{"schema_version":1,"profile_id":"p","redirects":{redirects},"outbound":{{"type":"direct"}}}}"#
        )
    };
    assert!(EmbeddedRuntime::from_json(
        config(r#"["IP-CIDR,203.0.113.10/32,10.8.0.5:7000","DST-PORT,8000,:18000"]"#).as_bytes()
    )
    .is_ok());
    assert!(EmbeddedRuntime::from_json(config("[]").as_bytes()).is_ok());
    for bad in [
        r#"["IP-CIDR,203.0.113.10/32"]"#,
        r#"["IP-CIDR,203.0.113.10/32,10.8.0.5:0"]"#,
        r#"["GEOIP,CN,10.8.0.5"]"#,
        r#"["FINAL,10.8.0.5"]"#,
    ] {
        let error = EmbeddedRuntime::from_json(config(bad).as_bytes()).err();
        assert!(error.is_some(), "{bad} was accepted");
    }
}
