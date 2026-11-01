//! Connection list, traffic counters, modes and policy group switching of
//! the dispatcher every flow uses.

use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use config_core::routing::{PolicyGroupSpec, RoutingSpec};
use engine_embedded::connections::{
    Dispatcher, Mode, Network, LARGE_CONNECTION_BYTES, MAX_CLOSED_CONNECTIONS,
    MAX_KEPT_LARGE_CONNECTIONS,
};
use engine_embedded::routing::RoutedOutbound;
use engine_embedded::{control, EmbeddedRuntime};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Echoes every connection in memory.
struct Echo(&'static str);

impl TcpOutbound for Echo {
    fn protocol(&self) -> &'static str {
        self.0
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
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

/// Refuses every connection.
struct Refuse;

impl TcpOutbound for Refuse {
    fn protocol(&self) -> &'static str {
        "test-refuse"
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async { Err(io::ErrorKind::ConnectionRefused.into()) })
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

fn routed() -> Dispatcher {
    let nodes = BTreeMap::from([(
        "hk-1".to_string(),
        Arc::new(Echo("test-node")) as Arc<dyn TcpOutbound>,
    )]);
    let spec = RoutingSpec {
        rules: vec![
            "DOMAIN-SUFFIX,blocked.test,REJECT".to_string(),
            "DOMAIN-SUFFIX,example.test,hk-1".to_string(),
            "FINAL,DIRECT".to_string(),
        ],
        groups: Vec::new(),
    };
    let routed = RoutedOutbound::new(&spec, Arc::new(Echo("direct")), nodes).unwrap();
    Dispatcher::routed(Arc::new(routed))
}

fn control_json(dispatcher: &Dispatcher, request: &str) -> serde_json::Value {
    serde_json::from_slice(&control::handle(dispatcher, request.as_bytes()).unwrap()).unwrap()
}

#[test]
fn connections_count_bytes_and_move_to_closed() {
    runtime().block_on(async {
        let dispatcher = Dispatcher::single(Arc::new(Echo("test-echo")));
        let mut stream = dispatcher
            .connect_flow(&ip("192.0.2.1:443"), Some("www.example.test"))
            .await
            .unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut reply = [0u8; 5];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"hello");

        let list = dispatcher.tracker().connections();
        assert_eq!(list.active.len(), 1);
        let active = &list.active[0];
        assert_eq!(active.network, Network::Tcp);
        assert_eq!(active.host.as_deref(), Some("www.example.test"));
        assert_eq!(active.destination, "192.0.2.1:443");
        assert_eq!(active.rule, "DEFAULT");
        assert_eq!(active.outbound, "test-echo");
        assert_eq!((active.upload, active.download), (5, 5));
        assert!(active.started_at_ms > 0);
        assert_eq!(active.ended_at_ms, None);
        assert_eq!(list.traffic.upload_total, 5);
        assert_eq!(list.traffic.download_total, 5);
        assert_eq!(list.traffic.active, 1);

        drop(stream);
        let list = dispatcher.tracker().connections();
        assert!(list.active.is_empty());
        assert_eq!(list.closed.len(), 1);
        assert!(list.closed[0].ended_at_ms.is_some());
        assert_eq!(list.closed[0].error, None);
    });
}

#[test]
fn sniffed_hosts_match_domain_rules_and_rejects_are_listed() {
    runtime().block_on(async {
        let dispatcher = routed();
        let proxied = dispatcher
            .connect_flow(&ip("192.0.2.1:443"), Some("api.example.test"))
            .await
            .unwrap();
        let direct = dispatcher
            .connect_flow(&ip("192.0.2.2:443"), None)
            .await
            .unwrap();
        let rejected = dispatcher
            .connect_flow(
                &TargetAddr::Domain("ads.blocked.test".to_string(), 80),
                None,
            )
            .await;
        assert_eq!(
            rejected.err().map(|err| err.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );

        let list = dispatcher.tracker().connections();
        assert_eq!(list.active.len(), 2);
        assert_eq!(list.active[0].rule, "DOMAIN-SUFFIX,example.test");
        assert_eq!(list.active[0].chain, ["hk-1"]);
        assert_eq!(list.active[0].outbound, "hk-1");
        assert_eq!(list.active[1].rule, "FINAL");
        assert_eq!(list.active[1].outbound, "DIRECT");
        assert_eq!(list.closed.len(), 1);
        assert_eq!(list.closed[0].host.as_deref(), Some("ads.blocked.test"));
        assert_eq!(list.closed[0].destination, "ads.blocked.test:80");
        assert_eq!(list.closed[0].outbound, "REJECT");
        assert_eq!(list.closed[0].error, Some("rejected"));
        drop((proxied, direct));
    });
}

#[test]
fn failed_connects_are_listed_as_failed() {
    runtime().block_on(async {
        let dispatcher = Dispatcher::single(Arc::new(Refuse));
        assert!(dispatcher
            .connect_flow(&ip("192.0.2.1:443"), None)
            .await
            .is_err());
        let list = dispatcher.tracker().connections();
        assert!(list.active.is_empty());
        assert_eq!(list.closed[0].error, Some("connect_failed"));
    });
}

#[test]
fn closing_from_the_list_ends_the_stream() {
    runtime().block_on(async {
        let dispatcher = Dispatcher::single(Arc::new(Echo("test-echo")));
        let mut first = dispatcher
            .connect_flow(&ip("192.0.2.1:443"), None)
            .await
            .unwrap();
        let mut second = dispatcher
            .connect_flow(&ip("192.0.2.2:443"), None)
            .await
            .unwrap();
        let ids: Vec<u64> = dispatcher
            .tracker()
            .connections()
            .active
            .iter()
            .map(|connection| connection.id)
            .collect();
        assert_eq!(ids.len(), 2);

        // A pending read wakes up when the connection is closed.
        let tracker = dispatcher.tracker().clone();
        let first_id = ids[0];
        let closer = tokio::spawn(async move {
            tokio::task::yield_now().await;
            assert!(tracker.close(first_id));
        });
        let mut buf = [0u8; 8];
        let read = first.read(&mut buf).await;
        assert_eq!(
            read.err().map(|err| err.kind()),
            Some(io::ErrorKind::ConnectionAborted)
        );
        closer.await.unwrap();
        drop(first);
        assert!(!dispatcher.tracker().close(first_id));

        let answer = control_json(&dispatcher, r#"{"cmd":"close_all"}"#);
        assert_eq!(answer["closed"], 1);
        assert!(second.write_all(b"late").await.is_err());
        drop(second);
        assert!(dispatcher.tracker().connections().active.is_empty());
    });
}

#[test]
fn the_closed_list_keeps_the_newest() {
    runtime().block_on(async {
        let dispatcher = Dispatcher::single(Arc::new(Refuse));
        for _ in 0..MAX_CLOSED_CONNECTIONS + 5 {
            let _ = dispatcher.connect_flow(&ip("192.0.2.1:443"), None).await;
        }
        let closed = dispatcher.tracker().connections().closed;
        assert_eq!(closed.len(), MAX_CLOSED_CONNECTIONS);
        assert!(closed[0].id > closed[1].id);
    });
}

#[test]
fn control_requests_answer_json() {
    runtime().block_on(async {
        let dispatcher = Dispatcher::single(Arc::new(Echo("test-echo")));
        let mut stream = dispatcher
            .connect_flow(&TargetAddr::Domain("example.test".to_string(), 443), None)
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();

        let traffic = control_json(&dispatcher, r#"{"cmd":"traffic"}"#);
        assert_eq!(traffic["upload_total"], 4);
        assert_eq!(traffic["active"], 1);
        for field in ["download_total", "upload_rate", "download_rate"] {
            assert!(traffic[field].is_u64(), "{field}");
        }

        let list = control_json(&dispatcher, r#"{"cmd":"connections"}"#);
        let connection = &list["active"][0];
        assert_eq!(connection["network"], "tcp");
        assert_eq!(connection["host"], "example.test");
        assert_eq!(connection["destination"], "example.test:443");
        assert_eq!(connection["chain"][0], "test-echo");
        assert!(connection["ended_at_ms"].is_null());
        assert!(connection["error"].is_null());
        assert!(list["closed"].as_array().unwrap().is_empty());

        let id = connection["id"].as_u64().unwrap();
        let closed = control_json(
            &dispatcher,
            &format!(r#"{{"cmd":"close_connection","id":{id}}}"#),
        );
        assert_eq!(closed["closed"], true);

        for bad in ["", "{}", "not json", r#"{"cmd":"reboot"}"#] {
            let err = control::handle(&dispatcher, bad.as_bytes()).unwrap_err();
            assert_eq!(err.code.as_str(), "invalid_argument", "{bad}");
        }
        let long = format!(
            r#"{{"cmd":"traffic","pad":"{}"}}"#,
            "x".repeat(control::MAX_REQUEST_LEN)
        );
        assert!(control::handle(&dispatcher, long.as_bytes()).is_err());
    });
}

fn grouped() -> Dispatcher {
    let nodes = BTreeMap::from([
        (
            "hk-1".to_string(),
            Arc::new(Echo("test-node")) as Arc<dyn TcpOutbound>,
        ),
        (
            "jp-1".to_string(),
            Arc::new(Echo("test-node")) as Arc<dyn TcpOutbound>,
        ),
    ]);
    let group = |id: &str, kind: &str| PolicyGroupSpec {
        id: id.to_string(),
        kind: kind.to_string(),
        members: vec!["hk-1".to_string(), "jp-1".to_string()],
        default: None,
        url: None,
        interval_secs: None,
        tolerance_ms: None,
    };
    let spec = RoutingSpec {
        rules: vec![
            "DOMAIN-SUFFIX,example.test,Proxy".to_string(),
            "FINAL,DIRECT".to_string(),
        ],
        groups: vec![group("Proxy", "select"), group("Auto", "url-test")],
    };
    let routed = RoutedOutbound::new(&spec, Arc::new(Echo("direct")), nodes).unwrap();
    Dispatcher::routed(Arc::new(routed))
}

async fn route_of(dispatcher: &Dispatcher, host: &str) -> (String, Vec<String>) {
    let stream = dispatcher
        .connect_flow(&TargetAddr::Domain(host.to_string(), 443), None)
        .await
        .unwrap();
    let list = dispatcher.tracker().connections();
    let connection = list.active.last().unwrap();
    let route = (connection.rule.clone(), connection.chain.clone());
    drop(stream);
    route
}

#[test]
fn select_groups_switch_without_a_restart() {
    runtime().block_on(async {
        let dispatcher = grouped();
        assert_eq!(
            route_of(&dispatcher, "www.example.test").await.1,
            ["Proxy", "hk-1"]
        );
        let answer = control_json(
            &dispatcher,
            r#"{"cmd":"select","group":"Proxy","member":"jp-1"}"#,
        );
        assert_eq!(answer["now"], "jp-1");
        assert_eq!(
            route_of(&dispatcher, "www.example.test").await.1,
            ["Proxy", "jp-1"]
        );

        let groups = control_json(&dispatcher, r#"{"cmd":"groups"}"#);
        let groups = groups["groups"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0]["id"], "Proxy");
        assert_eq!(groups[0]["type"], "select");
        assert_eq!(groups[0]["now"], "jp-1");
        assert_eq!(groups[0]["members"][0]["name"], "hk-1");
        assert!(groups[0]["members"][0]["latency_ms"].is_null());
        assert_eq!(groups[1]["type"], "url-test");
        assert_eq!(groups[1]["now"], "hk-1");

        for bad in [
            r#"{"cmd":"select","group":"Auto","member":"jp-1"}"#,
            r#"{"cmd":"select","group":"Missing","member":"jp-1"}"#,
            r#"{"cmd":"select","group":"Proxy","member":"us-1"}"#,
            r#"{"cmd":"select","group":"Proxy"}"#,
        ] {
            assert!(
                control::handle(&dispatcher, bad.as_bytes()).is_err(),
                "{bad}"
            );
        }
    });
}

#[test]
fn modes_override_the_rules() {
    runtime().block_on(async {
        let dispatcher = grouped();
        assert_eq!(
            control_json(&dispatcher, r#"{"cmd":"mode"}"#)["mode"],
            "rule"
        );
        assert_eq!(
            route_of(&dispatcher, "other.test").await,
            ("FINAL".to_string(), vec!["DIRECT".to_string()])
        );

        let answer = control_json(&dispatcher, r#"{"cmd":"set_mode","mode":"global"}"#);
        assert_eq!(answer["mode"], "global");
        assert_eq!(dispatcher.mode(), Mode::Global);
        // The global target defaults to the first group.
        assert_eq!(
            route_of(&dispatcher, "other.test").await,
            (
                "MODE,global".to_string(),
                vec!["Proxy".to_string(), "hk-1".to_string()]
            )
        );

        control_json(&dispatcher, r#"{"cmd":"set_mode","mode":"direct"}"#);
        assert_eq!(
            route_of(&dispatcher, "www.example.test").await,
            ("MODE,direct".to_string(), vec!["DIRECT".to_string()])
        );
        assert!(control::handle(&dispatcher, br#"{"cmd":"set_mode","mode":"fast"}"#).is_err());

        // A config with one outbound has no groups but switches modes.
        let single =
            Dispatcher::single(Arc::new(Echo("test-echo"))).with_direct(Arc::new(Echo("direct")));
        assert_eq!(
            control_json(&single, r#"{"cmd":"groups"}"#)["groups"],
            serde_json::json!([])
        );
        assert!(
            control::handle(&single, br#"{"cmd":"select","group":"Proxy","member":"x"}"#).is_err()
        );
        assert_eq!(route_of(&single, "a.test").await.0, "DEFAULT");
        single.set_mode(Mode::Global);
        assert_eq!(route_of(&single, "a.test").await.0, "DEFAULT");
        single.set_mode(Mode::Direct);
        assert_eq!(
            route_of(&single, "a.test").await,
            ("MODE,direct".to_string(), vec!["DIRECT".to_string()])
        );
    });
}

#[test]
fn the_global_target_and_start_mode_come_from_the_config() {
    let config = |extra: &str| {
        format!(
            r#"{{"schema_version":1,"profile_id":"p",{extra}"routing":{{"outbounds":{{"hk-1":{{"type":"direct"}},"jp-1":{{"type":"direct"}}}},"rules":["FINAL,Proxy"],"groups":[{{"id":"Proxy","type":"select","members":["hk-1","jp-1"]}}],"global":"jp-1"}}}}"#
        )
    };
    let runtime = EmbeddedRuntime::from_json(config(r#""mode":"global","#).as_bytes())
        .unwrap_or_else(|err| panic!("{err}"));
    let answer: serde_json::Value =
        serde_json::from_slice(&runtime.control_json(br#"{"cmd":"mode"}"#).unwrap()).unwrap();
    assert_eq!(answer["mode"], "global");

    assert!(EmbeddedRuntime::from_json(config(r#""mode":"fast","#).as_bytes()).is_err());
    let rejected = config("").replace(r#""global":"jp-1""#, r#""global":"REJECT""#);
    assert!(EmbeddedRuntime::from_json(rejected.as_bytes()).is_err());
    let unknown = config("").replace(r#""global":"jp-1""#, r#""global":"us-1""#);
    assert!(EmbeddedRuntime::from_json(unknown.as_bytes()).is_err());

    let single = EmbeddedRuntime::from_json(
        br#"{"schema_version":1,"profile_id":"p","mode":"direct","outbound":{"type":"direct"}}"#,
    )
    .unwrap_or_else(|err| panic!("{err}"));
    let answer: serde_json::Value =
        serde_json::from_slice(&single.control_json(br#"{"cmd":"mode"}"#).unwrap()).unwrap();
    assert_eq!(answer["mode"], "direct");
}

#[test]
fn global_routes_to_the_configured_target() {
    runtime().block_on(async {
        let nodes = BTreeMap::from([(
            "hk-1".to_string(),
            Arc::new(Echo("test-node")) as Arc<dyn TcpOutbound>,
        )]);
        let spec = RoutingSpec {
            rules: vec!["FINAL,DIRECT".to_string()],
            groups: Vec::new(),
        };
        let routed = RoutedOutbound::new(&spec, Arc::new(Echo("direct")), nodes).unwrap();
        let dispatcher = Dispatcher::routed(Arc::new(routed));
        dispatcher.set_mode(Mode::Global);
        // Without groups the global target is the first node.
        assert_eq!(
            route_of(&dispatcher, "a.test").await.1,
            ["hk-1".to_string()]
        );
    });
}

/// Accepts and discards everything written, reads nothing.
struct Sink;

impl TcpOutbound for Sink {
    fn protocol(&self) -> &'static str {
        "test-sink"
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async {
            let (client, mut server) = tokio::io::duplex(64 * 1024);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                while let Ok(n) = server.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                }
            });
            Ok(Box::new(client) as BoxStream)
        })
    }
}

#[test]
fn large_closed_connections_outlive_small_ones() {
    runtime().block_on(async {
        let sink = Dispatcher::single(Arc::new(Sink));
        let payload = vec![0u8; LARGE_CONNECTION_BYTES as usize];
        let mut large_ids = Vec::new();
        for _ in 0..3 {
            let mut stream = sink
                .connect_flow(&ip("192.0.2.9:8080"), Some("speedtest.example.test"))
                .await
                .unwrap();
            stream.write_all(&payload).await.unwrap();
            drop(stream);
            large_ids.push(sink.tracker().connections().closed[0].id);
        }
        // A burst of small connections afterwards, more than the list holds.
        for _ in 0..MAX_CLOSED_CONNECTIONS * 2 {
            let mut stream = sink.connect_flow(&ip("192.0.2.1:443"), None).await.unwrap();
            stream.write_all(b"ping").await.unwrap();
        }
        let closed = sink.tracker().connections().closed;
        assert_eq!(closed.len(), MAX_CLOSED_CONNECTIONS);
        for id in &large_ids {
            let kept = closed
                .iter()
                .find(|c| c.id == *id)
                .expect("large connection kept");
            assert_eq!(kept.upload, LARGE_CONNECTION_BYTES);
        }
        // Still newest first, and the newest small connection is listed.
        assert!(closed.windows(2).all(|pair| pair[0].id > pair[1].id));
        assert!(closed[0].upload < LARGE_CONNECTION_BYTES);
    });
}

#[test]
fn kept_large_connections_are_capped() {
    runtime().block_on(async {
        let sink = Dispatcher::single(Arc::new(Sink));
        let payload = vec![0u8; LARGE_CONNECTION_BYTES as usize];
        for _ in 0..MAX_CLOSED_CONNECTIONS + 10 {
            let mut stream = sink
                .connect_flow(&ip("192.0.2.9:8080"), None)
                .await
                .unwrap();
            stream.write_all(&payload).await.unwrap();
        }
        for _ in 0..MAX_CLOSED_CONNECTIONS {
            let _ = sink.connect_flow(&ip("192.0.2.1:443"), None).await.unwrap();
        }
        let closed = sink.tracker().connections().closed;
        assert_eq!(closed.len(), MAX_CLOSED_CONNECTIONS);
        let large = closed
            .iter()
            .filter(|c| c.upload >= LARGE_CONNECTION_BYTES)
            .count();
        assert_eq!(large, MAX_KEPT_LARGE_CONNECTIONS);
    });
}
