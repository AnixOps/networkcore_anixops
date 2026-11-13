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

/// Reports health and can be resumed, like an outbound that stops after its
/// credentials keep being rejected.
struct Stopped(std::sync::atomic::AtomicBool);

impl TcpOutbound for Stopped {
    fn protocol(&self) -> &'static str {
        "test-health"
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async { Err(io::ErrorKind::PermissionDenied.into()) })
    }

    fn health(&self) -> Option<serde_json::Value> {
        let stopped = self.0.load(std::sync::atomic::Ordering::SeqCst);
        Some(serde_json::json!({ "stopped": stopped, "counts": { "fallback": 3 } }))
    }

    fn resume(&self) -> bool {
        self.0.swap(false, std::sync::atomic::Ordering::SeqCst)
    }
}

#[test]
fn outbound_health_lists_reporting_nodes_and_resumes() {
    let nodes = BTreeMap::from([
        (
            "hk-1".to_string(),
            Arc::new(Echo("test-node")) as Arc<dyn TcpOutbound>,
        ),
        (
            "jp-anx".to_string(),
            Arc::new(Stopped(std::sync::atomic::AtomicBool::new(true))) as Arc<dyn TcpOutbound>,
        ),
    ]);
    let spec = RoutingSpec {
        rules: vec!["FINAL,DIRECT".to_string()],
        groups: Vec::new(),
    };
    let routed = RoutedOutbound::new(&spec, Arc::new(Echo("direct")), nodes).unwrap();
    let dispatcher = Dispatcher::routed(Arc::new(routed));

    let health = control_json(&dispatcher, r#"{"cmd":"outbound_health"}"#);
    let outbounds = health["outbounds"].as_array().unwrap();
    assert_eq!(
        outbounds.len(),
        1,
        "only nodes that report health: {health}"
    );
    assert_eq!(outbounds[0]["node"], "jp-anx");
    assert_eq!(outbounds[0]["protocol"], "test-health");
    assert_eq!(outbounds[0]["health"]["stopped"], true);

    let resumed = control_json(&dispatcher, r#"{"cmd":"resume_outbound","node":"jp-anx"}"#);
    assert_eq!(resumed["resumed"], true);
    let resumed = control_json(&dispatcher, r#"{"cmd":"resume_outbound","node":"jp-anx"}"#);
    assert_eq!(resumed["resumed"], false);
    let health = control_json(&dispatcher, r#"{"cmd":"outbound_health"}"#);
    assert_eq!(health["outbounds"][0]["health"]["stopped"], false);
    // Nodes without health resume to false; unknown nodes are an error.
    let resumed = control_json(&dispatcher, r#"{"cmd":"resume_outbound","node":"hk-1"}"#);
    assert_eq!(resumed["resumed"], false);
    assert!(control::handle(&dispatcher, br#"{"cmd":"resume_outbound","node":"nope"}"#).is_err());

    // A config with one outbound reports it as `proxy`.
    let single = Dispatcher::single(Arc::new(Stopped(std::sync::atomic::AtomicBool::new(true))));
    let health = control_json(&single, r#"{"cmd":"outbound_health"}"#);
    assert_eq!(health["outbounds"][0]["node"], control::SINGLE_NODE);
    let resumed = control_json(&single, r#"{"cmd":"resume_outbound","node":"proxy"}"#);
    assert_eq!(resumed["resumed"], true);
    let echo = Dispatcher::single(Arc::new(Echo("plain")));
    let health = control_json(&echo, r#"{"cmd":"outbound_health"}"#);
    assert_eq!(health["outbounds"].as_array().unwrap().len(), 0);
}

/// Records the target of every connection and echoes nothing.
struct Recording(&'static str, Arc<std::sync::Mutex<Vec<TargetAddr>>>);

impl TcpOutbound for Recording {
    fn protocol(&self) -> &'static str {
        self.0
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        self.1.lock().unwrap().push(target.clone());
        Box::pin(async {
            let (client, _server) = tokio::io::duplex(64);
            Ok(Box::new(client) as BoxStream)
        })
    }
}

#[test]
fn ipv6_flows_reach_a_proxy_by_their_sniffed_name() {
    runtime().block_on(async {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let proxy = Dispatcher::single(Arc::new(Recording("test-proxy", seen.clone())));
        proxy
            .connect_flow(&ip("[2001:db8::1]:443"), Some("ipleak.example.test"))
            .await
            .unwrap();
        proxy
            .connect_flow(&ip("192.0.2.1:443"), Some("v4.example.test"))
            .await
            .unwrap();
        proxy
            .connect_flow(&ip("[2001:db8::2]:443"), None)
            .await
            .unwrap();
        let direct = Dispatcher::single(Arc::new(Recording("direct", seen.clone())));
        direct
            .connect_flow(&ip("[2001:db8::3]:443"), Some("direct.example.test"))
            .await
            .unwrap();

        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                TargetAddr::Domain("ipleak.example.test".to_string(), 443),
                ip("192.0.2.1:443"),
                ip("[2001:db8::2]:443"),
                ip("[2001:db8::3]:443"),
            ]
        );
    });
}

#[test]
fn metrics_answer_prometheus_text() {
    runtime().block_on(async {
        let dispatcher = grouped();
        let stream = dispatcher
            .connect_flow(&TargetAddr::Domain("www.example.test".to_string(), 443), None)
            .await
            .unwrap();
        drop(stream);

        let answer = control_json(&dispatcher, r#"{"cmd":"metrics"}"#);
        assert_eq!(answer["content_type"], engine_embedded::metrics::CONTENT_TYPE);
        let text = answer["text"].as_str().unwrap();
        for line in [
            "# TYPE networkcore_upload_bytes_total counter",
            "networkcore_mode{mode=\"rule\"} 1",
            "networkcore_mode{mode=\"direct\"} 0",
            "networkcore_connections_opened_total{network=\"tcp\"} 1",
            "networkcore_connections_closed_total{network=\"tcp\",result=\"ok\"} 1",
            "networkcore_connections_closed_total{network=\"udp\",result=\"ok\"} 0",
            "networkcore_connections_active{network=\"tcp\"} 0",
            "networkcore_policy_group_selected{group=\"Proxy\",type=\"select\",member=\"hk-1\"} 1",
        ] {
            assert!(text.lines().any(|l| l == line), "missing {line:?} in\n{text}");
        }
        // Every sample line is `name{labels} value` with a numeric value.
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let value = line.rsplit(' ').next().unwrap();
            assert!(value.parse::<f64>().is_ok(), "{line}");
        }
        assert!(!text.contains("example.test"));

        let anonymous = control_json(&dispatcher, r#"{"cmd":"metrics","anonymous":true}"#);
        let text = anonymous["text"].as_str().unwrap();
        assert!(text.contains(
            "networkcore_policy_group_selected{group=\"group_1\",type=\"select\",member=\"member_1\"} 1"
        ));
        for name in ["Proxy", "Auto", "hk-1", "jp-1"] {
            assert!(!text.contains(name), "{name} in\n{text}");
        }
    });
}

/// Echoes like [`Echo`] and counts how often its sessions were reset.
struct Pooled {
    echo: Echo,
    resets: std::sync::atomic::AtomicUsize,
}

impl Pooled {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            echo: Echo("test-pooled"),
            resets: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    fn resets(&self) -> usize {
        self.resets.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl TcpOutbound for Pooled {
    fn protocol(&self) -> &'static str {
        "test-pooled"
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        self.echo.connect(target)
    }

    fn reset_sessions(&self) -> usize {
        self.resets
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        1
    }
}

/// Twenty network changes in a row (sleep/wake, Wi-Fi to cellular) leave no
/// connection behind and reset the outbound's sessions every time.
#[test]
fn reset_network_twenty_times_leaks_nothing() {
    runtime().block_on(async {
        let pooled = Pooled::new();
        let dispatcher = Dispatcher::single(pooled.clone());
        for cycle in 1..=20 {
            let mut streams = Vec::new();
            for _ in 0..3 {
                let mut stream = dispatcher
                    .connect_flow(&ip("192.0.2.1:443"), None)
                    .await
                    .unwrap();
                stream.write_all(b"ping").await.unwrap();
                let mut reply = [0u8; 4];
                stream.read_exact(&mut reply).await.unwrap();
                streams.push(stream);
            }
            assert_eq!(dispatcher.tracker().connections().active.len(), 3);

            let answer = control_json(&dispatcher, r#"{"cmd":"reset_network"}"#);
            assert_eq!(answer["closed"], 3);
            assert_eq!(answer["reset"], 1);
            assert_eq!(pooled.resets(), cycle);

            // The closed flows fail at once instead of hanging on a dead path.
            for mut stream in streams {
                let mut buf = [0u8; 4];
                assert!(stream.read(&mut buf).await.map_or(true, |n| n == 0));
            }
            assert!(dispatcher.tracker().connections().active.is_empty());
            assert_eq!(dispatcher.tracker().connections().traffic.active, 0);
        }
        // The pooled outbound still dials after the last reset.
        let mut stream = dispatcher
            .connect_flow(&ip("192.0.2.1:443"), None)
            .await
            .unwrap();
        stream.write_all(b"ok").await.unwrap();
        let mut reply = [0u8; 2];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ok");
    });
}

#[test]
fn reset_network_can_keep_open_connections() {
    runtime().block_on(async {
        let pooled = Pooled::new();
        let dispatcher = Dispatcher::single(pooled.clone());
        let mut stream = dispatcher
            .connect_flow(&ip("192.0.2.1:443"), None)
            .await
            .unwrap();
        let answer = control_json(
            &dispatcher,
            r#"{"cmd":"reset_network","close_connections":false}"#,
        );
        assert_eq!(answer["closed"], 0);
        assert_eq!(answer["reset"], 1);
        stream.write_all(b"still").await.unwrap();
        let mut reply = [0u8; 5];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"still");
    });
}

#[test]
fn reset_network_reaches_every_routed_node_and_direct() {
    runtime().block_on(async {
        let hk = Pooled::new();
        let jp = Pooled::new();
        let direct = Pooled::new();
        let nodes = BTreeMap::from([
            ("hk-1".to_string(), hk.clone() as Arc<dyn TcpOutbound>),
            ("jp-1".to_string(), jp.clone() as Arc<dyn TcpOutbound>),
        ]);
        let spec = RoutingSpec {
            rules: vec![
                "DOMAIN-SUFFIX,example.test,hk-1".to_string(),
                "DOMAIN-SUFFIX,example.jp,jp-1".to_string(),
                "FINAL,DIRECT".to_string(),
            ],
            groups: Vec::new(),
        };
        let routed = RoutedOutbound::new(&spec, direct.clone(), nodes).unwrap();
        let dispatcher = Dispatcher::routed(Arc::new(routed));
        let answer = control_json(&dispatcher, r#"{"cmd":"reset_network"}"#);
        assert_eq!(answer["reset"], 3);
        assert_eq!((hk.resets(), jp.resets(), direct.resets()), (1, 1, 1));
    });
}

#[test]
fn rules_reload_in_place_without_dropping_open_connections() {
    runtime().block_on(async {
        let dispatcher = grouped();
        let answer = control_json(
            &dispatcher,
            r#"{"cmd":"select","group":"Proxy","member":"jp-1"}"#,
        );
        assert_eq!(answer["now"], "jp-1");

        // A connection opened under the first rules.
        let mut held = dispatcher
            .connect_flow(&TargetAddr::Domain("www.example.test".to_string(), 443), None)
            .await
            .unwrap();
        held.write_all(b"before").await.unwrap();
        let mut buf = [0u8; 6];
        held.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"before");

        // A dry run checks only.
        let checked = control_json(
            &dispatcher,
            r#"{"cmd":"reload_rules","dry_run":true,"rules":["DOMAIN-SUFFIX,example.test,DIRECT","FINAL,Proxy"]}"#,
        );
        assert_eq!(checked["reloaded"], false);
        assert_eq!(checked["generation"], 0);
        assert!(checked["error"].is_null());
        assert_eq!(
            route_of(&dispatcher, "www.example.test").await.1,
            ["Proxy", "jp-1"]
        );

        // Refused lists name their first bad line and change nothing.
        for (rules, line, code) in [
            (r#"["DOMAIN-SUFFIX,a.test,DIRECT","BOGUS,x,DIRECT","FINAL,DIRECT"]"#, Some(1), "syntax"),
            (r#"["DOMAIN-SUFFIX,a.test,Nowhere","FINAL,DIRECT"]"#, Some(0), "unknown_target"),
            (r#"["RULE-SET,missing,DIRECT","FINAL,DIRECT"]"#, Some(0), "unknown_rule_set"),
            (r#"["FINAL,DIRECT","DOMAIN,a.test,DIRECT"]"#, Some(1), "final_not_last"),
            (r#"["DOMAIN,a.test,DIRECT"]"#, None, "final_missing"),
        ] {
            let refused = control_json(
                &dispatcher,
                &format!(r#"{{"cmd":"reload_rules","rules":{rules}}}"#),
            );
            assert_eq!(refused["reloaded"], false, "{rules}");
            assert_eq!(refused["error"]["code"], code, "{rules}");
            match line {
                Some(line) => assert_eq!(refused["error"]["line"], line, "{rules}"),
                None => assert!(refused["error"]["line"].is_null(), "{rules}"),
            }
        }
        assert_eq!(
            route_of(&dispatcher, "www.example.test").await.1,
            ["Proxy", "jp-1"]
        );

        let reloaded = control_json(
            &dispatcher,
            r#"{"cmd":"reload_rules","rules":["DOMAIN-SUFFIX,example.test,DIRECT","DOMAIN,other.test,Proxy","FINAL,DIRECT"]}"#,
        );
        assert_eq!(reloaded["reloaded"], true);
        assert_eq!(reloaded["rules"], 3);
        assert_eq!(reloaded["generation"], 1);

        // New connections follow the new rules; the select choice stays.
        let (rule, chain) = route_of(&dispatcher, "www.example.test").await;
        assert_eq!(rule, "DOMAIN-SUFFIX,example.test");
        assert_eq!(chain, ["DIRECT"]);
        assert_eq!(
            route_of(&dispatcher, "other.test").await.1,
            ["Proxy", "jp-1"]
        );

        // The connection opened before the swap still carries data.
        held.write_all(b"after!").await.unwrap();
        held.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"after!");
        let active = dispatcher.tracker().connections().active;
        assert!(active.iter().any(|connection| connection.chain == ["Proxy", "jp-1"]));
    });
}

#[test]
fn only_reload_rules_may_exceed_the_short_request_limit() {
    runtime().block_on(async {
        let dispatcher = grouped();
        let mut rules: Vec<String> = (0..2000)
            .map(|index| format!("DOMAIN-SUFFIX,site-{index}.example,Proxy"))
            .collect();
        rules.push("FINAL,DIRECT".to_string());
        let request = serde_json::json!({ "cmd": "reload_rules", "rules": rules }).to_string();
        assert!(request.len() > control::MAX_REQUEST_LEN);
        let answer = control_json(&dispatcher, &request);
        assert_eq!(answer["reloaded"], true);
        assert_eq!(answer["rules"], 2001);
        assert_eq!(
            route_of(&dispatcher, "www.site-1999.example").await.1,
            ["Proxy", "hk-1"]
        );

        let too_long = "x".repeat(control::MAX_RELOAD_REQUEST_LEN);
        let request = format!(r#"{{"cmd":"reload_rules","rules":["{too_long}"]}}"#);
        assert!(control::handle(&dispatcher, request.as_bytes()).is_err());

        let single = Dispatcher::single(Arc::new(Echo("test-echo")));
        assert!(control::handle(
            &single,
            br#"{"cmd":"reload_rules","rules":["FINAL,DIRECT"]}"#
        )
        .is_err());
    });
}

#[test]
fn block_quic_refuses_udp_443_in_every_mode_and_switches_at_runtime() {
    runtime().block_on(async {
        let dispatcher = routed();
        let udp_kind = |target: &'static str| {
            let dispatcher = &dispatcher;
            async move {
                dispatcher
                    .open_udp_flow(&ip(target), None)
                    .await
                    .err()
                    .map(|err| err.kind())
            }
        };
        // Off by default: UDP 443 goes to its outbound (which has no UDP here).
        assert_eq!(
            control_json(&dispatcher, r#"{"cmd":"block_quic"}"#)["block_quic"],
            false
        );
        assert_ne!(
            udp_kind("192.0.2.1:443").await,
            Some(io::ErrorKind::PermissionDenied)
        );

        let answer = control_json(&dispatcher, r#"{"cmd":"set_block_quic","enabled":true}"#);
        assert_eq!(answer["block_quic"], true);
        assert!(dispatcher.block_quic());
        assert_eq!(
            udp_kind("192.0.2.1:443").await,
            Some(io::ErrorKind::PermissionDenied)
        );
        // Other UDP ports are untouched.
        assert_ne!(
            udp_kind("192.0.2.1:53").await,
            Some(io::ErrorKind::PermissionDenied)
        );
        // TCP 443 is untouched.
        assert!(dispatcher
            .connect_flow(&ip("192.0.2.2:443"), None)
            .await
            .is_ok());
        // The direct mode blocks too.
        dispatcher.set_mode(Mode::Direct);
        assert_eq!(
            udp_kind("[2001:db8::1]:443").await,
            Some(io::ErrorKind::PermissionDenied)
        );

        let list = dispatcher.tracker().connections();
        let blocked: Vec<_> = list
            .closed
            .iter()
            .filter(|c| c.error == Some("quic_blocked"))
            .collect();
        assert_eq!(blocked.len(), 2);
        for c in blocked {
            assert_eq!(c.network, Network::Udp);
            assert_eq!(c.rule, "BLOCK-QUIC");
            assert_eq!(c.outbound, "REJECT");
        }

        control_json(&dispatcher, r#"{"cmd":"set_block_quic","enabled":false}"#);
        assert!(!dispatcher.block_quic());
        assert_ne!(
            udp_kind("192.0.2.1:443").await,
            Some(io::ErrorKind::PermissionDenied)
        );
        assert!(control::handle(&dispatcher, br#"{"cmd":"set_block_quic"}"#).is_err());
    });
}

#[test]
fn block_quic_starts_from_the_config() {
    let config = |extra: &str| {
        format!(r#"{{"schema_version":1,"profile_id":"p",{extra}"outbound":{{"type":"direct"}}}}"#)
    };
    let ask = |runtime: &EmbeddedRuntime| -> serde_json::Value {
        serde_json::from_slice(&runtime.control_json(br#"{"cmd":"block_quic"}"#).unwrap()).unwrap()
    };
    let off =
        EmbeddedRuntime::from_json(config("").as_bytes()).unwrap_or_else(|err| panic!("{err}"));
    assert_eq!(ask(&off)["block_quic"], false);
    let on = EmbeddedRuntime::from_json(config(r#""block_quic":true,"#).as_bytes())
        .unwrap_or_else(|err| panic!("{err}"));
    assert_eq!(ask(&on)["block_quic"], true);
    let routed = EmbeddedRuntime::from_json(
        br#"{"schema_version":1,"profile_id":"p","block_quic":true,"routing":{"outbounds":{"hk-1":{"type":"direct"}},"rules":["FINAL,hk-1"]}}"#,
    )
    .unwrap_or_else(|err| panic!("{err}"));
    assert_eq!(ask(&routed)["block_quic"], true);
    assert!(EmbeddedRuntime::from_json(config(r#""block_quic":"yes","#).as_bytes()).is_err());
}
