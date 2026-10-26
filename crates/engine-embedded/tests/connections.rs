//! Connection list and traffic counters of the dispatcher every flow uses.

use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use config_core::routing::RoutingSpec;
use engine_embedded::connections::{Dispatcher, Network, MAX_CLOSED_CONNECTIONS};
use engine_embedded::control;
use engine_embedded::routing::RoutedOutbound;
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
