//! Client multiplexing (`multiplex` on an outbound,
//! docs/architecture/outbound-multiplex.md): the config checks, and a
//! Shadowsocks-2022 node whose connections run as streams of one pooled
//! connection to an in-process server.

#![cfg(feature = "shadowsocks")]

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use engine_embedded::config::RuntimeConfig;
use engine_embedded::protocols::default_registry;
use engine_embedded::routing::RoutedOutbound;
use engine_inbound::server::{serve, InboundStats, ServeSettings};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpDialer, TcpOutbound};
use inbound_shadowsocks::{Method, Ss2022Inbound};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(10);

fn envelope(outbounds: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema_version": 1,
        "profile_id": "mux",
        "routing": {"outbounds": outbounds, "rules": ["FINAL,a"]},
    }))
    .unwrap()
}

fn build_routed(bytes: &[u8]) -> Result<Arc<RoutedOutbound>, &'static str> {
    let config = RuntimeConfig::from_json(bytes).map_err(|error| error.message)?;
    config
        .build_routed(&default_registry(), Arc::new(TcpDialer))
        .map(|routed| routed.expect("a routing config"))
        .map_err(|error| error.message)
}

fn key() -> String {
    base64::engine::general_purpose::STANDARD.encode([7u8; 16])
}

fn ss(port: u16, multiplex: serde_json::Value) -> serde_json::Value {
    json!({
        "type": "shadowsocks",
        "server": "127.0.0.1",
        "port": port,
        "method": "2022-blake3-aes-128-gcm",
        "password": key(),
        "multiplex": multiplex,
    })
}

fn rejection(outbound: serde_json::Value) -> &'static str {
    match build_routed(&envelope(json!({ "a": outbound }))) {
        Ok(_) => panic!("the config should be rejected"),
        Err(message) => message,
    }
}

#[test]
fn multiplex_settings_are_checked() {
    assert!(build_routed(&envelope(json!({"a": ss(1, json!({}))}))).is_ok());
    assert!(build_routed(&envelope(json!({"a": ss(1, json!({"enabled": false}))}))).is_ok());
    let message = rejection(ss(1, json!({"protocol": "quic"})));
    assert!(message.contains("protocol"), "{message}");
    let message = rejection(ss(1, json!({"max_streams": 4, "min_streams": 2})));
    assert!(message.contains("max_streams"), "{message}");
    let message = rejection(json!({"type": "direct", "multiplex": {}}));
    assert!(message.contains("multiplex works with"), "{message}");
}

struct Direct;

impl TcpOutbound for Direct {
    fn protocol(&self) -> &'static str {
        "direct"
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let stream = TcpStream::connect((target.host(), target.port())).await?;
            Ok(Box::new(stream) as BoxStream)
        })
    }
}

async fn tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    address
}

/// A Shadowsocks-2022 server; its serve loop takes sing-mux connections.
async fn start_server() -> (u16, Arc<InboundStats>) {
    let inbound = Arc::new(Ss2022Inbound::new(Method::Aes128Gcm, &key(), false).unwrap());
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let stats = Arc::new(InboundStats::default());
    tokio::spawn(serve(
        listener,
        inbound,
        Arc::new(Direct),
        ServeSettings::default(),
        stats.clone(),
    ));
    (port, stats)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shadowsocks_connections_share_one_multiplexed_connection() {
    let echo = tcp_echo().await;
    let (port, _stats) = start_server().await;
    let routed = build_routed(&envelope(json!({
        "a": ss(port, json!({"enabled": true, "protocol": "h2mux", "max_connections": 1})),
    })))
    .unwrap();

    for i in 0..20u32 {
        let mut stream = timeout(WAIT, routed.connect(&TargetAddr::Ip(echo)))
            .await
            .expect("connect timed out")
            .expect("connect over the multiplexed connection");
        let payload = format!("stream {i}");
        stream.write_all(payload.as_bytes()).await.unwrap();
        let mut echoed = vec![0u8; payload.len()];
        timeout(WAIT, stream.read_exact(&mut echoed))
            .await
            .expect("echo timed out")
            .unwrap();
        assert_eq!(echoed, payload.as_bytes());
    }

    let reuse = routed.node_reuse_stats();
    assert_eq!(reuse.len(), 1, "{reuse:?}");
    let (node, protocol, stats_json) = &reuse[0];
    assert_eq!((node.as_str(), *protocol), ("a", "shadowsocks-2022"));
    assert_eq!(stats_json["mux"]["sessions_opened"], 1);
    assert_eq!(stats_json["mux"]["streams_opened"], 20);
    assert!(stats_json["mux"]["reuse_rate"].as_f64().unwrap() >= 0.9);
}
