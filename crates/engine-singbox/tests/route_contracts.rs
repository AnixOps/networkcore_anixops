use config_core::parse_config_document;
use config_core::routing::{RoutingModel, RoutingSpec};
use config_core::routing_import::import_subscription_routing;
use config_core::CoreSubscriptionService;
use control_domain::{RawSubscription, SubscriptionService};
use engine_singbox::{
    render_sing_box_local_proxy_routing_config, render_sing_box_route,
    SingBoxLocalProxyConfigRequest, ENGINE_SINGBOX_CONFIG_NODE_UNSUPPORTED_CODE,
    SING_BOX_DIRECT_OUTBOUND_TAG,
};
use serde_json::{json, Value};
use std::collections::BTreeSet;

const SNAPSHOT_CONFIG: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/routing-snapshot/config.toml"
));
const SNAPSHOT_SING_BOX_ROUTE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/routing-snapshot/sing-box-route.json"
));

#[test]
fn routing_snapshot_renders_sing_box_route() {
    let model = parse_config_document(SNAPSHOT_CONFIG)
        .unwrap()
        .routing
        .expect("snapshot config defines routing");
    let expected = serde_json::from_str::<Value>(SNAPSHOT_SING_BOX_ROUTE).unwrap();

    assert_eq!(render_sing_box_route(&model).to_value(), expected);
}

#[test]
fn final_reject_renders_catch_all_reject_rule() {
    let model = RoutingModel::from_spec(
        &RoutingSpec {
            rules: vec![
                "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve".to_string(),
                "FINAL,REJECT".to_string(),
            ],
            groups: Vec::new(),
        },
        &BTreeSet::new(),
    )
    .unwrap();

    let fragment = render_sing_box_route(&model);

    assert!(fragment.outbounds.is_empty());
    assert_eq!(
        fragment.route,
        json!({
            "rules": [
                { "ip_cidr": ["10.0.0.0/8"], "action": "route", "outbound": "direct" },
                { "action": "reject" }
            ],
            "final": SING_BOX_DIRECT_OUTBOUND_TAG
        })
    );
}

const SURGE_ROUTED_PROFILE: &str = r#"
[Proxy]
HK = ss, 82.47.34.99, 11111, encrypt-method=aes-256-gcm, password=f43c0eee-13b9-4f07-bec9-d4b744141503
JP = ss, 82.47.34.100, 11112, encrypt-method=aes-256-gcm, password=f43c0eee-13b9-4f07-bec9-d4b744141504
Spare = ss, 82.47.34.101, 11113, encrypt-method=aes-256-gcm, password=f43c0eee-13b9-4f07-bec9-d4b744141505

[Proxy Group]
Proxy = select, Auto, HK, DIRECT
Auto = url-test, HK, JP

[Rule]
DOMAIN-SUFFIX,google.com,Proxy
GEOIP,CN,DIRECT
FINAL,Proxy
"#;

#[test]
fn local_proxy_routing_config_renders_referenced_nodes_groups_and_route() {
    let service = CoreSubscriptionService::new();
    let document = service
        .parse(&RawSubscription {
            source_id: "routed".to_string(),
            content: SURGE_ROUTED_PROFILE.to_string(),
        })
        .unwrap();
    let nodes = service.normalize(&document).unwrap().nodes;
    let model = import_subscription_routing(SURGE_ROUTED_PROFILE, &nodes)
        .routing
        .expect("surge routing should import");
    let id_of = |name: &str| {
        nodes
            .iter()
            .find(|node| node.name == name)
            .unwrap()
            .id
            .clone()
    };
    let (hk, jp) = (id_of("HK"), id_of("JP"));

    let config = render_sing_box_local_proxy_routing_config(
        &SingBoxLocalProxyConfigRequest {
            nodes: nodes.clone(),
            selected_node_id: None,
            listen_host: "127.0.0.1".to_string(),
            listen_port: 7890,
        },
        &model,
    )
    .unwrap();
    let rendered = serde_json::from_str::<Value>(&config.json).unwrap();
    let fragment = render_sing_box_route(&model);

    assert_eq!(rendered["route"], fragment.route);
    let tags = rendered["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|outbound| outbound["tag"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        tags,
        vec![
            "Proxy".to_string(),
            "Auto".to_string(),
            hk.clone(),
            jp.clone(),
            SING_BOX_DIRECT_OUTBOUND_TAG.to_string(),
        ]
    );
    assert_eq!(rendered["outbounds"][2]["type"], "shadowsocks");
    assert_eq!(rendered["inbounds"][0]["listen_port"], 7890);
    assert_eq!(config.selected_node_id, hk);
    assert_eq!(config.selected_node_name, "HK");
    assert_eq!(
        config
            .selectable_nodes
            .iter()
            .map(|node| node.outbound_tag.as_str())
            .collect::<Vec<_>>(),
        vec![hk.as_str(), jp.as_str()]
    );
    assert!(config.controller.is_none());
}

#[test]
fn local_proxy_routing_config_rejects_unsupported_routed_node() {
    // The snapshot nodes are SOCKS, which the local proxy cannot render.
    let nodes = parse_config_document(SNAPSHOT_CONFIG).unwrap().nodes;
    let model = parse_config_document(SNAPSHOT_CONFIG)
        .unwrap()
        .routing
        .unwrap();

    let error = render_sing_box_local_proxy_routing_config(
        &SingBoxLocalProxyConfigRequest {
            nodes,
            selected_node_id: None,
            listen_host: "127.0.0.1".to_string(),
            listen_port: 7890,
        },
        &model,
    )
    .unwrap_err();

    assert_eq!(error.code, ENGINE_SINGBOX_CONFIG_NODE_UNSUPPORTED_CODE);
}
