use config_core::parse_config_document;
use config_core::routing::{RoutingModel, RoutingSpec};
use engine_singbox::{render_sing_box_route, SING_BOX_DIRECT_OUTBOUND_TAG};
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
