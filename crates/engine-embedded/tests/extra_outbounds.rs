//! Outbounds registered from outside the crate join every registry it builds.
//! This file is its own test binary, so the process-wide registration does not
//! leak into the other tests.

use std::sync::Arc;

use control_domain::{
    Endpoint, MetadataEntry, NodeDescriptor, Protocol, NODE_METADATA_ANX_PUBLIC_KEY,
    NODE_METADATA_ANX_USER_KEY,
};
use engine_embedded::nodes::outbound_for_node;
use engine_embedded::protocols::{default_registry, register_extra_outbound, supported_types};
use engine_outbound::registry::{BuildError, OutboundFactory, Settings};
use engine_outbound::{Dialer, TcpOutbound};

struct StandIn(&'static str);

impl OutboundFactory for StandIn {
    fn type_name(&self) -> &'static str {
        self.0
    }

    fn build(
        &self,
        _settings: &Settings,
        _dialer: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn TcpOutbound>, BuildError> {
        Err("stand-in factory")
    }
}

fn anx_node() -> NodeDescriptor {
    NodeDescriptor {
        id: "anx".to_string(),
        name: "anx".to_string(),
        protocol: Protocol::Anx,
        endpoint: Endpoint {
            host: "192.0.2.1".to_string(),
            port: 443,
        },
        tags: Vec::new(),
        metadata: [
            (NODE_METADATA_ANX_USER_KEY, "dXNlcg"),
            (NODE_METADATA_ANX_PUBLIC_KEY, "c2VydmVy"),
        ]
        .iter()
        .map(|(key, value)| MetadataEntry {
            key: key.to_string(),
            value: value.to_string(),
        })
        .collect(),
    }
}

#[test]
fn extra_outbounds_join_the_default_registry() {
    // The public build imports anx nodes but does not compile the protocol in.
    assert!(!default_registry().contains("anx"));
    assert_eq!(
        outbound_for_node(&anx_node()).unwrap_err(),
        "protocol is not compiled into this build"
    );

    register_extra_outbound(Arc::new(StandIn("anx")));
    // Registering the same type again replaces the earlier factory.
    register_extra_outbound(Arc::new(StandIn("anx")));

    let registry = default_registry();
    assert!(registry.contains("anx"));
    assert!(registry.contains("direct"));
    assert_eq!(
        supported_types()
            .iter()
            .filter(|kind| **kind == "anx")
            .count(),
        1
    );
    assert_eq!(outbound_for_node(&anx_node()).unwrap()["type"], "anx");
}
