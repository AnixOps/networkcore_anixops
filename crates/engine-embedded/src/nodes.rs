//! Converts normalized subscription nodes (`control_domain::NodeDescriptor`)
//! into this engine's config envelope. The per-node outbound entries come
//! from the `node-import` crate.
//!
//! Desktop clients parse subscriptions with `config-core` and hand the nodes
//! here instead of rendering a config for an external engine. A node whose
//! protocol or options this build cannot carry is reported as unsupported, so
//! the caller can say which node and why without exposing its credentials.

use std::collections::BTreeMap;

use config_core::routing::RoutingSpec;
use control_domain::NodeDescriptor;
use serde_json::{json, Value};

use crate::config::CONFIG_SCHEMA_VERSION;
use crate::protocols;

pub use node_import::Unsupported;

/// The outbound entry (`{"type": ..., ...}`) for one node, if this build
/// compiles its protocol in.
pub fn outbound_for_node(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let outbound = node_import::outbound_json(node)?;
    let kind = outbound["type"].as_str().unwrap_or_default();
    if !protocols::default_registry().contains(kind) {
        return Err("protocol is not compiled into this build");
    }
    Ok(outbound)
}

/// Envelope with one outbound for the selected node (or the first node), and
/// that node.
pub fn single_node_envelope(
    profile_id: &str,
    nodes: &[NodeDescriptor],
    selected_node_id: Option<&str>,
) -> Result<(String, NodeDescriptor), Unsupported> {
    let node = match selected_node_id {
        Some(id) => nodes.iter().find(|node| node.id == id),
        None => nodes.first(),
    }
    .ok_or("the selected node is not in the subscription")?;
    let outbound = outbound_for_node(node)?;
    let envelope = json!({
        "schema_version": CONFIG_SCHEMA_VERSION,
        "profile_id": profile_id,
        "outbound": outbound,
    });
    Ok((envelope.to_string(), node.clone()))
}

/// Envelope with every node as a routed outbound plus `routing`'s rules and
/// policy groups. Fails if any node is unsupported, since rules and groups may
/// refer to it.
pub fn routing_envelope(
    profile_id: &str,
    nodes: &[NodeDescriptor],
    routing: &RoutingSpec,
) -> Result<String, Unsupported> {
    let mut outbounds = BTreeMap::new();
    for node in nodes {
        outbounds.insert(node.id.clone(), outbound_for_node(node)?);
    }
    let section = node_import::routing_json(routing);
    let envelope = json!({
        "schema_version": CONFIG_SCHEMA_VERSION,
        "profile_id": profile_id,
        "routing": {
            "outbounds": outbounds,
            "rules": section["rules"],
            "groups": section["groups"],
        },
    });
    Ok(envelope.to_string())
}
