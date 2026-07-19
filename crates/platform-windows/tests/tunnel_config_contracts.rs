use config_core::windows_tunnel::{WindowsTunnelPlan, WindowsTunnelRouteIntent};
use platform_windows::tunnel_config::{
    deserialize_tunnel_state, render_easytier_config, serialize_tunnel_state, verify_file_sha256,
    EasyTierConfigRequest, OwnedProcessHandle, WindowsRouteSnapshotEntry,
    WindowsTunnelLifecycleState, WindowsTunnelRuntimeOwnership, WindowsTunnelState,
    WINDOWS_TUNNEL_BINARY_HASH_INVALID_CODE, WINDOWS_TUNNEL_STATE_SCHEMA_UNSUPPORTED_CODE,
    WINDOWS_TUNNEL_STATE_SCHEMA_VERSION,
};
use std::path::Path;

fn fixture_plan() -> WindowsTunnelPlan {
    WindowsTunnelPlan {
        session_id: "windows-easytier-fixture-session".to_string(),
        tenant_id: "fixture-tenant-1".to_string(),
        client_bundle_id: "fixture-easytier-client-bundle-1".to_string(),
        pop_bundle_id: "fixture-easytier-pop-bundle-1".to_string(),
        client_sequence: 3,
        pop_sequence: 4,
        selected_pop_id: "pop-a".to_string(),
        selected_endpoint: "198.51.100.10:11010".to_string(),
        route_intents: vec![WindowsTunnelRouteIntent {
            route_id: "fixture-easytier-route-1".to_string(),
            destination_cidr: "203.0.113.0/24".to_string(),
            service_chain_id: "pop-a-chain".to_string(),
            direct_fallback: false,
        }],
        endpoint_bypass_required: true,
        plan_digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
    }
}

fn fixture_state() -> WindowsTunnelState {
    WindowsTunnelState {
        schema_version: WINDOWS_TUNNEL_STATE_SCHEMA_VERSION,
        session_id: "windows-easytier-fixture-session".to_string(),
        plan_digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        selected_pop_id: "pop-a".to_string(),
        selected_endpoint: "198.51.100.10:11010".to_string(),
        state: WindowsTunnelLifecycleState::Running,
        config_path: "fixture-state.easytier.toml".to_string(),
        last_client_sequence: 3,
        last_pop_sequence: 4,
        route_snapshot: vec![WindowsRouteSnapshotEntry {
            destination_cidr: "198.51.100.10/32".to_string(),
            gateway: Some("192.0.2.1".to_string()),
            interface_index: Some(12),
            metric: Some(25),
        }],
        rollback_status: "clean".to_string(),
        runtime_ownership: WindowsTunnelRuntimeOwnership {
            process: OwnedProcessHandle {
                session_id: "windows-easytier-fixture-session".to_string(),
                process_id: 41001,
                creation_marker: "fixture-creation-marker".to_string(),
            },
            binary_sha256: "d33d1d119b40c768c4d96c66236ba1c033e72a9c041e88aa9c84bd67a38d04a5"
                .to_string(),
            cli_file_name: "easytier-cli.exe".to_string(),
            route_cidrs: vec!["203.0.113.0/24".to_string()],
        },
    }
}

#[test]
fn renders_network_identity_peer_and_destination_routes_without_secret_in_redacted_output() {
    let secret = "fixture-secret-never-commit";
    let plan = fixture_plan();
    let artifact = render_easytier_config(EasyTierConfigRequest {
        plan: &plan,
        network_name: "fixture-network",
        network_secret: secret,
        virtual_ipv4: Some("10.10.0.2"),
    })
    .expect("valid EasyTier config request");

    assert!(artifact.toml.contains("network_identity"));
    assert!(artifact.toml.contains("fixture-network"));
    assert!(artifact.toml.contains("peer"));
    assert!(artifact.toml.contains("198.51.100.10:11010"));
    assert!(artifact.toml.contains("203.0.113.0/24"));
    assert!(artifact.toml.contains("10.10.0.2"));
    assert_eq!(artifact.route_cidrs, vec!["203.0.113.0/24"]);

    let raw: toml::Value = toml::from_str(&artifact.toml).expect("raw TOML parses");
    let raw_routes = raw
        .get("routes")
        .and_then(toml::Value::as_array)
        .expect("destination routes are a root-level TOML array");
    assert_eq!(raw_routes.len(), 1);
    assert_eq!(raw_routes[0].as_str(), Some("203.0.113.0/24"));
    assert!(raw.get("proxy_network").is_none());
    let raw_peers = raw
        .get("peer")
        .and_then(toml::Value::as_array)
        .expect("peer list is present");
    assert!(raw_peers.iter().all(|peer| peer.get("routes").is_none()));

    assert!(artifact.redacted_toml.contains("[redacted]"));
    assert!(!artifact.redacted_toml.contains(secret));
    let redacted: toml::Value =
        toml::from_str(&artifact.redacted_toml).expect("redacted TOML parses");
    let redacted_routes = redacted
        .get("routes")
        .and_then(toml::Value::as_array)
        .expect("redacted destination routes are a root-level TOML array");
    assert_eq!(redacted_routes.len(), 1);
    assert_eq!(redacted_routes[0].as_str(), Some("203.0.113.0/24"));
    assert!(redacted.get("proxy_network").is_none());
    let redacted_peers = redacted
        .get("peer")
        .and_then(toml::Value::as_array)
        .expect("redacted peer list is present");
    assert!(redacted_peers
        .iter()
        .all(|peer| peer.get("routes").is_none()));
}

#[test]
fn rejects_invalid_binary_hash() {
    let error = verify_file_sha256(Path::new("C:/missing/easytier.exe"), "not-a-sha256")
        .expect_err("invalid hash format must be rejected before reading a file");

    assert_eq!(error.code, WINDOWS_TUNNEL_BINARY_HASH_INVALID_CODE);
}

#[test]
fn serializes_schema_v2_runtime_ownership_without_paths_or_secrets() {
    let state = fixture_state();
    let first = serialize_tunnel_state(&state).expect("state serializes");
    let second = serialize_tunnel_state(&state).expect("state serializes deterministically");

    assert_eq!(first, second);
    assert!(first.contains("\"schema_version\": 2"));
    assert!(first.contains("\"selected_pop_id\": \"pop-a\""));
    assert!(first.contains("\"creation_marker\": \"fixture-creation-marker\""));
    assert!(first.contains("\"cli_file_name\": \"easytier-cli.exe\""));
    assert!(!first.contains("fixture-secret-never-commit"));
    assert!(!first.contains("C:/fixture/runtime/easytier-core.exe"));
    assert!(!first.contains("C:/fixture/runtime/easytier-cli.exe"));
    assert_eq!(
        deserialize_tunnel_state(first.as_bytes()).expect("state deserializes"),
        state
    );

    let mut schema_v1: serde_json::Value =
        serde_json::from_str(&first).expect("serialized state is JSON");
    schema_v1["schema_version"] = serde_json::Value::from(1_u64);
    let schema_v1 = serde_json::to_vec(&schema_v1).expect("schema-v1 record is JSON");
    let error = deserialize_tunnel_state(&schema_v1)
        .expect_err("schema-v1 state records must be unrecoverable");
    assert_eq!(error.code, WINDOWS_TUNNEL_STATE_SCHEMA_UNSUPPORTED_CODE);
}

#[test]
fn refuses_unknown_state_schema() {
    let state = fixture_state();
    let serialized = serialize_tunnel_state(&state).expect("state serializes");
    let mut value: serde_json::Value =
        serde_json::from_str(&serialized).expect("serialized state is JSON");
    value["schema_version"] = serde_json::Value::from(99_u64);
    let unknown_schema = serde_json::to_vec(&value).expect("unknown schema is JSON");

    let error = deserialize_tunnel_state(&unknown_schema)
        .expect_err("unknown state schema must be rejected");
    assert_eq!(error.code, WINDOWS_TUNNEL_STATE_SCHEMA_UNSUPPORTED_CODE);
}
