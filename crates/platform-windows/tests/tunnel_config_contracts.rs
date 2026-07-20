use config_core::windows_tunnel::{WindowsTunnelPlan, WindowsTunnelRouteIntent};
use platform_windows::tunnel_config::{
    deserialize_tunnel_state, render_easytier_config, serialize_tunnel_state, verify_file_sha256,
    EasyTierConfigRequest, OwnedProcessHandle, WindowsRouteSnapshotEntry,
    WindowsTunnelLifecycleState, WindowsTunnelRuntimeOwnership, WindowsTunnelState,
    WINDOWS_TUNNEL_BINARY_HASH_INVALID_CODE, WINDOWS_TUNNEL_CONFIG_INVALID_CODE,
    WINDOWS_TUNNEL_STATE_INVALID_CODE, WINDOWS_TUNNEL_STATE_SCHEMA_UNSUPPORTED_CODE,
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
        client_bundle_id: "fixture-easytier-client-bundle-1".to_string(),
        client_sequence: 3,
        pop_bundle_id: "fixture-easytier-pop-bundle-1".to_string(),
        pop_sequence: 4,
        easytier_version: "2.6.1".to_string(),
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
            virtual_route_snapshot: vec![WindowsRouteSnapshotEntry {
                destination_cidr: "203.0.113.0/24".to_string(),
                gateway: Some("10.10.0.1".to_string()),
                interface_index: Some(42),
                metric: Some(7),
            }],
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
fn rejects_noncanonical_destination_policy_routes() {
    for destination_cidr in [
        "0.0.0.0/0",
        "::/0",
        "2001:db8::/32",
        "203.0.113.1/24",
        " 203.0.113.0/24",
        "203.0.113.0/24 ",
        "not-a-destination-prefix",
    ] {
        let mut plan = fixture_plan();
        plan.route_intents[0].destination_cidr = destination_cidr.to_string();

        let error = render_easytier_config(EasyTierConfigRequest {
            plan: &plan,
            network_name: "fixture-network",
            network_secret: "fixture-secret-never-commit",
            virtual_ipv4: None,
        })
        .expect_err("noncanonical destination policies must be rejected");
        assert_eq!(error.code, WINDOWS_TUNNEL_CONFIG_INVALID_CODE);
    }
}

#[test]
fn rejects_duplicate_destination_policy_routes() {
    let mut plan = fixture_plan();
    plan.route_intents.push(WindowsTunnelRouteIntent {
        route_id: "fixture-easytier-route-2".to_string(),
        destination_cidr: "203.0.113.0/24".to_string(),
        service_chain_id: "pop-a-chain".to_string(),
        direct_fallback: false,
    });

    let error = render_easytier_config(EasyTierConfigRequest {
        plan: &plan,
        network_name: "fixture-network",
        network_secret: "fixture-secret-never-commit",
        virtual_ipv4: None,
    })
    .expect_err("duplicate destination policies must be rejected");
    assert_eq!(error.code, WINDOWS_TUNNEL_CONFIG_INVALID_CODE);
}

#[test]
fn preserves_canonical_ipv4_host_routes() {
    let mut plan = fixture_plan();
    plan.route_intents[0].destination_cidr = "203.0.113.7/32".to_string();

    let artifact = render_easytier_config(EasyTierConfigRequest {
        plan: &plan,
        network_name: "fixture-network",
        network_secret: "fixture-secret-never-commit",
        virtual_ipv4: None,
    })
    .expect("canonical IPv4 host routes remain valid destination policies");

    assert_eq!(artifact.route_cidrs, vec!["203.0.113.7/32"]);
}

#[test]
fn rejects_invalid_binary_hash() {
    let error = verify_file_sha256(Path::new("C:/missing/easytier.exe"), "not-a-sha256")
        .expect_err("invalid hash format must be rejected before reading a file");

    assert_eq!(error.code, WINDOWS_TUNNEL_BINARY_HASH_INVALID_CODE);
}

#[test]
fn serializes_schema_v4_runtime_ownership_without_paths_or_secrets() {
    let state = fixture_state();
    let first = serialize_tunnel_state(&state).expect("state serializes");
    let second = serialize_tunnel_state(&state).expect("state serializes deterministically");

    assert_eq!(first, second);
    assert!(first.contains("\"schema_version\": 4"));
    assert!(first.contains("\"selected_pop_id\": \"pop-a\""));
    assert!(first.contains("\"creation_marker\": \"fixture-creation-marker\""));
    assert!(first.contains("\"cli_file_name\": \"easytier-cli.exe\""));
    assert!(first.contains("\"cli_sha256\""));
    assert!(first.contains("\"virtual_route_snapshot\""));
    assert!(first.contains("\"client_bundle_id\": \"fixture-easytier-client-bundle-1\""));
    assert!(first.contains("\"client_sequence\": 3"));
    assert!(first.contains("\"pop_bundle_id\": \"fixture-easytier-pop-bundle-1\""));
    assert!(first.contains("\"pop_sequence\": 4"));
    assert!(first.contains("\"easytier_version\": \"2.6.1\""));
    assert!(!first.contains("fixture-secret-never-commit"));
    assert!(!first.contains("C:/fixture/runtime/easytier-core.exe"));
    assert!(!first.contains("C:/fixture/runtime/easytier-cli.exe"));
    assert_eq!(
        deserialize_tunnel_state(first.as_bytes()).expect("state deserializes"),
        state
    );

    let mut schema_v3: serde_json::Value =
        serde_json::from_str(&first).expect("serialized state is JSON");
    schema_v3["schema_version"] = serde_json::Value::from(3_u64);
    let schema_v3 = serde_json::to_vec(&schema_v3).expect("schema-v3 record is JSON");
    let error = deserialize_tunnel_state(&schema_v3)
        .expect_err("schema-v3 state records must be unrecoverable");
    assert_eq!(error.code, WINDOWS_TUNNEL_STATE_SCHEMA_UNSUPPORTED_CODE);
}

#[test]
fn state_rejects_runtime_ownership_without_cli_hash() {
    let state = fixture_state();
    let serialized = serialize_tunnel_state(&state).expect("state serializes");
    let mut value: serde_json::Value =
        serde_json::from_str(&serialized).expect("serialized state is JSON");
    value["runtime_ownership"]
        .as_object_mut()
        .expect("runtime ownership is an object")
        .remove("cli_sha256");
    let missing_cli_hash = serde_json::to_vec(&value).expect("missing CLI hash fixture is JSON");

    let error = deserialize_tunnel_state(&missing_cli_hash)
        .expect_err("persisted runtime ownership must include a CLI SHA-256 pin");
    assert_eq!(error.code, WINDOWS_TUNNEL_STATE_INVALID_CODE);
}

#[test]
fn runtime_ownership_contract_includes_a_validated_cli_hash() {
    let source = include_str!("../src/tunnel_config.rs").replace("\r\n", "\n");

    assert!(source.contains("pub const WINDOWS_TUNNEL_STATE_SCHEMA_VERSION: u32 = 4;"));
    assert!(source.contains("pub cli_sha256: String,"));
    assert!(source.contains("!is_lowercase_sha256(&state.runtime_ownership.cli_sha256)"));
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

#[test]
fn state_rejects_process_session_id_that_differs_from_state() {
    let mut state = fixture_state();
    let different_process_session_id = "different-process-session";
    state.runtime_ownership.process.session_id = different_process_session_id.to_string();
    let serialized = serde_json::to_vec(&state).expect("fixture state JSON");

    let error = deserialize_tunnel_state(&serialized)
        .expect_err("state must bind the owned process to its session ID");
    assert_eq!(error.code, WINDOWS_TUNNEL_STATE_INVALID_CODE);
    assert!(!error.message.contains("windows-easytier-fixture-session"));
    assert!(!error.message.contains(different_process_session_id));
}

#[test]
fn state_rejects_noncanonical_owned_destination_routes() {
    for destination_cidr in [
        "0.0.0.0/0",
        "::/0",
        "2001:db8::/32",
        "203.0.113.1/24",
        " 203.0.113.0/24",
        "not-a-destination-prefix",
    ] {
        let mut state = fixture_state();
        state.runtime_ownership.route_cidrs = vec![destination_cidr.to_string()];
        state.runtime_ownership.virtual_route_snapshot[0].destination_cidr =
            destination_cidr.to_string();
        let serialized = serde_json::to_vec(&state).expect("fixture state JSON");

        let error = deserialize_tunnel_state(&serialized)
            .expect_err("persisted policy route ownership must stay canonical IPv4");
        assert_eq!(error.code, WINDOWS_TUNNEL_STATE_INVALID_CODE);
    }
}

#[test]
fn state_rejects_duplicate_owned_destination_routes() {
    let mut state = fixture_state();
    state
        .runtime_ownership
        .route_cidrs
        .push("203.0.113.0/24".to_string());
    state
        .runtime_ownership
        .virtual_route_snapshot
        .push(WindowsRouteSnapshotEntry {
            destination_cidr: "203.0.113.0/24".to_string(),
            gateway: Some("10.10.0.2".to_string()),
            interface_index: Some(43),
            metric: Some(8),
        });
    let serialized = serde_json::to_vec(&state).expect("fixture state JSON");

    let error = deserialize_tunnel_state(&serialized)
        .expect_err("persisted policy route ownership cannot repeat a destination");
    assert_eq!(error.code, WINDOWS_TUNNEL_STATE_INVALID_CODE);
}

#[test]
fn state_writer_uses_synced_unique_sibling_and_atomic_replacement() {
    let source = include_str!("../src/tunnel_config.rs").replace("\r\n", "\n");
    let writer_start = source
        .find("pub fn write_tunnel_state(path: &Path, state: &WindowsTunnelState)")
        .expect("state writer exists");
    let writer_end = source[writer_start..]
        .find("\n/// Reads and validates a state record")
        .expect("state writer ends before state reader");
    let writer = &source[writer_start..writer_start + writer_end];

    let serialized = writer
        .find("serialize_tunnel_state(state)?")
        .expect("state serializes before filesystem mutation");
    let temporary = writer
        .find("create_state_temporary_file(path)")
        .expect("state writer creates a unique sibling temporary file");
    let write = writer
        .find("write_all(serialized.as_bytes())")
        .expect("state writer writes serialized bytes to its temporary file");
    let sync = writer
        .find("sync_all()")
        .expect("state writer synchronizes its temporary file");
    let replace = writer
        .find("replace_state_file(&temporary_path, path)")
        .expect("state writer atomically replaces the destination after syncing");
    assert!(serialized < temporary && temporary < write && write < sync && sync < replace);
    assert!(writer.contains("fs::remove_file(&temporary_path)"));
    assert!(!writer.contains("fs::write("));

    let temporary_start = source
        .find("fn create_state_temporary_file(path: &Path)")
        .expect("state temporary helper exists");
    let temporary_end = source[temporary_start..]
        .find("\n#[cfg(windows)]\nfn replace_state_file(")
        .expect("state temporary helper ends before platform replacement");
    let temporary = &source[temporary_start..temporary_start + temporary_end];
    assert!(temporary.contains("path.parent()"));
    assert!(temporary.contains("directory.join("));
    assert!(temporary.contains(".create_new(true)"));
    assert!(temporary.contains("file.metadata()?.is_file()"));
    assert!(!temporary.contains("file_name().and_then(|name| name.to_str())"));
    assert!(temporary.contains("let file_name = path.file_name().ok_or_else("));
    assert!(temporary.contains("temporary_name.push(file_name)"));

    let windows_replace = "#[cfg(windows)]\nfn replace_state_file(";
    let windows_replace_start = source
        .find(windows_replace)
        .expect("Windows state replacement helper exists");
    let non_windows_replace = "#[cfg(not(windows))]\nfn replace_state_file(";
    let non_windows_replace_start = source
        .find(non_windows_replace)
        .expect("non-Windows state replacement helper exists");
    let windows_replace = &source[windows_replace_start..non_windows_replace_start];
    assert!(windows_replace.contains("MoveFileExW"));
    assert!(windows_replace.contains("MOVEFILE_REPLACE_EXISTING"));
    assert!(windows_replace.contains("MOVEFILE_WRITE_THROUGH"));

    let non_windows_replace = &source[non_windows_replace_start..];
    assert!(non_windows_replace.contains("fs::rename(temporary_path, destination)"));
}

#[test]
fn stop_source_never_writes_transient_stopping_state() {
    let source = include_str!("../src/tunnel_runtime.rs").replace("\r\n", "\n");
    let stop_marker =
        "    pub fn stop(&mut self, state_path: &Path, confirm: bool) -> DomainResult<WindowsTunnelState> {";
    let stop_start = source
        .find(stop_marker)
        .expect("stop implementation exists");
    let stop_end = source[stop_start..]
        .find("\n    fn prepare_start(")
        .expect("stop implementation ends before start preparation");
    let stop = &source[stop_start..stop_start + stop_end];

    assert!(stop.contains("stopping.state = WindowsTunnelLifecycleState::Stopping"));
    assert!(
        !stop.contains("write_tunnel_state(&state_path, &stopping)"),
        "a post-removal stopping write can leave an unrecoverable running record"
    );
}
