use control_domain::{DomainError, DomainResult};
use networkcore_windows::{
    cli_help_text, handle_entrypoint, handle_entrypoint_with_tunnel, handle_parse_error,
    parse_args, render_response, DeliveryBackedWindowsTunnelCommandService, OutputFormat,
    WindowsCliCommand, WindowsCliExitCode, WindowsCliResponse, WindowsTunnelCommandResult,
    WindowsTunnelCommandService, WindowsTunnelDeliveryLoader, WindowsTunnelLifecyclePort,
    WindowsTunnelPrivilegePort, WindowsTunnelStartArgs, WindowsTunnelStatusArgs,
    WindowsTunnelStopArgs, CLI_WINDOWS_ARGUMENT_UNKNOWN_CODE, CLI_WINDOWS_ARTIFACT_READY_CODE,
    CLI_WINDOWS_SYSTEM_MUTATION_BLOCKED_CODE, COMMAND_NAME,
    WINDOWS_CLI_SUBSCRIPTION_COMPATIBILITY_STATUS,
};
use platform_windows::tunnel_config::{
    OwnedProcessHandle, WindowsRouteSnapshotEntry, WindowsTunnelLifecycleState,
    WindowsTunnelRuntimeOwnership, WindowsTunnelState, WINDOWS_TUNNEL_STATE_SCHEMA_VERSION,
};
use platform_windows::tunnel_runtime::{
    WindowsTunnelStartRequest, WINDOWS_TUNNEL_ADMIN_REQUIRED_CODE,
    WINDOWS_TUNNEL_STATUS_UNAVAILABLE_CODE,
};
use platform_windows::{
    ReadOnlyWindowsPlatformCapabilityService, WindowsTunnelPlan, WindowsTunnelRouteIntent,
    WINDOWS_ACTIVE_STATUS, WINDOWS_BLOCKED_STATUS, WINDOWS_CLI_ARTIFACT_GATE,
    WINDOWS_CLI_RELEASE_ASSETS_STATUS, WINDOWS_CLI_SOURCE_IDENTITY,
};
use std::path::{Path, PathBuf};

const FOREGROUND_TUNNEL_MUTATION_POLICY: &str = "explicit-confirm-external-easytier-only";
const EASYTIER_CORE_COMMAND_FRAGMENT: &str = "easytier-core.exe --config-file";
const EASYTIER_CLI_COMMAND_FRAGMENT: &str = "easytier-cli.exe --rpc-portal";

fn tunnel_start_arguments(
    include_confirm: bool,
    include_secret_file: bool,
    include_state_path: bool,
) -> Vec<&'static str> {
    let mut arguments = vec![
        "tunnel",
        "start",
        "C:/fixtures/client-envelope.json",
        "C:/fixtures/pop-envelope.json",
        "--pop-id",
        "pop-a",
        "--device-id",
        "fixture-device-1",
        "--delivery-public-key-file",
        "C:/fixtures/delivery-public-key.pem",
        "--easytier-bin",
        "C:/Program Files/EasyTier/easytier-core.exe",
        "--easytier-cli",
        "C:/Program Files/EasyTier/easytier-cli.exe",
        "--easytier-version",
        "2.6.1",
        "--easytier-sha256",
        "d33d1d119b40c768c4d96c66236ba1c033e72a9c041e88aa9c84bd67a38d04a5",
        "--network-name",
        "fixture-network",
    ];
    if include_state_path {
        arguments.extend(["--state-path", "C:/ProgramData/AnixOps/tunnel-state.json"]);
    }
    if include_secret_file {
        arguments.extend(["--network-secret-file", "C:/private/network-secret.txt"]);
    }
    if include_confirm {
        arguments.push("--confirm");
    }
    arguments
}

fn fixture_tunnel_state() -> WindowsTunnelState {
    WindowsTunnelState {
        schema_version: WINDOWS_TUNNEL_STATE_SCHEMA_VERSION,
        session_id: "fixture-session".to_string(),
        plan_digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        selected_pop_id: "pop-a".to_string(),
        selected_endpoint: "198.51.100.10:11010".to_string(),
        state: WindowsTunnelLifecycleState::Running,
        config_path: "fixture.easytier.toml".to_string(),
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
                session_id: "fixture-session".to_string(),
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

fn fixture_tunnel_command_result() -> WindowsTunnelCommandResult {
    WindowsTunnelCommandResult {
        state: fixture_tunnel_state(),
        peer_ready: true,
        route_ready: true,
        route_count: 1,
    }
}

fn fixture_stopped_state() -> WindowsTunnelState {
    let mut state = fixture_tunnel_state();
    state.state = WindowsTunnelLifecycleState::Stopped;
    state
}

fn fixture_tunnel_plan() -> WindowsTunnelPlan {
    WindowsTunnelPlan {
        session_id: "fixture-session".to_string(),
        tenant_id: "fixture-tenant".to_string(),
        client_bundle_id: "fixture-client-bundle".to_string(),
        pop_bundle_id: "fixture-pop-bundle".to_string(),
        client_sequence: 3,
        pop_sequence: 4,
        selected_pop_id: "pop-a".to_string(),
        selected_endpoint: "198.51.100.10:11010".to_string(),
        route_intents: vec![WindowsTunnelRouteIntent {
            route_id: "fixture-route".to_string(),
            destination_cidr: "203.0.113.0/24".to_string(),
            service_chain_id: "fixture-chain".to_string(),
            direct_fallback: false,
        }],
        endpoint_bypass_required: true,
        plan_digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
    }
}

fn fixture_tunnel_start_args() -> WindowsTunnelStartArgs {
    match parse_args(tunnel_start_arguments(true, true, true)).expect("fixture tunnel start") {
        WindowsCliCommand::TunnelStart(args) => args,
        command => panic!("expected tunnel start command, got {command:?}"),
    }
}

fn fixture_tunnel_status_args() -> WindowsTunnelStatusArgs {
    match parse_args([
        "tunnel",
        "status",
        "C:/ProgramData/AnixOps/tunnel-state.json",
    ])
    .expect("fixture tunnel status")
    {
        WindowsCliCommand::TunnelStatus(args) => args,
        command => panic!("expected tunnel status command, got {command:?}"),
    }
}

fn fixture_tunnel_stop_args() -> WindowsTunnelStopArgs {
    match parse_args([
        "tunnel",
        "stop",
        "C:/ProgramData/AnixOps/tunnel-state.json",
        "--confirm",
    ])
    .expect("fixture tunnel stop")
    {
        WindowsCliCommand::TunnelStop(args) => args,
        command => panic!("expected tunnel stop command, got {command:?}"),
    }
}

fn assert_redacted_tunnel_success_response(response: &WindowsCliResponse, state_path: &str) {
    let json_rendered = render_response(response, OutputFormat::Json);
    let json: serde_json::Value = serde_json::from_str(&json_rendered).expect("valid JSON");
    let tunnel_json = json["tunnel"]
        .as_object()
        .expect("tunnel response JSON is present");
    let text_rendered = render_response(response, OutputFormat::Text);

    assert_eq!(tunnel_json["session_id"], "fixture-session");
    assert_eq!(tunnel_json["state"], "running");
    assert_eq!(tunnel_json["selected_pop_id"], "pop-a");
    assert_eq!(
        tunnel_json["plan_digest"],
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    );
    assert_eq!(tunnel_json["peer_ready"].as_bool(), Some(true));
    assert_eq!(tunnel_json["route_ready"].as_bool(), Some(true));
    assert_eq!(tunnel_json["route_count"].as_u64(), Some(1));
    assert_eq!(tunnel_json["rollback_status"], "clean");
    assert!(text_rendered.contains("session_id: fixture-session"));
    assert!(text_rendered.contains("state: running"));
    assert!(text_rendered.contains("selected_pop_id: pop-a"));
    assert!(text_rendered
        .contains("plan_digest: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    assert!(text_rendered.contains("peer_ready: true"));
    assert!(text_rendered.contains("route_ready: true"));
    assert!(text_rendered.contains("route_count: 1"));
    assert!(text_rendered.contains("rollback_status: clean"));

    for sensitive_value in [
        "network_secret_file",
        "client_envelope",
        "pop_envelope",
        "easytier_binary",
        "easytier_cli",
        "state_path",
        "config_path",
        "C:/private/network-secret.txt",
        "C:/fixtures/client-envelope.json",
        "C:/fixtures/pop-envelope.json",
        "C:/fixtures/delivery-public-key.pem",
        "C:/Program Files/EasyTier/easytier-core.exe",
        "C:/Program Files/EasyTier/easytier-cli.exe",
        EASYTIER_CORE_COMMAND_FRAGMENT,
        EASYTIER_CLI_COMMAND_FRAGMENT,
        state_path,
        "fixture.easytier.toml",
    ] {
        assert!(
            !json_rendered.contains(sensitive_value),
            "tunnel JSON leaked {sensitive_value}"
        );
        assert!(
            !text_rendered.contains(sensitive_value),
            "tunnel text leaked {sensitive_value}"
        );
    }
}

#[derive(Debug)]
struct RecordedTunnelStart {
    client_envelope: PathBuf,
    pop_envelope: PathBuf,
    pop_id: String,
    device_id: String,
    delivery_public_key_file: PathBuf,
    easytier_binary: PathBuf,
    easytier_cli: PathBuf,
    easytier_version: String,
    easytier_sha256: String,
    network_name: String,
    network_secret_file: PathBuf,
    state_path: PathBuf,
    confirm: bool,
}

#[derive(Debug)]
struct RecordedTunnelStop {
    state_path: PathBuf,
    confirm: bool,
}

struct RecordingTunnelCommandService {
    start_calls: Vec<RecordedTunnelStart>,
    status_paths: Vec<PathBuf>,
    stop_calls: Vec<RecordedTunnelStop>,
    status_error_marker: Option<String>,
}

impl RecordingTunnelCommandService {
    fn new() -> Self {
        Self {
            start_calls: Vec::new(),
            status_paths: Vec::new(),
            stop_calls: Vec::new(),
            status_error_marker: None,
        }
    }

    fn with_status_error(marker: impl Into<String>) -> Self {
        Self {
            status_error_marker: Some(marker.into()),
            ..Self::new()
        }
    }
}

impl WindowsTunnelCommandService for RecordingTunnelCommandService {
    fn start(&mut self, args: &WindowsTunnelStartArgs) -> DomainResult<WindowsTunnelCommandResult> {
        self.start_calls.push(RecordedTunnelStart {
            client_envelope: args.client_envelope.clone(),
            pop_envelope: args.pop_envelope.clone(),
            pop_id: args.pop_id.clone(),
            device_id: args.device_id.clone(),
            delivery_public_key_file: args.delivery_public_key_file.clone(),
            easytier_binary: args.easytier_binary.clone(),
            easytier_cli: args.easytier_cli.clone(),
            easytier_version: args.easytier_version.clone(),
            easytier_sha256: args.easytier_sha256.clone(),
            network_name: args.network_name.clone(),
            network_secret_file: args.network_secret_file.clone(),
            state_path: args.state_path.clone(),
            confirm: args.confirm,
        });
        Ok(fixture_tunnel_command_result())
    }

    fn status(
        &mut self,
        args: &WindowsTunnelStatusArgs,
    ) -> DomainResult<WindowsTunnelCommandResult> {
        self.status_paths.push(args.state_path.clone());
        if let Some(marker) = &self.status_error_marker {
            return Err(DomainError::new(
                WINDOWS_TUNNEL_STATUS_UNAVAILABLE_CODE,
                format!("synthetic status failure: {marker}"),
            ));
        }
        Ok(fixture_tunnel_command_result())
    }

    fn stop(&mut self, args: &WindowsTunnelStopArgs) -> DomainResult<WindowsTunnelCommandResult> {
        self.stop_calls.push(RecordedTunnelStop {
            state_path: args.state_path.clone(),
            confirm: args.confirm,
        });
        Ok(fixture_tunnel_command_result())
    }
}

#[derive(Clone)]
struct FixedPrivilege(bool);

impl WindowsTunnelPrivilegePort for FixedPrivilege {
    fn is_elevated(&self) -> bool {
        self.0
    }
}

#[derive(Clone)]
struct RecordingDeliveryLoader {
    plan: WindowsTunnelPlan,
    calls: std::rc::Rc<std::cell::Cell<usize>>,
}

impl WindowsTunnelDeliveryLoader for RecordingDeliveryLoader {
    fn load_plan(&self, _args: &WindowsTunnelStartArgs) -> DomainResult<WindowsTunnelPlan> {
        self.calls.set(self.calls.get() + 1);
        Ok(self.plan.clone())
    }
}

#[derive(Default)]
struct LifecycleEvents {
    started: Vec<WindowsTunnelStartRequest>,
    status_calls: Vec<PathBuf>,
    stop_calls: Vec<(PathBuf, bool)>,
}

#[derive(Clone)]
struct RecordingLifecyclePort {
    events: std::rc::Rc<std::cell::RefCell<LifecycleEvents>>,
    running_state: WindowsTunnelState,
    stopped_state: WindowsTunnelState,
}

impl RecordingLifecyclePort {
    fn with_states(
        events: std::rc::Rc<std::cell::RefCell<LifecycleEvents>>,
        running_state: WindowsTunnelState,
        stopped_state: WindowsTunnelState,
    ) -> Self {
        Self {
            events,
            running_state,
            stopped_state,
        }
    }
}

impl WindowsTunnelLifecyclePort for RecordingLifecyclePort {
    fn start(&mut self, request: WindowsTunnelStartRequest) -> DomainResult<WindowsTunnelState> {
        self.events.borrow_mut().started.push(request);
        Ok(self.running_state.clone())
    }

    fn status(&mut self, state_path: &Path) -> DomainResult<WindowsTunnelState> {
        self.events
            .borrow_mut()
            .status_calls
            .push(state_path.to_path_buf());
        Ok(self.running_state.clone())
    }

    fn stop(&mut self, state_path: &Path, confirm: bool) -> DomainResult<WindowsTunnelState> {
        self.events
            .borrow_mut()
            .stop_calls
            .push((state_path.to_path_buf(), confirm));
        Ok(self.stopped_state.clone())
    }
}

#[test]
fn windows_cli_help_declares_package_boundary_and_explicit_easytier_tunnel() {
    let help = cli_help_text();

    assert!(help.contains("NetworkCore Windows CLI"));
    assert!(help.contains(COMMAND_NAME));
    assert!(help.contains(WINDOWS_CLI_ARTIFACT_GATE));
    assert!(help.contains(WINDOWS_CLI_SOURCE_IDENTITY));
    assert!(help.contains("system_mutation_policy: none"));
    assert!(help.contains("system-proxy-mutation"));
    assert!(help.contains("system-trust-store-mutation"));
    assert!(help.contains("javascript-script-dispatch"));
    assert!(help.contains("preinstalled EasyTier"));
    assert!(help.contains("elevated"));
    assert!(help.contains("--confirm"));
}

#[test]
fn windows_cli_capabilities_json_reports_foreground_tunnel_active_and_legacy_mutations_blocked() {
    let command = parse_args(["capabilities", "--format", "json"]).expect("valid command");
    let platform = ReadOnlyWindowsPlatformCapabilityService::new();
    let response = handle_entrypoint(command, &platform);
    let rendered = render_response(&response, OutputFormat::Json);
    let json: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");

    assert_eq!(json["ok"].as_bool(), Some(true));
    assert_eq!(json["command"], "capabilities");
    assert_eq!(json["capabilities"]["platform"], "windows");
    assert_eq!(
        json["capabilities"]["artifact_gate"],
        WINDOWS_CLI_ARTIFACT_GATE
    );
    assert_eq!(
        json["capabilities"]["source_identity"],
        WINDOWS_CLI_SOURCE_IDENTITY
    );
    assert_eq!(
        json["capabilities"]["package_windows"]["status"],
        WINDOWS_ACTIVE_STATUS
    );
    assert_eq!(
        json["capabilities"]["foreground_tunnel"]["status"],
        WINDOWS_ACTIVE_STATUS
    );
    assert_eq!(
        json["capabilities"]["foreground_tunnel"]["mutation_policy"],
        FOREGROUND_TUNNEL_MUTATION_POLICY
    );
    assert_eq!(
        json["capabilities"]["subscription_compatibility"]["status"],
        "deferred"
    );
    assert_eq!(
        json["capabilities"]["service"]["status"],
        WINDOWS_BLOCKED_STATUS
    );
    assert_eq!(
        json["capabilities"]["driver"]["status"],
        WINDOWS_BLOCKED_STATUS
    );
    assert_eq!(
        json["capabilities"]["installer"]["status"],
        WINDOWS_BLOCKED_STATUS
    );
    assert_eq!(
        json["capabilities"]["system_proxy_mutation"]["status"],
        WINDOWS_BLOCKED_STATUS
    );
    assert_eq!(
        json["capabilities"]["trust_store_mutation"]["status"],
        WINDOWS_BLOCKED_STATUS
    );
    assert_eq!(
        json["capabilities"]["script_dispatch"]["status"],
        WINDOWS_BLOCKED_STATUS
    );
}

#[test]
fn windows_cli_capabilities_text_lists_release_assets_and_blocked_lifecycle() {
    let command = parse_args(["capabilities"]).expect("valid command");
    let platform = ReadOnlyWindowsPlatformCapabilityService::new();
    let response = handle_entrypoint(command, &platform);
    let rendered = render_response(&response, OutputFormat::Text);

    let release_assets_line = format!("release_assets: {WINDOWS_CLI_RELEASE_ASSETS_STATUS}");
    assert!(rendered.contains(&release_assets_line));
    assert!(rendered.contains("foreground_tunnel: active"));
    assert!(rendered.contains("driver: blocked"));
    assert!(rendered.contains("installer: blocked"));
    assert!(rendered.contains("managed_lifecycle: blocked"));
}

#[test]
fn windows_cli_status_reports_foreground_tunnel_and_legacy_blocked_lifecycle() {
    let platform = ReadOnlyWindowsPlatformCapabilityService::new();
    let response = handle_entrypoint(
        WindowsCliCommand::Status {
            format: OutputFormat::Text,
        },
        &platform,
    );
    let rendered = render_response(&response, OutputFormat::Text);

    assert!(rendered.contains("package_windows: defined"));
    let release_assets_line = format!("release_assets: {WINDOWS_CLI_RELEASE_ASSETS_STATUS}");
    let subscription_line =
        format!("subscription_compatibility: {WINDOWS_CLI_SUBSCRIPTION_COMPATIBILITY_STATUS}");
    assert!(rendered.contains(&release_assets_line));
    assert!(rendered.contains(&subscription_line));
    assert!(rendered.contains("foreground_tunnel: active"));
    assert!(rendered.contains("service: blocked"));
    assert!(rendered.contains("driver: blocked"));
    assert!(rendered.contains("installer: blocked"));
    assert!(rendered.contains("system_proxy_mutation: blocked"));
    assert!(rendered.contains("trust_store_mutation: blocked"));
    assert!(rendered.contains("script_dispatch: blocked"));
    assert!(rendered.contains("managed_lifecycle: blocked"));
}

#[test]
fn windows_cli_diagnostics_report_artifact_ready_and_system_mutation_blocked() {
    let command = parse_args(["diagnostics", "--format", "json"]).expect("valid command");
    let platform = ReadOnlyWindowsPlatformCapabilityService::new();
    let response = handle_entrypoint(command, &platform);
    let rendered = render_response(&response, OutputFormat::Json);
    let json: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");

    assert_eq!(json["ok"].as_bool(), Some(true));
    let diagnostics = json["diagnostics"].as_array().expect("diagnostics array");
    assert!(diagnostics
        .iter()
        .any(|item| item["code"] == CLI_WINDOWS_ARTIFACT_READY_CODE));
    assert!(diagnostics
        .iter()
        .any(|item| item["code"] == CLI_WINDOWS_SYSTEM_MUTATION_BLOCKED_CODE));
}

#[test]
fn windows_cli_unknown_command_returns_argument_error() {
    let error = parse_args(["install-service"]).expect_err("unknown command");
    let response = handle_parse_error(error.into_diagnostic());
    let rendered = render_response(&response, OutputFormat::Text);

    assert!(!response.ok);
    assert_eq!(response.exit_code, WindowsCliExitCode::ArgumentOrConfig);
    assert!(rendered.contains(CLI_WINDOWS_ARGUMENT_UNKNOWN_CODE));
    assert!(rendered.contains("unknown windows CLI command"));
}

#[test]
fn parses_tunnel_start_with_all_explicit_paths() {
    let mut arguments = tunnel_start_arguments(true, true, true);
    arguments.insert(1, "json");
    arguments.insert(1, "--format");

    let command = parse_args(arguments).expect("fully explicit tunnel start command");
    match command {
        WindowsCliCommand::TunnelStart(args) => {
            assert_eq!(args.format(), OutputFormat::Json);
            assert_eq!(
                args.client_envelope,
                PathBuf::from("C:/fixtures/client-envelope.json")
            );
            assert_eq!(
                args.pop_envelope,
                PathBuf::from("C:/fixtures/pop-envelope.json")
            );
            assert_eq!(args.pop_id, "pop-a");
            assert_eq!(args.device_id, "fixture-device-1");
            assert_eq!(
                args.delivery_public_key_file,
                PathBuf::from("C:/fixtures/delivery-public-key.pem")
            );
            assert_eq!(
                args.easytier_binary,
                PathBuf::from("C:/Program Files/EasyTier/easytier-core.exe")
            );
            assert_eq!(
                args.easytier_cli,
                PathBuf::from("C:/Program Files/EasyTier/easytier-cli.exe")
            );
            assert_eq!(args.easytier_version, "2.6.1");
            assert_eq!(
                args.easytier_sha256,
                "d33d1d119b40c768c4d96c66236ba1c033e72a9c041e88aa9c84bd67a38d04a5"
            );
            assert_eq!(args.network_name, "fixture-network");
            assert_eq!(
                args.network_secret_file,
                PathBuf::from("C:/private/network-secret.txt")
            );
            assert_eq!(
                args.state_path,
                PathBuf::from("C:/ProgramData/AnixOps/tunnel-state.json")
            );
            assert!(args.confirm);
        }
        other => panic!("expected tunnel start command, got {other:?}"),
    }
}

#[test]
fn rejects_tunnel_start_without_confirm() {
    let error = parse_args(tunnel_start_arguments(false, true, true))
        .expect_err("tunnel start must require explicit confirmation");
    let response = handle_parse_error(error.into_diagnostic());
    let rendered = render_response(&response, OutputFormat::Text);

    assert!(!response.ok);
    assert_eq!(response.exit_code, WindowsCliExitCode::ArgumentOrConfig);
    assert!(rendered.contains("--confirm"));
}

#[test]
fn rejects_tunnel_start_without_secret_file() {
    let error = parse_args(tunnel_start_arguments(true, false, true))
        .expect_err("tunnel start must require an explicit secret file");
    let response = handle_parse_error(error.into_diagnostic());
    let rendered = render_response(&response, OutputFormat::Text);

    assert!(!response.ok);
    assert_eq!(response.exit_code, WindowsCliExitCode::ArgumentOrConfig);
    assert!(rendered.contains("--network-secret-file"));
}

#[test]
fn rejects_tunnel_start_without_state_path() {
    let error = parse_args(tunnel_start_arguments(true, true, false))
        .expect_err("tunnel start must require an explicit state path");
    let response = handle_parse_error(error.into_diagnostic());
    let rendered = render_response(&response, OutputFormat::Text);

    assert!(!response.ok);
    assert_eq!(response.exit_code, WindowsCliExitCode::ArgumentOrConfig);
    assert!(rendered.contains("state path is required"));
    assert!(rendered.contains("--state-path"));
}

#[test]
fn confirmed_tunnel_start_delegates_typed_args_without_launching_process() {
    let command =
        parse_args(tunnel_start_arguments(true, true, true)).expect("confirmed tunnel start");
    match &command {
        WindowsCliCommand::TunnelStart(args) => {
            assert_eq!(args.format(), OutputFormat::Text);
            assert!(args.confirm);
        }
        other => panic!("expected tunnel start command, got {other:?}"),
    }

    let platform = ReadOnlyWindowsPlatformCapabilityService::new();
    let mut tunnel = RecordingTunnelCommandService::new();
    let response = handle_entrypoint_with_tunnel(command, &platform, &mut tunnel);

    assert!(response.ok);
    assert_redacted_tunnel_success_response(&response, "C:/ProgramData/AnixOps/tunnel-state.json");
    assert_eq!(tunnel.start_calls.len(), 1);
    let start = &tunnel.start_calls[0];
    assert_eq!(
        start.client_envelope,
        PathBuf::from("C:/fixtures/client-envelope.json")
    );
    assert_eq!(
        start.pop_envelope,
        PathBuf::from("C:/fixtures/pop-envelope.json")
    );
    assert_eq!(start.pop_id, "pop-a");
    assert_eq!(start.device_id, "fixture-device-1");
    assert_eq!(
        start.delivery_public_key_file,
        PathBuf::from("C:/fixtures/delivery-public-key.pem")
    );
    assert_eq!(
        start.easytier_binary,
        PathBuf::from("C:/Program Files/EasyTier/easytier-core.exe")
    );
    assert_eq!(
        start.easytier_cli,
        PathBuf::from("C:/Program Files/EasyTier/easytier-cli.exe")
    );
    assert_eq!(start.easytier_version, "2.6.1");
    assert_eq!(
        start.easytier_sha256,
        "d33d1d119b40c768c4d96c66236ba1c033e72a9c041e88aa9c84bd67a38d04a5"
    );
    assert_eq!(start.network_name, "fixture-network");
    assert_eq!(
        start.network_secret_file,
        PathBuf::from("C:/private/network-secret.txt")
    );
    assert_eq!(
        start.state_path,
        PathBuf::from("C:/ProgramData/AnixOps/tunnel-state.json")
    );
    assert!(start.confirm);
    assert!(tunnel.status_paths.is_empty());
    assert!(tunnel.stop_calls.is_empty());
}

#[test]
fn renders_redacted_tunnel_status_json() {
    let missing_state_error = parse_args(["tunnel", "status", "--format", "json"])
        .expect_err("tunnel status must require an explicit state path");
    let missing_state_response = handle_parse_error(missing_state_error.into_diagnostic());
    let missing_state_rendered = render_response(&missing_state_response, OutputFormat::Text);
    assert!(!missing_state_response.ok);
    assert_eq!(
        missing_state_response.exit_code,
        WindowsCliExitCode::ArgumentOrConfig
    );
    assert!(missing_state_rendered.contains("state path is required"));

    let private_state_path = "C:/private/fixture-secret-never-render/tunnel-state.json";
    let command = parse_args(["tunnel", "status", private_state_path, "--format", "json"])
        .expect("tunnel status command");
    match &command {
        WindowsCliCommand::TunnelStatus(args) => {
            assert_eq!(args.format(), OutputFormat::Json);
            assert_eq!(args.state_path, PathBuf::from(private_state_path));
        }
        other => panic!("expected tunnel status command, got {other:?}"),
    }
    let platform = ReadOnlyWindowsPlatformCapabilityService::new();
    let mut tunnel = RecordingTunnelCommandService::new();

    let response = handle_entrypoint_with_tunnel(command, &platform, &mut tunnel);
    let rendered = render_response(&response, OutputFormat::Json);
    let json: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
    let tunnel_json = json["tunnel"]
        .as_object()
        .expect("tunnel status JSON is present");

    assert!(response.ok);
    assert_redacted_tunnel_success_response(&response, private_state_path);
    assert_eq!(tunnel.status_paths, vec![PathBuf::from(private_state_path)]);
    assert_eq!(tunnel_json["session_id"], "fixture-session");
    assert_eq!(tunnel_json["selected_pop_id"], "pop-a");
    assert_eq!(tunnel_json["selected_endpoint"], "198.51.100.10:11010");
    assert_eq!(
        tunnel_json["plan_digest"],
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    );
    assert_eq!(tunnel_json["state"], "running");
    assert_eq!(tunnel_json["peer_ready"].as_bool(), Some(true));
    assert_eq!(tunnel_json["route_ready"].as_bool(), Some(true));
    assert_eq!(tunnel_json["route_count"].as_u64(), Some(1));
    assert_eq!(tunnel_json["rollback_status"], "clean");
    assert!(!tunnel_json.contains_key("config_path"));
    assert!(!rendered.contains("fixture.easytier.toml"));
    assert!(!rendered.contains(private_state_path));
    assert!(!rendered.contains("fixture-secret-never-render"));
}

#[test]
fn redacts_tunnel_command_service_error_details_from_json() {
    let private_state_path = "C:/private/fixture-status-input.json";
    let sensitive_marker = "fixture-secret-never-render C:/private/network-secret.txt easytier-core.exe --config-file C:/private/fixture.easytier.toml easytier-cli.exe --rpc-portal 127.0.0.1:15888 --raw-command=easytier-core.exe";
    let command = parse_args(["tunnel", "status", private_state_path, "--format", "json"])
        .expect("tunnel status command");
    let platform = ReadOnlyWindowsPlatformCapabilityService::new();
    let mut tunnel = RecordingTunnelCommandService::with_status_error(format!(
        "{sensitive_marker} {private_state_path}"
    ));

    let response = handle_entrypoint_with_tunnel(command, &platform, &mut tunnel);
    let rendered = render_response(&response, OutputFormat::Json);
    let json: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
    let diagnostics = json["diagnostics"].as_array().expect("diagnostics array");
    let text_rendered = render_response(&response, OutputFormat::Text);
    let sensitive_fragments = [
        sensitive_marker,
        private_state_path,
        "fixture-secret-never-render",
        "network-secret.txt",
        "--raw-command",
        "easytier-core.exe",
        "easytier-cli.exe",
        EASYTIER_CORE_COMMAND_FRAGMENT,
        EASYTIER_CLI_COMMAND_FRAGMENT,
        "fixture.easytier.toml",
    ];

    assert!(!response.ok);
    assert_eq!(tunnel.status_paths, vec![PathBuf::from(private_state_path)]);
    assert!(response
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == WINDOWS_TUNNEL_STATUS_UNAVAILABLE_CODE));
    assert!(diagnostics
        .iter()
        .any(|item| item["code"] == WINDOWS_TUNNEL_STATUS_UNAVAILABLE_CODE));
    assert!(text_rendered.contains(WINDOWS_TUNNEL_STATUS_UNAVAILABLE_CODE));
    for diagnostic in &response.diagnostics {
        for sensitive_fragment in sensitive_fragments {
            assert!(
                !diagnostic.code.contains(sensitive_fragment),
                "diagnostic code leaked {sensitive_fragment}"
            );
            assert!(
                !diagnostic.message.contains(sensitive_fragment),
                "diagnostic message leaked {sensitive_fragment}"
            );
            assert!(
                !diagnostic.source.contains(sensitive_fragment),
                "diagnostic source leaked {sensitive_fragment}"
            );
        }
    }
    for sensitive_fragment in sensitive_fragments {
        assert!(
            !rendered.contains(sensitive_fragment),
            "tunnel JSON error leaked {sensitive_fragment}"
        );
        assert!(
            !text_rendered.contains(sensitive_fragment),
            "tunnel text error leaked {sensitive_fragment}"
        );
    }
}

#[test]
fn tunnel_stop_requires_confirm() {
    let error = parse_args([
        "tunnel",
        "stop",
        "C:/ProgramData/AnixOps/tunnel-state.json",
        "--format",
        "json",
    ])
    .expect_err("tunnel stop must require explicit confirmation");
    let response = handle_parse_error(error.into_diagnostic());
    let rendered = render_response(&response, OutputFormat::Text);

    assert!(!response.ok);
    assert_eq!(response.exit_code, WindowsCliExitCode::ArgumentOrConfig);
    assert!(rendered.contains("--confirm"));
}

#[test]
fn tunnel_stop_requires_state_path() {
    let error = parse_args(["tunnel", "stop", "--confirm", "--format", "json"])
        .expect_err("tunnel stop must require an explicit state path");
    let response = handle_parse_error(error.into_diagnostic());
    let rendered = render_response(&response, OutputFormat::Text);

    assert!(!response.ok);
    assert_eq!(response.exit_code, WindowsCliExitCode::ArgumentOrConfig);
    assert!(rendered.contains("state path is required"));
}

#[test]
fn confirmed_tunnel_stop_delegates_typed_args_without_launching_process() {
    let state_path = "C:/ProgramData/AnixOps/tunnel-state.json";
    let command = parse_args([
        "tunnel",
        "stop",
        state_path,
        "--confirm",
        "--format",
        "json",
    ])
    .expect("confirmed tunnel stop");
    match &command {
        WindowsCliCommand::TunnelStop(args) => {
            assert_eq!(args.format(), OutputFormat::Json);
            assert_eq!(args.state_path, PathBuf::from(state_path));
            assert!(args.confirm);
        }
        other => panic!("expected tunnel stop command, got {other:?}"),
    }

    let platform = ReadOnlyWindowsPlatformCapabilityService::new();
    let mut tunnel = RecordingTunnelCommandService::new();
    let response = handle_entrypoint_with_tunnel(command, &platform, &mut tunnel);

    assert!(response.ok);
    assert_redacted_tunnel_success_response(&response, state_path);
    assert!(tunnel.start_calls.is_empty());
    assert!(tunnel.status_paths.is_empty());
    assert_eq!(tunnel.stop_calls.len(), 1);
    let stop = &tunnel.stop_calls[0];
    assert_eq!(stop.state_path, PathBuf::from(state_path));
    assert!(stop.confirm);
}

#[test]
fn delivery_backed_tunnel_start_requires_elevation_before_delivery_load() {
    let calls = std::rc::Rc::new(std::cell::Cell::new(0));
    let events = std::rc::Rc::new(std::cell::RefCell::new(LifecycleEvents::default()));
    let lifecycle = RecordingLifecyclePort::with_states(
        events.clone(),
        fixture_tunnel_state(),
        fixture_stopped_state(),
    );
    let mut service = DeliveryBackedWindowsTunnelCommandService::new(
        lifecycle,
        RecordingDeliveryLoader {
            plan: fixture_tunnel_plan(),
            calls: calls.clone(),
        },
        FixedPrivilege(false),
    );

    let error = service
        .start(&fixture_tunnel_start_args())
        .expect_err("unelevated start is denied");

    assert_eq!(error.code, WINDOWS_TUNNEL_ADMIN_REQUIRED_CODE);
    assert_eq!(calls.get(), 0);
    assert!(events.borrow().started.is_empty());
}

#[test]
fn delivery_backed_tunnel_stop_requires_elevation_before_lifecycle_stop() {
    let calls = std::rc::Rc::new(std::cell::Cell::new(0));
    let events = std::rc::Rc::new(std::cell::RefCell::new(LifecycleEvents::default()));
    let mut service = DeliveryBackedWindowsTunnelCommandService::new(
        RecordingLifecyclePort::with_states(
            events.clone(),
            fixture_tunnel_state(),
            fixture_stopped_state(),
        ),
        RecordingDeliveryLoader {
            plan: fixture_tunnel_plan(),
            calls,
        },
        FixedPrivilege(false),
    );

    let error = service
        .stop(&fixture_tunnel_stop_args())
        .expect_err("unelevated stop is denied");

    assert_eq!(error.code, WINDOWS_TUNNEL_ADMIN_REQUIRED_CODE);
    assert!(events.borrow().stop_calls.is_empty());
}

#[test]
fn delivery_backed_tunnel_service_delegates_verified_plan_and_reports_readiness() {
    let calls = std::rc::Rc::new(std::cell::Cell::new(0));
    let expected_plan = fixture_tunnel_plan();
    let events = std::rc::Rc::new(std::cell::RefCell::new(LifecycleEvents::default()));
    let mut service = DeliveryBackedWindowsTunnelCommandService::new(
        RecordingLifecyclePort::with_states(
            events.clone(),
            fixture_tunnel_state(),
            fixture_stopped_state(),
        ),
        RecordingDeliveryLoader {
            plan: expected_plan.clone(),
            calls: calls.clone(),
        },
        FixedPrivilege(true),
    );

    let result = service
        .start(&fixture_tunnel_start_args())
        .expect("elevated verified start delegates");

    assert_eq!(calls.get(), 1);
    assert_eq!(events.borrow().started.len(), 1);
    assert_eq!(events.borrow().started[0].plan, expected_plan);
    assert_eq!(result.state, fixture_tunnel_state());
    assert!(result.peer_ready);
    assert!(result.route_ready);
    assert_eq!(result.route_count, 1);
}

#[test]
fn delivery_backed_tunnel_status_and_stop_render_runtime_evidence() {
    let calls = std::rc::Rc::new(std::cell::Cell::new(0));
    let events = std::rc::Rc::new(std::cell::RefCell::new(LifecycleEvents::default()));
    let mut service = DeliveryBackedWindowsTunnelCommandService::new(
        RecordingLifecyclePort::with_states(
            events.clone(),
            fixture_tunnel_state(),
            fixture_stopped_state(),
        ),
        RecordingDeliveryLoader {
            plan: fixture_tunnel_plan(),
            calls,
        },
        FixedPrivilege(true),
    );

    let status = service
        .status(&fixture_tunnel_status_args())
        .expect("status is read-only");
    assert!(status.peer_ready);
    assert!(status.route_ready);
    assert_eq!(status.route_count, 1);

    let stopped = service
        .stop(&fixture_tunnel_stop_args())
        .expect("elevated stop delegates");
    assert!(!stopped.peer_ready);
    assert!(!stopped.route_ready);
    assert_eq!(stopped.route_count, 0);
    assert_eq!(events.borrow().status_calls.len(), 1);
    assert_eq!(
        events.borrow().stop_calls,
        vec![(fixture_tunnel_stop_args().state_path, true)]
    );
}

#[test]
fn native_main_routes_tunnel_commands_to_the_native_service() {
    let source = include_str!("../src/main.rs").replace("\r\n", "\n");

    assert!(source.contains("native_windows_tunnel_command_service()"));
    assert!(source.contains("handle_entrypoint_with_tunnel"));
    assert!(source.contains("WindowsCliCommand::TunnelStart"));
    assert!(source.contains("WindowsCliCommand::TunnelStatus"));
    assert!(source.contains("WindowsCliCommand::TunnelStop"));
    assert_eq!(
        source
            .matches("native_windows_tunnel_command_service()")
            .count(),
        1
    );
    assert_eq!(source.matches("handle_entrypoint_with_tunnel").count(), 1);
}
