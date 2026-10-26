use networkcore_windows::{
    cli_help_text, handle_entrypoint, handle_parse_error, parse_args, render_response,
    OutputFormat, WindowsCliCommand, WindowsCliExitCode, CLI_WINDOWS_ARGUMENT_UNKNOWN_CODE,
    CLI_WINDOWS_ARTIFACT_READY_CODE, CLI_WINDOWS_SYSTEM_INTEGRATION_ACTIVE_CODE, COMMAND_NAME,
    WINDOWS_CLI_SUBSCRIPTION_COMPATIBILITY_STATUS,
};
use platform_windows::{
    ReadOnlyWindowsPlatformCapabilityService, WINDOWS_ACTIVE_STATUS, WINDOWS_BLOCKED_STATUS,
    WINDOWS_CLI_ARTIFACT_GATE, WINDOWS_CLI_RELEASE_ASSETS_STATUS, WINDOWS_CLI_SOURCE_IDENTITY,
};

#[test]
fn windows_cli_help_declares_managed_client_without_a_tunnel_command() {
    let help = cli_help_text();

    assert!(help.contains("NetworkCore Windows CLI"));
    assert!(help.contains(COMMAND_NAME));
    assert!(help.contains(WINDOWS_CLI_ARTIFACT_GATE));
    assert!(help.contains(WINDOWS_CLI_SOURCE_IDENTITY));
    assert!(help.contains("system_mutation_policy: managed-apply-and-rollback"));
    assert!(help.contains("system-proxy-mutation"));
    assert!(help.contains("system-trust-store-mutation"));
    assert!(help.contains("javascript-script-dispatch"));
    assert!(!help.contains("tunnel"));
}

#[test]
fn windows_cli_capabilities_json_reports_managed_windows_integration_active() {
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
    assert!(json["capabilities"].get("foreground_tunnel").is_none());
    assert_eq!(
        json["capabilities"]["subscription_compatibility"]["status"],
        "deferred"
    );
    assert_eq!(
        json["capabilities"]["service"]["status"],
        WINDOWS_ACTIVE_STATUS
    );
    assert_eq!(
        json["capabilities"]["driver"]["status"],
        WINDOWS_ACTIVE_STATUS
    );
    assert_eq!(
        json["capabilities"]["installer"]["status"],
        WINDOWS_ACTIVE_STATUS
    );
    assert_eq!(
        json["capabilities"]["system_proxy_mutation"]["status"],
        WINDOWS_ACTIVE_STATUS
    );
    assert_eq!(
        json["capabilities"]["trust_store_mutation"]["status"],
        WINDOWS_ACTIVE_STATUS
    );
    assert_eq!(
        json["capabilities"]["https_mitm"]["status"],
        WINDOWS_ACTIVE_STATUS
    );
    assert_eq!(
        json["capabilities"]["script_dispatch"]["status"],
        WINDOWS_BLOCKED_STATUS
    );
}

#[test]
fn windows_cli_capabilities_text_lists_release_assets_and_active_lifecycle() {
    let command = parse_args(["capabilities"]).expect("valid command");
    let platform = ReadOnlyWindowsPlatformCapabilityService::new();
    let response = handle_entrypoint(command, &platform);
    let rendered = render_response(&response, OutputFormat::Text);

    let release_assets_line = format!("release_assets: {WINDOWS_CLI_RELEASE_ASSETS_STATUS}");
    assert!(rendered.contains(&release_assets_line));
    assert!(!rendered.contains("foreground_tunnel"));
    assert!(rendered.contains("driver: active"));
    assert!(rendered.contains("installer: active"));
    assert!(rendered.contains("https_mitm: active"));
    assert!(rendered.contains("managed_lifecycle: active"));
}

#[test]
fn windows_cli_status_reports_managed_lifecycle() {
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
    assert!(!rendered.contains("foreground_tunnel"));
    assert!(rendered.contains("service: active"));
    assert!(rendered.contains("driver: active"));
    assert!(rendered.contains("installer: active"));
    assert!(rendered.contains("system_proxy_mutation: active"));
    assert!(rendered.contains("trust_store_mutation: active"));
    assert!(rendered.contains("https_mitm: active"));
    assert!(rendered.contains("script_dispatch: blocked"));
    assert!(rendered.contains("managed_lifecycle: active"));
}

#[test]
fn windows_cli_diagnostics_report_artifact_and_system_integration_ready() {
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
        .any(|item| item["code"] == CLI_WINDOWS_SYSTEM_INTEGRATION_ACTIVE_CODE));
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
fn windows_cli_rejects_the_removed_tunnel_command() {
    let error = parse_args(["tunnel", "status", "state.json"]).expect_err("tunnel is removed");
    let response = handle_parse_error(error.into_diagnostic());

    assert!(!response.ok);
    assert!(
        render_response(&response, OutputFormat::Text).contains(CLI_WINDOWS_ARGUMENT_UNKNOWN_CODE)
    );
}
