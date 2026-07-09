use networkcore_windows::{
    cli_help_text, handle_entrypoint, handle_parse_error, parse_args, render_response,
    OutputFormat, WindowsCliCommand, WindowsCliExitCode, CLI_WINDOWS_ARGUMENT_UNKNOWN_CODE,
    CLI_WINDOWS_ARTIFACT_READY_CODE, CLI_WINDOWS_SYSTEM_MUTATION_BLOCKED_CODE,
    COMMAND_NAME, WINDOWS_CLI_SUBSCRIPTION_COMPATIBILITY_STATUS,
};
use platform_windows::{
    ReadOnlyWindowsPlatformCapabilityService, WINDOWS_ACTIVE_STATUS, WINDOWS_BLOCKED_STATUS,
    WINDOWS_CLI_ARTIFACT_GATE, WINDOWS_CLI_RELEASE_ASSETS_STATUS, WINDOWS_CLI_SOURCE_IDENTITY,
};

#[test]
fn windows_cli_help_declares_package_boundary_without_system_mutation() {
    let help = cli_help_text();

    assert!(help.contains("NetworkCore Windows CLI"));
    assert!(help.contains(COMMAND_NAME));
    assert!(help.contains(WINDOWS_CLI_ARTIFACT_GATE));
    assert!(help.contains(WINDOWS_CLI_SOURCE_IDENTITY));
    assert!(help.contains("system_mutation_policy: none"));
    assert!(help.contains("system-proxy-mutation"));
    assert!(help.contains("system-trust-store-mutation"));
    assert!(help.contains("javascript-script-dispatch"));
}

#[test]
fn windows_cli_capabilities_json_reports_package_active_and_mutations_blocked() {
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
        json["capabilities"]["subscription_compatibility"]["status"],
        "deferred"
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
    assert!(rendered.contains("driver: blocked"));
    assert!(rendered.contains("installer: blocked"));
    assert!(rendered.contains("managed_lifecycle: blocked"));
}

#[test]
fn windows_cli_status_keeps_subscription_and_system_mutation_out_of_alpha2() {
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
