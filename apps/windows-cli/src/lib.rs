//! Windows CLI entrypoint contracts for NetworkCore.
//!
//! The first Windows CLI artifact is a conservative package/publish surface. It reports
//! source identity and blocked system mutation boundaries, but it does not install services,
//! drivers, system proxy settings, trust store entries, JavaScript dispatch, or managed
//! daemon lifecycle state.

use platform_windows::{
    WindowsFeatureStatus, WindowsPlatformCapabilityService, WindowsPlatformSnapshot,
    WINDOWS_CLI_ARTIFACT_GATE, WINDOWS_CLI_PACKAGE_STATUS, WINDOWS_CLI_RELEASE_ASSETS_STATUS,
    WINDOWS_CLI_SOURCE_IDENTITY, WINDOWS_SYSTEM_MUTATION_POLICY,
};
use serde::Serialize;

pub const COMMAND_NAME: &str = "networkcore-windows";
pub const PLATFORM_NAME: &str = "windows";
pub const WINDOWS_CLI_SOURCE_CONTRACT_STATUS: &str = "active";
pub const WINDOWS_CLI_VERSION_SCOPE: &str = "v0.1.1-alpha.2";
pub const WINDOWS_CLI_SUBSCRIPTION_COMPATIBILITY_STATUS: &str = "deferred-to-v0.1.1-alpha.3";

pub const CLI_WINDOWS_ARGUMENT_UNKNOWN_CODE: &str = "cli.windows.argument.unknown";
pub const CLI_WINDOWS_ARGUMENT_VALUE_MISSING_CODE: &str = "cli.windows.argument.value_missing";
pub const CLI_WINDOWS_OUTPUT_FORMAT_UNSUPPORTED_CODE: &str =
    "cli.windows.output.format_unsupported";
pub const CLI_WINDOWS_ARTIFACT_READY_CODE: &str = "cli.windows.artifact.package_ready";
pub const CLI_WINDOWS_SYSTEM_MUTATION_BLOCKED_CODE: &str =
    "cli.windows.system_mutation.blocked";
pub const CLI_WINDOWS_SUBSCRIPTION_DEFERRED_CODE: &str =
    "cli.windows.subscription_compatibility.deferred";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

impl OutputFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsCliExitCode {
    Success,
    ArgumentOrConfig,
}

impl WindowsCliExitCode {
    pub const fn code(self) -> i32 {
        match self {
            Self::Success => 0,
            Self::ArgumentOrConfig => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsCliDiagnosticSeverity {
    Info,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WindowsCliDiagnostic {
    pub severity: WindowsCliDiagnosticSeverity,
    pub code: String,
    pub message: String,
    pub source: String,
}

impl WindowsCliDiagnostic {
    pub fn new(
        severity: WindowsCliDiagnosticSeverity,
        code: impl Into<String>,
        message: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            code: code.into(),
            message: message.into(),
            source: source.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsCliParseError {
    diagnostic: WindowsCliDiagnostic,
}

impl WindowsCliParseError {
    fn new(diagnostic: WindowsCliDiagnostic) -> Self {
        Self { diagnostic }
    }

    pub fn into_diagnostic(self) -> WindowsCliDiagnostic {
        self.diagnostic
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsCliCommand {
    Help { format: OutputFormat },
    Version { format: OutputFormat },
    Capabilities { format: OutputFormat },
    Status { format: OutputFormat },
    Diagnostics { format: OutputFormat },
}

impl WindowsCliCommand {
    pub const fn format(self) -> OutputFormat {
        match self {
            Self::Help { format }
            | Self::Version { format }
            | Self::Capabilities { format }
            | Self::Status { format }
            | Self::Diagnostics { format } => format,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Help { .. } => "help",
            Self::Version { .. } => "version",
            Self::Capabilities { .. } => "capabilities",
            Self::Status { .. } => "status",
            Self::Diagnostics { .. } => "diagnostics",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WindowsCliVersion {
    pub package: &'static str,
    pub version: &'static str,
    pub source_identity: &'static str,
    pub version_scope: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WindowsFeatureReport {
    pub name: &'static str,
    pub status: &'static str,
    pub mutation_policy: &'static str,
}

impl From<&WindowsFeatureStatus> for WindowsFeatureReport {
    fn from(status: &WindowsFeatureStatus) -> Self {
        Self {
            name: status.name,
            status: status.status,
            mutation_policy: status.mutation_policy,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WindowsCliCapabilities {
    pub command_name: &'static str,
    pub platform: &'static str,
    pub source_contract_status: &'static str,
    pub version_scope: &'static str,
    pub artifact_gate: &'static str,
    pub source_identity: &'static str,
    pub package_windows: WindowsFeatureReport,
    pub release_assets: WindowsFeatureReport,
    pub subscription_compatibility: WindowsFeatureReport,
    pub service: WindowsFeatureReport,
    pub driver: WindowsFeatureReport,
    pub installer: WindowsFeatureReport,
    pub system_proxy_mutation: WindowsFeatureReport,
    pub trust_store_mutation: WindowsFeatureReport,
    pub script_dispatch: WindowsFeatureReport,
    pub managed_lifecycle: WindowsFeatureReport,
    pub system_mutation_policy: &'static str,
}

impl WindowsCliCapabilities {
    fn from_snapshot(snapshot: &WindowsPlatformSnapshot) -> Self {
        Self {
            command_name: COMMAND_NAME,
            platform: PLATFORM_NAME,
            source_contract_status: WINDOWS_CLI_SOURCE_CONTRACT_STATUS,
            version_scope: WINDOWS_CLI_VERSION_SCOPE,
            artifact_gate: snapshot.artifact_gate,
            source_identity: snapshot.source_identity,
            package_windows: WindowsFeatureReport::from(&snapshot.package_windows),
            release_assets: WindowsFeatureReport::from(&snapshot.release_assets),
            subscription_compatibility: WindowsFeatureReport::from(
                &snapshot.subscription_compatibility,
            ),
            service: WindowsFeatureReport::from(&snapshot.service),
            driver: WindowsFeatureReport::from(&snapshot.driver),
            installer: WindowsFeatureReport::from(&snapshot.installer),
            system_proxy_mutation: WindowsFeatureReport::from(&snapshot.system_proxy_mutation),
            trust_store_mutation: WindowsFeatureReport::from(&snapshot.trust_store_mutation),
            script_dispatch: WindowsFeatureReport::from(&snapshot.script_dispatch),
            managed_lifecycle: WindowsFeatureReport::from(&snapshot.managed_lifecycle),
            system_mutation_policy: WINDOWS_SYSTEM_MUTATION_POLICY,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WindowsCliStatus {
    pub artifact_gate: &'static str,
    pub source_identity: &'static str,
    pub package_windows: &'static str,
    pub release_assets: &'static str,
    pub subscription_compatibility: &'static str,
    pub service: &'static str,
    pub driver: &'static str,
    pub installer: &'static str,
    pub system_proxy_mutation: &'static str,
    pub trust_store_mutation: &'static str,
    pub script_dispatch: &'static str,
    pub managed_lifecycle: &'static str,
    pub system_mutation_policy: &'static str,
}

impl WindowsCliStatus {
    fn from_snapshot(snapshot: &WindowsPlatformSnapshot) -> Self {
        Self {
            artifact_gate: snapshot.artifact_gate,
            source_identity: snapshot.source_identity,
            package_windows: WINDOWS_CLI_PACKAGE_STATUS,
            release_assets: WINDOWS_CLI_RELEASE_ASSETS_STATUS,
            subscription_compatibility: WINDOWS_CLI_SUBSCRIPTION_COMPATIBILITY_STATUS,
            service: snapshot.service.status,
            driver: snapshot.driver.status,
            installer: snapshot.installer.status,
            system_proxy_mutation: snapshot.system_proxy_mutation.status,
            trust_store_mutation: snapshot.trust_store_mutation.status,
            script_dispatch: snapshot.script_dispatch.status,
            managed_lifecycle: snapshot.managed_lifecycle.status,
            system_mutation_policy: WINDOWS_SYSTEM_MUTATION_POLICY,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsCliResponse {
    pub ok: bool,
    pub command: &'static str,
    pub exit_code: WindowsCliExitCode,
    pub diagnostics: Vec<WindowsCliDiagnostic>,
    pub version: Option<WindowsCliVersion>,
    pub capabilities: Option<WindowsCliCapabilities>,
    pub status: Option<WindowsCliStatus>,
}

impl WindowsCliResponse {
    fn success(command: &'static str) -> Self {
        Self {
            ok: true,
            command,
            exit_code: WindowsCliExitCode::Success,
            diagnostics: Vec::new(),
            version: None,
            capabilities: None,
            status: None,
        }
    }

    fn failure(command: &'static str, diagnostic: WindowsCliDiagnostic) -> Self {
        Self {
            ok: false,
            command,
            exit_code: WindowsCliExitCode::ArgumentOrConfig,
            diagnostics: vec![diagnostic],
            version: None,
            capabilities: None,
            status: None,
        }
    }

    fn with_version(mut self, version: WindowsCliVersion) -> Self {
        self.version = Some(version);
        self
    }

    fn with_capabilities(mut self, capabilities: WindowsCliCapabilities) -> Self {
        self.capabilities = Some(capabilities);
        self
    }

    fn with_status(mut self, status: WindowsCliStatus) -> Self {
        self.status = Some(status);
        self
    }

    fn with_diagnostics(mut self, diagnostics: Vec<WindowsCliDiagnostic>) -> Self {
        self.diagnostics = diagnostics;
        self
    }
}

pub fn parse_args<I, S>(args: I) -> Result<WindowsCliCommand, WindowsCliParseError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut values: Vec<String> = args.into_iter().map(Into::into).collect();
    let format = parse_output_format(&mut values)?;
    if values.is_empty() {
        return Ok(WindowsCliCommand::Help { format });
    }

    let command = values.remove(0);
    if !values.is_empty() {
        return Err(parse_error(
            CLI_WINDOWS_ARGUMENT_UNKNOWN_CODE,
            format!("unknown windows CLI argument: {}", values[0]),
        ));
    }

    match command.as_str() {
        "help" | "--help" | "-h" => Ok(WindowsCliCommand::Help { format }),
        "version" | "--version" | "-V" => Ok(WindowsCliCommand::Version { format }),
        "capabilities" => Ok(WindowsCliCommand::Capabilities { format }),
        "status" => Ok(WindowsCliCommand::Status { format }),
        "diagnostics" => Ok(WindowsCliCommand::Diagnostics { format }),
        unknown => Err(parse_error(
            CLI_WINDOWS_ARGUMENT_UNKNOWN_CODE,
            format!("unknown windows CLI command: {unknown}"),
        )),
    }
}

pub fn handle_entrypoint(
    command: WindowsCliCommand,
    platform: &impl WindowsPlatformCapabilityService,
) -> WindowsCliResponse {
    let snapshot = platform.snapshot();
    match command {
        WindowsCliCommand::Help { .. } => WindowsCliResponse::success(command.name()),
        WindowsCliCommand::Version { .. } => {
            WindowsCliResponse::success(command.name()).with_version(WindowsCliVersion {
                package: COMMAND_NAME,
                version: env!("CARGO_PKG_VERSION"),
                source_identity: WINDOWS_CLI_SOURCE_IDENTITY,
                version_scope: WINDOWS_CLI_VERSION_SCOPE,
            })
        }
        WindowsCliCommand::Capabilities { .. } => WindowsCliResponse::success(command.name())
            .with_capabilities(WindowsCliCapabilities::from_snapshot(&snapshot)),
        WindowsCliCommand::Status { .. } => WindowsCliResponse::success(command.name())
            .with_status(WindowsCliStatus::from_snapshot(&snapshot)),
        WindowsCliCommand::Diagnostics { .. } => WindowsCliResponse::success(command.name())
            .with_status(WindowsCliStatus::from_snapshot(&snapshot))
            .with_diagnostics(windows_cli_diagnostics(&snapshot)),
    }
}

pub fn handle_parse_error(diagnostic: WindowsCliDiagnostic) -> WindowsCliResponse {
    WindowsCliResponse::failure("parse", diagnostic)
}

pub fn render_response(response: &WindowsCliResponse, format: OutputFormat) -> String {
    match format {
        OutputFormat::Text => render_text_response(response),
        OutputFormat::Json => render_json_response(response),
    }
}

pub fn cli_help_text() -> String {
    [
        "NetworkCore Windows CLI",
        "",
        "Usage:",
        "  networkcore-windows help [--format text|json]",
        "  networkcore-windows version [--format text|json]",
        "  networkcore-windows capabilities [--format text|json]",
        "  networkcore-windows status [--format text|json]",
        "  networkcore-windows diagnostics [--format text|json]",
        "",
        "Current boundary:",
        "  artifact_gate: package-windows-active/system-mutation-blocked",
        "  source_identity: apps/windows-cli",
        "  install_model: manual-extract",
        "  system_mutation_policy: none",
        "",
        "Blocked:",
        "  windows-service, windows-driver, windows-installer, system-proxy-mutation,",
        "  system-trust-store-mutation, javascript-script-dispatch, managed-daemon-lifecycle",
    ]
    .join("\n")
}

fn parse_output_format(values: &mut Vec<String>) -> Result<OutputFormat, WindowsCliParseError> {
    let mut format = OutputFormat::Text;
    let mut index = 0;
    while index < values.len() {
        if values[index] == "--format" {
            let value = values.get(index + 1).cloned().ok_or_else(|| {
                parse_error(
                    CLI_WINDOWS_ARGUMENT_VALUE_MISSING_CODE,
                    "windows CLI --format requires text or json",
                )
            })?;
            format = match value.as_str() {
                "text" => OutputFormat::Text,
                "json" => OutputFormat::Json,
                other => {
                    return Err(parse_error(
                        CLI_WINDOWS_OUTPUT_FORMAT_UNSUPPORTED_CODE,
                        format!("unsupported windows CLI output format: {other}"),
                    ))
                }
            };
            values.remove(index);
            values.remove(index);
        } else {
            index += 1;
        }
    }
    Ok(format)
}

fn parse_error(code: impl Into<String>, message: impl Into<String>) -> WindowsCliParseError {
    WindowsCliParseError::new(WindowsCliDiagnostic::new(
        WindowsCliDiagnosticSeverity::Error,
        code,
        message,
        "cli.windows.argument",
    ))
}

fn windows_cli_diagnostics(snapshot: &WindowsPlatformSnapshot) -> Vec<WindowsCliDiagnostic> {
    vec![
        WindowsCliDiagnostic::new(
            WindowsCliDiagnosticSeverity::Info,
            CLI_WINDOWS_ARTIFACT_READY_CODE,
            format!(
                "Windows CLI source identity {} is ready for package-windows release artifacts.",
                snapshot.source_identity
            ),
            "cli.windows.artifact",
        ),
        WindowsCliDiagnostic::new(
            WindowsCliDiagnosticSeverity::Info,
            CLI_WINDOWS_SYSTEM_MUTATION_BLOCKED_CODE,
            "Windows service, driver, installer, system proxy mutation, trust store mutation, script dispatch, and managed daemon lifecycle are blocked.",
            "cli.windows.system",
        ),
        WindowsCliDiagnostic::new(
            WindowsCliDiagnosticSeverity::Info,
            CLI_WINDOWS_SUBSCRIPTION_DEFERRED_CODE,
            "Subscription compatibility remains deferred to later v0.1.1 alpha slices.",
            "cli.windows.subscription",
        ),
    ]
}

fn render_text_response(response: &WindowsCliResponse) -> String {
    if response.command == "help" && response.ok {
        return cli_help_text();
    }

    let mut lines = vec![
        format!("command: {}", response.command),
        format!("ok: {}", response.ok),
        format!("exit_code: {}", response.exit_code.code()),
    ];

    if let Some(version) = &response.version {
        lines.push(format!("package: {}", version.package));
        lines.push(format!("version: {}", version.version));
        lines.push(format!("source_identity: {}", version.source_identity));
        lines.push(format!("version_scope: {}", version.version_scope));
    }

    if let Some(capabilities) = &response.capabilities {
        lines.push(format!("platform: {}", capabilities.platform));
        lines.push(format!("artifact_gate: {}", capabilities.artifact_gate));
        lines.push(format!("source_identity: {}", capabilities.source_identity));
        lines.push(format!(
            "package_windows: {}",
            capabilities.package_windows.status
        ));
        lines.push(format!(
            "release_assets: {}",
            WINDOWS_CLI_RELEASE_ASSETS_STATUS
        ));
        lines.push(format!(
            "subscription_compatibility: {}",
            WINDOWS_CLI_SUBSCRIPTION_COMPATIBILITY_STATUS
        ));
        lines.push(format!("service: {}", capabilities.service.status));
        lines.push(format!("driver: {}", capabilities.driver.status));
        lines.push(format!("installer: {}", capabilities.installer.status));
        lines.push(format!(
            "system_proxy_mutation: {}",
            capabilities.system_proxy_mutation.status
        ));
        lines.push(format!(
            "trust_store_mutation: {}",
            capabilities.trust_store_mutation.status
        ));
        lines.push(format!(
            "script_dispatch: {}",
            capabilities.script_dispatch.status
        ));
        lines.push(format!(
            "managed_lifecycle: {}",
            capabilities.managed_lifecycle.status
        ));
        lines.push(format!(
            "system_mutation_policy: {}",
            capabilities.system_mutation_policy
        ));
    }

    if let Some(status) = &response.status {
        lines.push(format!("artifact_gate: {}", status.artifact_gate));
        lines.push(format!("source_identity: {}", status.source_identity));
        lines.push(format!("package_windows: {}", status.package_windows));
        lines.push(format!("release_assets: {}", status.release_assets));
        lines.push(format!(
            "subscription_compatibility: {}",
            status.subscription_compatibility
        ));
        lines.push(format!("service: {}", status.service));
        lines.push(format!("driver: {}", status.driver));
        lines.push(format!("installer: {}", status.installer));
        lines.push(format!(
            "system_proxy_mutation: {}",
            status.system_proxy_mutation
        ));
        lines.push(format!(
            "trust_store_mutation: {}",
            status.trust_store_mutation
        ));
        lines.push(format!("script_dispatch: {}", status.script_dispatch));
        lines.push(format!("managed_lifecycle: {}", status.managed_lifecycle));
        lines.push(format!(
            "system_mutation_policy: {}",
            status.system_mutation_policy
        ));
    }

    if !response.diagnostics.is_empty() {
        lines.push("diagnostics:".to_string());
        for diagnostic in &response.diagnostics {
            lines.push(format!(
                "- {:?} {}: {}",
                diagnostic.severity, diagnostic.code, diagnostic.message
            ));
        }
    }

    lines.join("\n")
}

#[derive(Serialize)]
struct JsonWindowsCliResponse<'a> {
    ok: bool,
    command: &'a str,
    exit_code: i32,
    diagnostics: &'a [WindowsCliDiagnostic],
    version: Option<&'a WindowsCliVersion>,
    capabilities: Option<&'a WindowsCliCapabilities>,
    status: Option<&'a WindowsCliStatus>,
}

impl<'a> From<&'a WindowsCliResponse> for JsonWindowsCliResponse<'a> {
    fn from(response: &'a WindowsCliResponse) -> Self {
        Self {
            ok: response.ok,
            command: response.command,
            exit_code: response.exit_code.code(),
            diagnostics: &response.diagnostics,
            version: response.version.as_ref(),
            capabilities: response.capabilities.as_ref(),
            status: response.status.as_ref(),
        }
    }
}

fn render_json_response(response: &WindowsCliResponse) -> String {
    serde_json::to_string_pretty(&JsonWindowsCliResponse::from(response))
        .expect("windows CLI response JSON serialization should be infallible")
}
