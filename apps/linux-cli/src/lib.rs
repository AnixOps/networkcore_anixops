//! Linux CLI entrypoint contracts for NetworkCore.
//!
//! The crate contains command parsing, response mapping, config I/O boundaries,
//! and foreground runtime handoff. Daemon control, service installation, and
//! release packaging are deliberately outside this first source increment.

use config_core::CoreSubscriptionService;
use control_domain::{
    CertificateTrustState, ConfigurationService, Diagnostic, DiagnosticSeverity, DomainError,
    DomainResult, GrantedPermissions, MitmPluginService, OperatingSystem,
    PlatformCapabilityService, PlatformCapabilityStatus, PlatformFeatureState, ProxyEngineConfig,
    ProxyEngineDescriptor, ProxyEngineEvent, ProxyEngineLifecycleState, ProxyEngineService,
    ProxyEngineStatus, RawSubscription, SubscriptionService,
};
use control_runtime::{RuntimeConfigRequest, RuntimeOperationResult, RuntimeOrchestrator};
use engine_singbox::{
    default_sing_box_install_root, render_sing_box_local_proxy_config, SingBoxInstallReport,
    SingBoxInstallRequest, SingBoxLocalProxyConfigRequest, SingBoxProcessRunRequest,
    SingBoxProcessRunner, SingBoxReleaseInstaller, SingBoxTarget,
};
use mitm_policy::{
    builtin_ad_block_plugin_package, AnixOpsMitmPluginService, AnixOpsMitmPolicyEngine,
    MITM_POLICY_AD_BLOCK_PLUGIN_ID,
};
use serde::Serialize;
#[cfg(unix)]
use signal_hook::{
    consts::signal::{SIGINT, SIGTERM},
    iterator::Signals,
};
use std::thread;

pub const COMMAND_NAME: &str = "networkcore-linux";
pub const DEFAULT_ENGINE_ID: &str = "native";

pub const CLI_COMMAND_MISSING_CODE: &str = "cli.linux.command.missing";
pub const CLI_ARGUMENT_UNKNOWN_CODE: &str = "cli.linux.argument.unknown";
pub const CLI_ARGUMENT_VALUE_MISSING_CODE: &str = "cli.linux.argument.value_missing";
pub const CLI_OUTPUT_FORMAT_UNSUPPORTED_CODE: &str = "cli.linux.output.format_unsupported";
pub const CLI_CONFIG_PATH_MISSING_CODE: &str = "cli.linux.config.path_missing";
pub const CLI_CONFIG_READ_FAILED_CODE: &str = "cli.linux.config.read_failed";
pub const CLI_CONFIG_EMPTY_CODE: &str = "cli.linux.config.empty";
pub const CLI_START_PLATFORM_DENIED_CODE: &str = "cli.linux.start.platform_denied";
pub const CLI_START_CONFIG_DENIED_CODE: &str = "cli.linux.start.config_denied";
pub const CLI_START_ENGINE_DENIED_CODE: &str = "cli.linux.start.engine_denied";
pub const CLI_START_FOREGROUND_ONLY_CODE: &str = "cli.linux.start.foreground_only";
pub const CLI_START_LIFECYCLE_HOST_MISSING_CODE: &str = "cli.linux.start.lifecycle_host_missing";
pub const CLI_START_LIFECYCLE_INTERRUPTED_CODE: &str = "cli.linux.start.lifecycle_interrupted";
pub const CLI_START_LIFECYCLE_FAILED_CODE: &str = "cli.linux.start.lifecycle_failed";
pub const CLI_START_RUNTIME_STOP_FAILED_CODE: &str = "cli.linux.start.runtime_stop_failed";
pub const CLI_START_SIGNAL_RECEIVED_CODE: &str = "cli.linux.start.signal_received";
pub const CLI_START_SIGNAL_SOURCE_FAILED_CODE: &str = "cli.linux.start.signal_source_failed";
pub const CLI_STOP_UNAVAILABLE_WITHOUT_DAEMON_CODE: &str =
    "cli.linux.stop.unavailable_without_daemon";
pub const CLI_STATUS_NO_RUNTIME_CONTEXT_CODE: &str = "cli.linux.status.no_runtime_context";
pub const CLI_STATUS_PLATFORM_ONLY_CODE: &str = "cli.linux.status.platform_only";
pub const CLI_RUNTIME_UNWIRED_CODE: &str = "cli.linux.runtime.unwired";
pub const CLI_SING_BOX_INSTALL_FAILED_CODE: &str = "cli.linux.sing_box.install_failed";
pub const CLI_RUN_URL_PARSE_FAILED_CODE: &str = "cli.linux.run_url.parse_failed";
pub const CLI_RUN_URL_CONFIG_FAILED_CODE: &str = "cli.linux.run_url.config_failed";
pub const CLI_RUN_URL_CONFIG_WRITE_FAILED_CODE: &str = "cli.linux.run_url.config_write_failed";
pub const CLI_RUN_URL_PROCESS_FAILED_CODE: &str = "cli.linux.run_url.process_failed";
pub const CLI_MITM_POLICY_READY_CODE: &str = "cli.linux.mitm.policy_ready";
pub const CLI_MITM_CLI_GATE_PARTIAL_CODE: &str = "cli.linux.mitm.cli_gate.partial";
pub const CLI_MITM_CERTIFICATE_GATE_DEFERRED_CODE: &str =
    "cli.linux.mitm.certificate_gate.deferred";
pub const CLI_MITM_DATA_PLANE_GATE_DEFERRED_CODE: &str = "cli.linux.mitm.data_plane_gate.deferred";
pub const CLI_MITM_BROWSER_HIJACK_DEFERRED_CODE: &str = "cli.linux.mitm.browser_hijack.deferred";

pub const MITM_CLI_COMMAND_GATE: &str = "MITM_CLI_COMMAND_GATE";
pub const MITM_CERTIFICATE_LIFECYCLE_GATE: &str = "MITM_CERTIFICATE_LIFECYCLE_GATE";
pub const MITM_HTTP_TLS_DATA_PLANE_GATE: &str = "MITM_HTTP_TLS_DATA_PLANE_GATE";
pub const MITM_CLI_COMMAND_GATE_STATUS: &str = "partial-active";
pub const MITM_CERTIFICATE_LIFECYCLE_GATE_STATUS: &str = "blocked";
pub const MITM_HTTP_TLS_DATA_PLANE_GATE_STATUS: &str = "blocked";
pub const MITM_BROWSER_HIJACK_STATUS: &str = "deferred";
pub const MITM_USER_FACING_STAGE: &str = "policy-only";
pub const MITM_USER_FACING_READY: bool = false;

pub const SOURCE_CLI_ARGUMENT: &str = "cli.argument";
pub const SOURCE_CLI_CONFIG: &str = "cli.config";
pub const SOURCE_CLI_HELP: &str = "cli.help";
pub const SOURCE_CLI_MITM: &str = "cli.mitm";
pub const SOURCE_CLI_SING_BOX: &str = "cli.sing_box";
pub const SOURCE_CLI_START: &str = "cli.start";
pub const SOURCE_CLI_STOP: &str = "cli.stop";
pub const SOURCE_CLI_STATUS: &str = "cli.status";
pub const SOURCE_CLI_RUNTIME: &str = "cli.runtime";

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
pub enum LinuxCliExitCode {
    Success,
    GeneralFailure,
    ArgumentOrConfig,
    ConfigValidation,
    PlatformDenied,
    EngineDenied,
    Unavailable,
    Interrupted,
}

impl LinuxCliExitCode {
    pub const fn code(self) -> i32 {
        match self {
            Self::Success => 0,
            Self::GeneralFailure => 1,
            Self::ArgumentOrConfig => 2,
            Self::ConfigValidation => 3,
            Self::PlatformDenied => 4,
            Self::EngineDenied => 5,
            Self::Unavailable => 6,
            Self::Interrupted => 130,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinuxCliCommand {
    Help {
        format: OutputFormat,
    },
    Version {
        format: OutputFormat,
    },
    Capabilities {
        format: OutputFormat,
    },
    PrepareConfig {
        config_path: Option<String>,
        format: OutputFormat,
    },
    Start {
        config_path: Option<String>,
        format: OutputFormat,
    },
    Stop {
        format: OutputFormat,
    },
    Status {
        format: OutputFormat,
    },
    Diagnostics {
        format: OutputFormat,
    },
    MitmStatus {
        format: OutputFormat,
    },
    MitmDiagnostics {
        format: OutputFormat,
    },
    InstallSingBox {
        install_dir: Option<String>,
        force: bool,
        format: OutputFormat,
    },
    RunUrl {
        url: String,
        listen_host: String,
        listen_port: u16,
        install_dir: Option<String>,
        force: bool,
        format: OutputFormat,
    },
}

impl LinuxCliCommand {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Help { .. } => "help",
            Self::Version { .. } => "version",
            Self::Capabilities { .. } => "capabilities",
            Self::PrepareConfig { .. } => "prepare-config",
            Self::Start { .. } => "start",
            Self::Stop { .. } => "stop",
            Self::Status { .. } => "status",
            Self::Diagnostics { .. } => "diagnostics",
            Self::MitmStatus { .. } => "mitm status",
            Self::MitmDiagnostics { .. } => "mitm diagnostics",
            Self::InstallSingBox { .. } => "install-sing-box",
            Self::RunUrl { .. } => "run-url",
        }
    }

    pub const fn format(&self) -> OutputFormat {
        match self {
            Self::Help { format }
            | Self::Version { format }
            | Self::Capabilities { format }
            | Self::PrepareConfig { format, .. }
            | Self::Start { format, .. }
            | Self::Stop { format }
            | Self::Status { format }
            | Self::Diagnostics { format }
            | Self::MitmStatus { format }
            | Self::MitmDiagnostics { format }
            | Self::InstallSingBox { format, .. }
            | Self::RunUrl { format, .. } => *format,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxCliParseError {
    diagnostic: Box<Diagnostic>,
}

impl LinuxCliParseError {
    pub fn new(diagnostic: Diagnostic) -> Self {
        Self {
            diagnostic: Box::new(diagnostic),
        }
    }

    pub fn diagnostic(&self) -> &Diagnostic {
        self.diagnostic.as_ref()
    }

    pub fn into_diagnostic(self) -> Diagnostic {
        *self.diagnostic
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxCliResponse {
    pub ok: bool,
    pub command: String,
    pub exit_code: LinuxCliExitCode,
    pub diagnostics: Vec<Diagnostic>,
    pub platform: Option<PlatformCapabilityStatus>,
    pub config_profiles: Vec<String>,
    pub version: Option<String>,
    pub help: Option<String>,
    pub sing_box_install: Option<LinuxSingBoxInstallStatus>,
    pub sing_box_run: Option<LinuxSingBoxRunStatus>,
    pub mitm_status: Option<LinuxMitmStatus>,
}

impl LinuxCliResponse {
    pub fn success(command: impl Into<String>) -> Self {
        Self {
            ok: true,
            command: command.into(),
            exit_code: LinuxCliExitCode::Success,
            diagnostics: Vec::new(),
            platform: None,
            config_profiles: Vec::new(),
            version: None,
            help: None,
            sing_box_install: None,
            sing_box_run: None,
            mitm_status: None,
        }
    }

    pub fn failure(
        command: impl Into<String>,
        exit_code: LinuxCliExitCode,
        diagnostic: Diagnostic,
    ) -> Self {
        Self {
            ok: false,
            command: command.into(),
            exit_code,
            diagnostics: vec![diagnostic],
            platform: None,
            config_profiles: Vec::new(),
            version: None,
            help: None,
            sing_box_install: None,
            sing_box_run: None,
            mitm_status: None,
        }
    }

    pub fn with_platform(mut self, platform: PlatformCapabilityStatus) -> Self {
        self.platform = Some(platform);
        self
    }

    pub fn with_config_profiles(mut self, profiles: Vec<String>) -> Self {
        self.config_profiles = profiles;
        self
    }

    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    pub fn with_sing_box_install(mut self, install: LinuxSingBoxInstallStatus) -> Self {
        self.sing_box_install = Some(install);
        self
    }

    pub fn with_sing_box_run(mut self, run: LinuxSingBoxRunStatus) -> Self {
        self.sing_box_run = Some(run);
        self
    }

    pub fn with_mitm_status(mut self, status: LinuxMitmStatus) -> Self {
        self.mitm_status = Some(status);
        self
    }

    pub fn with_diagnostics(mut self, diagnostics: Vec<Diagnostic>) -> Self {
        self.diagnostics = diagnostics;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxSingBoxInstallStatus {
    pub version: String,
    pub target: String,
    pub asset_name: String,
    pub asset_url: String,
    pub asset_sha256: Option<String>,
    pub archive_path: String,
    pub executable_path: String,
    pub downloaded: bool,
}

impl From<SingBoxInstallReport> for LinuxSingBoxInstallStatus {
    fn from(report: SingBoxInstallReport) -> Self {
        Self {
            version: report.version,
            target: report.target.directory_name(),
            asset_name: report.asset_name,
            asset_url: report.asset_url,
            asset_sha256: report.asset_sha256,
            archive_path: report.archive_path.display().to_string(),
            executable_path: report.executable_path.display().to_string(),
            downloaded: report.downloaded,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxSingBoxRunStatus {
    pub node_id: String,
    pub node_name: String,
    pub listen_host: String,
    pub listen_port: u16,
    pub executable_path: String,
    pub config_path: String,
    pub process_exit_code: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmStatus {
    pub stage: String,
    pub user_facing_ready: bool,
    pub browser_hijack: String,
    pub platform_mitm_available: bool,
    pub certificate_state: String,
    pub policy: LinuxMitmPolicyStatus,
    pub gates: Vec<LinuxMitmGateStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmPolicyStatus {
    pub engine: String,
    pub engine_version: String,
    pub plugin_id: String,
    pub plugin_version: String,
    pub plugin_loaded: bool,
    pub mitm_pattern_count: usize,
    pub rewrite_rule_count: usize,
    pub script_rule_count: usize,
    pub argument_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmGateStatus {
    pub gate: String,
    pub status: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigReadError {
    pub message: String,
}

impl ConfigReadError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

pub trait ConfigReader {
    fn read_config(&self, path: &str) -> Result<String, ConfigReadError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FsConfigReader;

impl ConfigReader for FsConfigReader {
    fn read_config(&self, path: &str) -> Result<String, ConfigReadError> {
        std::fs::read_to_string(path).map_err(|error| ConfigReadError::new(error.to_string()))
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableProxyEngineService;

impl UnavailableProxyEngineService {
    pub const fn new() -> Self {
        Self
    }
}

impl ProxyEngineService for UnavailableProxyEngineService {
    fn list_engines(&self) -> Vec<ProxyEngineDescriptor> {
        Vec::new()
    }

    fn validate_config(&self, _engine_config: &ProxyEngineConfig) -> Vec<Diagnostic> {
        vec![cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_RUNTIME_UNWIRED_CODE,
            "linux proxy engine adapter is not wired",
            SOURCE_CLI_RUNTIME,
        )]
    }

    fn start(&self, _engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
        Err(unavailable_engine_error())
    }

    fn reload(&self, _engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
        Err(unavailable_engine_error())
    }

    fn stop(&self, _engine_id: &str) -> DomainResult<ProxyEngineStatus> {
        Err(unavailable_engine_error())
    }

    fn status(&self, _engine_id: &str) -> DomainResult<ProxyEngineStatus> {
        Err(unavailable_engine_error())
    }

    fn events(&self, _engine_id: &str) -> DomainResult<Vec<ProxyEngineEvent>> {
        Err(unavailable_engine_error())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForegroundLifecycleRequest {
    pub engine_status: ProxyEngineStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForegroundLifecycleOutcome {
    pub exit_code: LinuxCliExitCode,
    pub diagnostics: Vec<Diagnostic>,
}

impl ForegroundLifecycleOutcome {
    pub fn success(diagnostics: Vec<Diagnostic>) -> Self {
        Self {
            exit_code: LinuxCliExitCode::Success,
            diagnostics,
        }
    }

    pub fn failure(exit_code: LinuxCliExitCode, diagnostic: Diagnostic) -> Self {
        Self {
            exit_code,
            diagnostics: vec![diagnostic],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForegroundLifecycleInterruption {
    pub reason: String,
    pub diagnostics: Vec<Diagnostic>,
}

impl ForegroundLifecycleInterruption {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            diagnostics: Vec::new(),
        }
    }

    pub fn with_diagnostics(mut self, diagnostics: Vec<Diagnostic>) -> Self {
        self.diagnostics = diagnostics;
        self
    }
}

pub trait ForegroundLifecycleHost {
    fn run_foreground(&self, request: &ForegroundLifecycleRequest) -> ForegroundLifecycleOutcome;
}

pub trait ForegroundLifecycleInterruptionSource {
    fn wait_for_interruption(
        &self,
        request: &ForegroundLifecycleRequest,
    ) -> ForegroundLifecycleInterruption;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableForegroundLifecycleHost;

impl UnavailableForegroundLifecycleHost {
    pub const fn new() -> Self {
        Self
    }
}

impl ForegroundLifecycleHost for UnavailableForegroundLifecycleHost {
    fn run_foreground(&self, _request: &ForegroundLifecycleRequest) -> ForegroundLifecycleOutcome {
        ForegroundLifecycleOutcome::failure(
            LinuxCliExitCode::Unavailable,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_START_LIFECYCLE_HOST_MISSING_CODE,
                "linux foreground lifecycle host is not wired",
                SOURCE_CLI_START,
            ),
        )
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ParkingForegroundLifecycleInterruptionSource;

impl ParkingForegroundLifecycleInterruptionSource {
    pub const fn new() -> Self {
        Self
    }
}

impl ForegroundLifecycleInterruptionSource for ParkingForegroundLifecycleInterruptionSource {
    fn wait_for_interruption(
        &self,
        _request: &ForegroundLifecycleRequest,
    ) -> ForegroundLifecycleInterruption {
        loop {
            thread::park();
        }
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, Default)]
pub struct OsSignalForegroundLifecycleInterruptionSource;

#[cfg(unix)]
impl OsSignalForegroundLifecycleInterruptionSource {
    pub const fn new() -> Self {
        Self
    }

    pub fn interruption_for_signal(signal: i32) -> ForegroundLifecycleInterruption {
        foreground_os_signal_interruption(signal)
    }
}

#[cfg(unix)]
impl ForegroundLifecycleInterruptionSource for OsSignalForegroundLifecycleInterruptionSource {
    fn wait_for_interruption(
        &self,
        _request: &ForegroundLifecycleRequest,
    ) -> ForegroundLifecycleInterruption {
        let mut signals = match Signals::new([SIGINT, SIGTERM]) {
            Ok(signals) => signals,
            Err(error) => {
                return ForegroundLifecycleInterruption::new("os-signal-source-failed")
                    .with_diagnostics(vec![cli_diagnostic(
                        DiagnosticSeverity::Error,
                        CLI_START_SIGNAL_SOURCE_FAILED_CODE,
                        format!("failed to register foreground OS signal source: {error}"),
                        SOURCE_CLI_START,
                    )]);
            }
        };

        if let Some(signal) = signals.forever().next() {
            return Self::interruption_for_signal(signal);
        }

        ForegroundLifecycleInterruption::new("os-signal-source-closed").with_diagnostics(vec![
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_START_SIGNAL_SOURCE_FAILED_CODE,
                "foreground OS signal source closed before receiving an interruption",
                SOURCE_CLI_START,
            ),
        ])
    }
}

#[cfg(unix)]
pub type DefaultForegroundLifecycleInterruptionSource =
    OsSignalForegroundLifecycleInterruptionSource;

#[cfg(not(unix))]
pub type DefaultForegroundLifecycleInterruptionSource =
    ParkingForegroundLifecycleInterruptionSource;

#[derive(Debug, Clone, Copy, Default)]
pub struct CurrentProcessForegroundLifecycleHost<I = DefaultForegroundLifecycleInterruptionSource> {
    interruption_source: I,
}

impl CurrentProcessForegroundLifecycleHost<DefaultForegroundLifecycleInterruptionSource> {
    pub const fn new() -> Self {
        Self {
            interruption_source: DefaultForegroundLifecycleInterruptionSource::new(),
        }
    }
}

impl<I> CurrentProcessForegroundLifecycleHost<I> {
    pub const fn with_interruption_source(interruption_source: I) -> Self {
        Self {
            interruption_source,
        }
    }
}

impl<I> ForegroundLifecycleHost for CurrentProcessForegroundLifecycleHost<I>
where
    I: ForegroundLifecycleInterruptionSource,
{
    fn run_foreground(&self, request: &ForegroundLifecycleRequest) -> ForegroundLifecycleOutcome {
        let interruption = self.interruption_source.wait_for_interruption(request);
        let mut diagnostics = interruption.diagnostics;
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Warning,
            CLI_START_LIFECYCLE_INTERRUPTED_CODE,
            format!(
                "linux foreground runtime was interrupted: {}",
                interruption.reason
            ),
            SOURCE_CLI_START,
        ));

        ForegroundLifecycleOutcome {
            exit_code: LinuxCliExitCode::Interrupted,
            diagnostics,
        }
    }
}

#[cfg(unix)]
fn foreground_os_signal_interruption(signal: i32) -> ForegroundLifecycleInterruption {
    let signal_name = foreground_os_signal_name(signal);

    ForegroundLifecycleInterruption::new(signal_name.clone()).with_diagnostics(vec![
        cli_diagnostic(
            DiagnosticSeverity::Warning,
            CLI_START_SIGNAL_RECEIVED_CODE,
            format!("foreground OS signal {signal_name} interrupted linux runtime"),
            SOURCE_CLI_START,
        ),
    ])
}

#[cfg(unix)]
fn foreground_os_signal_name(signal: i32) -> String {
    match signal {
        SIGINT => "SIGINT".to_string(),
        SIGTERM => "SIGTERM".to_string(),
        _ => format!("signal-{signal}"),
    }
}

#[derive(Debug, Default)]
struct ParsedOptions {
    config_path: Option<String>,
    install_dir: Option<String>,
    listen_host: Option<String>,
    listen_port: Option<u16>,
    force: bool,
    format: OutputFormat,
}

pub fn parse_args<I, S>(args: I) -> Result<LinuxCliCommand, LinuxCliParseError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut args = args.into_iter().map(Into::into);
    let Some(command) = args.next() else {
        return Err(parse_error(
            CLI_COMMAND_MISSING_CODE,
            "missing linux CLI command; run networkcore-linux help",
        ));
    };
    let rest = args.collect::<Vec<_>>();

    match command.as_str() {
        "help" | "--help" | "-h" => {
            let options = parse_options(&rest)?;
            Ok(LinuxCliCommand::Help {
                format: options.format,
            })
        }
        "version" => {
            let options = parse_options(&rest)?;
            Ok(LinuxCliCommand::Version {
                format: options.format,
            })
        }
        "capabilities" => {
            let options = parse_options(&rest)?;
            Ok(LinuxCliCommand::Capabilities {
                format: options.format,
            })
        }
        "prepare-config" => {
            let options = parse_options(&rest)?;
            Ok(LinuxCliCommand::PrepareConfig {
                config_path: options.config_path,
                format: options.format,
            })
        }
        "start" => {
            let options = parse_options(&rest)?;
            Ok(LinuxCliCommand::Start {
                config_path: options.config_path,
                format: options.format,
            })
        }
        "stop" => {
            let options = parse_options(&rest)?;
            Ok(LinuxCliCommand::Stop {
                format: options.format,
            })
        }
        "status" => {
            let options = parse_options(&rest)?;
            Ok(LinuxCliCommand::Status {
                format: options.format,
            })
        }
        "diagnostics" => {
            let options = parse_options(&rest)?;
            Ok(LinuxCliCommand::Diagnostics {
                format: options.format,
            })
        }
        "mitm" => parse_mitm_command(&rest),
        "install-sing-box" | "install-singbox" => {
            let options = parse_options(&rest)?;
            Ok(LinuxCliCommand::InstallSingBox {
                install_dir: options.install_dir,
                force: options.force,
                format: options.format,
            })
        }
        "run-url" => parse_run_url_command(&rest),
        "sing-box" => parse_sing_box_command(&rest),
        _ => Err(parse_error(
            CLI_ARGUMENT_UNKNOWN_CODE,
            format!("unknown linux CLI command: {command}; run networkcore-linux help"),
        )),
    }
}

pub fn handle_parse_error(diagnostic: Diagnostic) -> LinuxCliResponse {
    let show_help = diagnostic.code == CLI_COMMAND_MISSING_CODE
        || diagnostic.code == CLI_ARGUMENT_UNKNOWN_CODE
        || diagnostic.code == CLI_OUTPUT_FORMAT_UNSUPPORTED_CODE;
    let response =
        LinuxCliResponse::failure("parse", LinuxCliExitCode::ArgumentOrConfig, diagnostic);
    if show_help {
        response.with_help(cli_help_text())
    } else {
        response
    }
}

pub fn handle_entrypoint_skeleton(command: LinuxCliCommand) -> LinuxCliResponse {
    match command {
        LinuxCliCommand::Help { .. } => handle_help(),
        LinuxCliCommand::Version { .. } => handle_version(),
        LinuxCliCommand::Stop { .. } => handle_stop(),
        other => handle_unwired_command(other.name()),
    }
}

pub fn handle_entrypoint<P>(command: LinuxCliCommand, platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    match command {
        LinuxCliCommand::Help { .. } => handle_help(),
        LinuxCliCommand::Version { .. } => handle_version(),
        LinuxCliCommand::Capabilities { .. } => handle_capabilities(platform),
        LinuxCliCommand::Status { .. } => handle_status(platform),
        LinuxCliCommand::Diagnostics { .. } => handle_diagnostics(platform),
        LinuxCliCommand::MitmStatus { .. } => handle_mitm_status(platform),
        LinuxCliCommand::MitmDiagnostics { .. } => handle_mitm_diagnostics(platform),
        LinuxCliCommand::Stop { .. } => handle_stop(),
        other => handle_unwired_command(other.name()),
    }
}

pub fn handle_entrypoint_with_runtime<C, P, E, R>(
    command: LinuxCliCommand,
    platform: &P,
    orchestrator: &RuntimeOrchestrator<C, P, E>,
    reader: &R,
) -> LinuxCliResponse
where
    C: ConfigurationService,
    P: PlatformCapabilityService,
    E: ProxyEngineService,
    R: ConfigReader,
{
    match command {
        LinuxCliCommand::PrepareConfig { config_path, .. } => {
            handle_prepare_config(orchestrator, reader, config_path.as_deref())
        }
        other => handle_entrypoint(other, platform),
    }
}

pub fn handle_entrypoint_with_runtime_and_lifecycle<C, P, E, R, H>(
    command: LinuxCliCommand,
    platform: &P,
    orchestrator: &RuntimeOrchestrator<C, P, E>,
    reader: &R,
    lifecycle_host: &H,
) -> LinuxCliResponse
where
    C: ConfigurationService,
    P: PlatformCapabilityService,
    E: ProxyEngineService,
    R: ConfigReader,
    H: ForegroundLifecycleHost,
{
    match command {
        LinuxCliCommand::PrepareConfig { config_path, .. } => {
            handle_prepare_config(orchestrator, reader, config_path.as_deref())
        }
        LinuxCliCommand::Start { config_path, .. } => {
            handle_start_foreground(orchestrator, reader, config_path.as_deref(), lifecycle_host)
        }
        other => handle_entrypoint(other, platform),
    }
}

pub fn handle_entrypoint_with_runtime_lifecycle_and_sing_box<C, P, E, R, H, I, S>(
    command: LinuxCliCommand,
    platform: &P,
    orchestrator: &RuntimeOrchestrator<C, P, E>,
    reader: &R,
    lifecycle_host: &H,
    sing_box_installer: &I,
    sing_box_runner: &S,
) -> LinuxCliResponse
where
    C: ConfigurationService,
    P: PlatformCapabilityService,
    E: ProxyEngineService,
    R: ConfigReader,
    H: ForegroundLifecycleHost,
    I: SingBoxReleaseInstaller,
    S: SingBoxProcessRunner,
{
    match command {
        LinuxCliCommand::InstallSingBox {
            install_dir, force, ..
        } => handle_install_sing_box(sing_box_installer, install_dir.as_deref(), force),
        LinuxCliCommand::RunUrl {
            url,
            listen_host,
            listen_port,
            install_dir,
            force,
            ..
        } => handle_run_url_with_sing_box(
            sing_box_installer,
            sing_box_runner,
            &url,
            &listen_host,
            listen_port,
            install_dir.as_deref(),
            force,
        ),
        other => handle_entrypoint_with_runtime_and_lifecycle(
            other,
            platform,
            orchestrator,
            reader,
            lifecycle_host,
        ),
    }
}

pub fn handle_help() -> LinuxCliResponse {
    LinuxCliResponse::success("help").with_help(cli_help_text())
}

pub fn handle_version() -> LinuxCliResponse {
    LinuxCliResponse::success("version").with_version(env!("CARGO_PKG_VERSION"))
}

pub fn handle_capabilities<P>(platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    match platform.status() {
        Ok(status) => {
            let diagnostics = platform_diagnostics(&status);
            LinuxCliResponse::success("capabilities")
                .with_diagnostics(diagnostics)
                .with_platform(status)
        }
        Err(error) => domain_error_response(
            "capabilities",
            LinuxCliExitCode::GeneralFailure,
            error,
            SOURCE_CLI_RUNTIME,
        ),
    }
}

pub fn handle_prepare_config<C, P, E, R>(
    orchestrator: &RuntimeOrchestrator<C, P, E>,
    reader: &R,
    config_path: Option<&str>,
) -> LinuxCliResponse
where
    C: ConfigurationService,
    P: PlatformCapabilityService,
    E: ProxyEngineService,
    R: ConfigReader,
{
    let raw_config = match read_required_config("prepare-config", reader, config_path) {
        Ok(raw_config) => raw_config,
        Err(response) => return *response,
    };

    match orchestrator.prepare_config(&raw_config) {
        Ok(prepared) => LinuxCliResponse::success("prepare-config")
            .with_diagnostics(prepared.diagnostics)
            .with_platform(prepared.platform)
            .with_config_profiles(prepared.config.profiles),
        Err(error) => domain_error_response(
            "prepare-config",
            LinuxCliExitCode::ConfigValidation,
            error,
            SOURCE_CLI_CONFIG,
        ),
    }
}

pub fn handle_start<C, P, E, R>(
    orchestrator: &RuntimeOrchestrator<C, P, E>,
    reader: &R,
    config_path: Option<&str>,
) -> LinuxCliResponse
where
    C: ConfigurationService,
    P: PlatformCapabilityService,
    E: ProxyEngineService,
    R: ConfigReader,
{
    let raw_config = match read_required_config("start", reader, config_path) {
        Ok(raw_config) => raw_config,
        Err(response) => return *response,
    };

    let request = RuntimeConfigRequest::new(DEFAULT_ENGINE_ID, raw_config);
    match orchestrator.start_runtime(request) {
        Ok(result) => LinuxCliResponse::success("start")
            .with_diagnostics(result.diagnostics)
            .with_platform(result.platform),
        Err(error) => start_error_response(error),
    }
}

pub fn handle_start_foreground<C, P, E, R, H>(
    orchestrator: &RuntimeOrchestrator<C, P, E>,
    reader: &R,
    config_path: Option<&str>,
    lifecycle_host: &H,
) -> LinuxCliResponse
where
    C: ConfigurationService,
    P: PlatformCapabilityService,
    E: ProxyEngineService,
    R: ConfigReader,
    H: ForegroundLifecycleHost,
{
    let raw_config = match read_required_config("start", reader, config_path) {
        Ok(raw_config) => raw_config,
        Err(response) => return *response,
    };

    let request = RuntimeConfigRequest::new(DEFAULT_ENGINE_ID, raw_config);
    match orchestrator.start_runtime(request) {
        Ok(result) => {
            handle_foreground_lifecycle_with_runtime_stop(result, orchestrator, lifecycle_host)
        }
        Err(error) => start_error_response(error),
    }
}

pub fn handle_foreground_lifecycle<H>(
    operation: RuntimeOperationResult,
    host: &H,
) -> LinuxCliResponse
where
    H: ForegroundLifecycleHost,
{
    let RuntimeOperationResult {
        platform,
        engine_status,
        mut diagnostics,
        ..
    } = operation;

    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Info,
        CLI_START_FOREGROUND_ONLY_CODE,
        "linux start is limited to the current foreground process",
        SOURCE_CLI_START,
    ));

    if engine_status.state != ProxyEngineLifecycleState::Running {
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_START_LIFECYCLE_FAILED_CODE,
            "linux runtime did not enter running state before foreground hosting",
            SOURCE_CLI_START,
        ));

        return LinuxCliResponse {
            ok: false,
            command: "start".to_string(),
            exit_code: LinuxCliExitCode::GeneralFailure,
            diagnostics,
            platform: Some(platform),
            config_profiles: Vec::new(),
            version: None,
            help: None,
            sing_box_install: None,
            sing_box_run: None,
            mitm_status: None,
        };
    }

    let request = ForegroundLifecycleRequest { engine_status };
    let outcome = host.run_foreground(&request);
    let ok = outcome.exit_code == LinuxCliExitCode::Success;
    diagnostics.extend(outcome.diagnostics);

    LinuxCliResponse {
        ok,
        command: "start".to_string(),
        exit_code: outcome.exit_code,
        diagnostics,
        platform: Some(platform),
        config_profiles: Vec::new(),
        version: None,
        help: None,
        sing_box_install: None,
        sing_box_run: None,
        mitm_status: None,
    }
}

pub fn handle_foreground_lifecycle_with_runtime_stop<C, P, E, H>(
    operation: RuntimeOperationResult,
    orchestrator: &RuntimeOrchestrator<C, P, E>,
    host: &H,
) -> LinuxCliResponse
where
    C: ConfigurationService,
    P: PlatformCapabilityService,
    E: ProxyEngineService,
    H: ForegroundLifecycleHost,
{
    let engine_id = operation.engine_status.engine_id.clone();
    let mut response = handle_foreground_lifecycle(operation, host);
    if response.exit_code != LinuxCliExitCode::Interrupted {
        return response;
    }

    match orchestrator.stop_runtime(&engine_id) {
        Ok(stop_status) => response.diagnostics.extend(stop_status.diagnostics),
        Err(error) => response.diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_START_RUNTIME_STOP_FAILED_CODE,
            format!(
                "failed to stop linux runtime after foreground interruption: {}",
                error.message
            ),
            SOURCE_CLI_START,
        )),
    }

    response
}

pub fn handle_stop() -> LinuxCliResponse {
    LinuxCliResponse::failure(
        "stop",
        LinuxCliExitCode::Unavailable,
        cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_STOP_UNAVAILABLE_WITHOUT_DAEMON_CODE,
            "linux stop is unavailable without a daemon or control socket",
            SOURCE_CLI_STOP,
        ),
    )
}

pub fn handle_status<P>(platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    match platform.status() {
        Ok(status) => {
            let mut diagnostics = platform_diagnostics(&status);
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Warning,
                CLI_STATUS_NO_RUNTIME_CONTEXT_CODE,
                "no runtime context is available for linux status",
                SOURCE_CLI_STATUS,
            ));
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Info,
                CLI_STATUS_PLATFORM_ONLY_CODE,
                "linux status output is limited to platform capability context",
                SOURCE_CLI_STATUS,
            ));

            LinuxCliResponse::success("status")
                .with_diagnostics(diagnostics)
                .with_platform(status)
        }
        Err(error) => domain_error_response(
            "status",
            LinuxCliExitCode::GeneralFailure,
            error,
            SOURCE_CLI_STATUS,
        ),
    }
}

pub fn handle_diagnostics<P>(platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    match platform.status() {
        Ok(status) => LinuxCliResponse::success("diagnostics")
            .with_diagnostics(platform_diagnostics(&status))
            .with_platform(status),
        Err(error) => domain_error_response(
            "diagnostics",
            LinuxCliExitCode::GeneralFailure,
            error,
            SOURCE_CLI_RUNTIME,
        ),
    }
}

pub fn handle_mitm_status<P>(platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_status_inner("mitm status", platform)
}

pub fn handle_mitm_diagnostics<P>(platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_status_inner("mitm diagnostics", platform)
}

fn handle_mitm_status_inner<P>(command: &'static str, platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    let platform_status = match platform.status() {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    match build_linux_mitm_status(&platform_status) {
        Ok((status, diagnostics)) => LinuxCliResponse::success(command)
            .with_platform(platform_status)
            .with_mitm_status(status)
            .with_diagnostics(diagnostics),
        Err(error) => domain_error_response(
            command,
            LinuxCliExitCode::GeneralFailure,
            error,
            SOURCE_CLI_MITM,
        ),
    }
}

fn build_linux_mitm_status(
    platform_status: &PlatformCapabilityStatus,
) -> DomainResult<(LinuxMitmStatus, Vec<Diagnostic>)> {
    let package = builtin_ad_block_plugin_package();
    let mut engine = AnixOpsMitmPolicyEngine::new()?;
    let report = engine.load_config(&package.source)?;
    let service = AnixOpsMitmPluginService::new();
    let instance = service.load(
        &package,
        &GrantedPermissions {
            permissions: package.manifest.permissions.clone(),
        },
    )?;

    let mut diagnostics = platform_diagnostics(platform_status);
    diagnostics.extend(report.diagnostics.clone());
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Info,
        CLI_MITM_POLICY_READY_CODE,
        "mitm policy engine loaded built-in networkcore.adblock plugin",
        SOURCE_CLI_MITM,
    ));
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Info,
        CLI_MITM_CLI_GATE_PARTIAL_CODE,
        "MITM_CLI_COMMAND_GATE is partially active for status and diagnostics only",
        SOURCE_CLI_MITM,
    ));
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Warning,
        CLI_MITM_CERTIFICATE_GATE_DEFERRED_CODE,
        "MITM_CERTIFICATE_LIFECYCLE_GATE is blocked; no CA generation, install, trust, revocation, or rollback path is active",
        SOURCE_CLI_MITM,
    ));
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Warning,
        CLI_MITM_DATA_PLANE_GATE_DEFERRED_CODE,
        "MITM_HTTP_TLS_DATA_PLANE_GATE is blocked; rewrite plans are not applied to live HTTP/TLS traffic",
        SOURCE_CLI_MITM,
    ));
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Warning,
        CLI_MITM_BROWSER_HIJACK_DEFERRED_CODE,
        "browser hijack is deferred until certificate lifecycle and HTTP/TLS data plane gates are active",
        SOURCE_CLI_MITM,
    ));

    let status = LinuxMitmStatus {
        stage: MITM_USER_FACING_STAGE.to_string(),
        user_facing_ready: MITM_USER_FACING_READY,
        browser_hijack: MITM_BROWSER_HIJACK_STATUS.to_string(),
        platform_mitm_available: platform_status.mitm_available(),
        certificate_state: certificate_state_name(platform_status.mitm_certificate.state)
            .to_string(),
        policy: LinuxMitmPolicyStatus {
            engine: "mitm_anixops".to_string(),
            engine_version: report.version,
            plugin_id: instance.manifest.id,
            plugin_version: instance.manifest.version,
            plugin_loaded: true,
            mitm_pattern_count: report.mitm_pattern_count,
            rewrite_rule_count: report.rewrite_rule_count,
            script_rule_count: report.script_rule_count,
            argument_count: report.argument_count,
        },
        gates: vec![
            LinuxMitmGateStatus {
                gate: MITM_CLI_COMMAND_GATE.to_string(),
                status: MITM_CLI_COMMAND_GATE_STATUS.to_string(),
                reason: "status and diagnostics command surface is active".to_string(),
            },
            LinuxMitmGateStatus {
                gate: MITM_CERTIFICATE_LIFECYCLE_GATE.to_string(),
                status: MITM_CERTIFICATE_LIFECYCLE_GATE_STATUS.to_string(),
                reason: "CA lifecycle is not implemented in the Linux CLI".to_string(),
            },
            LinuxMitmGateStatus {
                gate: MITM_HTTP_TLS_DATA_PLANE_GATE.to_string(),
                status: MITM_HTTP_TLS_DATA_PLANE_GATE_STATUS.to_string(),
                reason: "live HTTP/TLS interception and mutation are not wired".to_string(),
            },
        ],
    };

    debug_assert_eq!(status.policy.plugin_id, MITM_POLICY_AD_BLOCK_PLUGIN_ID);

    Ok((status, diagnostics))
}

pub fn handle_install_sing_box<I>(
    installer: &I,
    install_dir: Option<&str>,
    force: bool,
) -> LinuxCliResponse
where
    I: SingBoxReleaseInstaller,
{
    let target = match SingBoxTarget::current() {
        Ok(target) => target,
        Err(error) => {
            return domain_error_response(
                "install-sing-box",
                LinuxCliExitCode::Unavailable,
                error,
                SOURCE_CLI_SING_BOX,
            );
        }
    };
    let install_root = install_dir
        .map(std::path::PathBuf::from)
        .unwrap_or_else(default_sing_box_install_root);
    let request = SingBoxInstallRequest {
        install_root,
        target,
        force,
    };

    match installer.install_latest(&request) {
        Ok(report) => {
            let diagnostics = report.diagnostics.clone();
            LinuxCliResponse::success("install-sing-box")
                .with_diagnostics(diagnostics)
                .with_sing_box_install(LinuxSingBoxInstallStatus::from(report))
        }
        Err(error) => LinuxCliResponse::failure(
            "install-sing-box",
            LinuxCliExitCode::GeneralFailure,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_SING_BOX_INSTALL_FAILED_CODE,
                error.message,
                SOURCE_CLI_SING_BOX,
            ),
        ),
    }
}

pub fn handle_run_url_with_sing_box<I, S>(
    installer: &I,
    runner: &S,
    url: &str,
    listen_host: &str,
    listen_port: u16,
    install_dir: Option<&str>,
    force: bool,
) -> LinuxCliResponse
where
    I: SingBoxReleaseInstaller,
    S: SingBoxProcessRunner,
{
    let install_root = install_dir
        .map(std::path::PathBuf::from)
        .unwrap_or_else(default_sing_box_install_root);
    let subscription = CoreSubscriptionService::new();
    let raw_subscription = RawSubscription {
        source_id: "cli-run-url".to_string(),
        content: url.to_string(),
    };
    let document = match subscription.parse(&raw_subscription) {
        Ok(document) => document,
        Err(error) => {
            return domain_error_response(
                "run-url",
                LinuxCliExitCode::ArgumentOrConfig,
                DomainError::new(CLI_RUN_URL_PARSE_FAILED_CODE, error.message),
                SOURCE_CLI_SING_BOX,
            );
        }
    };
    let catalog = match subscription.normalize(&document) {
        Ok(catalog) => catalog,
        Err(error) => {
            return domain_error_response(
                "run-url",
                LinuxCliExitCode::ArgumentOrConfig,
                DomainError::new(CLI_RUN_URL_PARSE_FAILED_CODE, error.message),
                SOURCE_CLI_SING_BOX,
            );
        }
    };
    let generated_config =
        match render_sing_box_local_proxy_config(&SingBoxLocalProxyConfigRequest {
            nodes: catalog.nodes,
            selected_node_id: None,
            listen_host: listen_host.to_string(),
            listen_port,
        }) {
            Ok(config) => config,
            Err(error) => {
                return domain_error_response(
                    "run-url",
                    LinuxCliExitCode::ArgumentOrConfig,
                    DomainError::new(CLI_RUN_URL_CONFIG_FAILED_CODE, error.message),
                    SOURCE_CLI_SING_BOX,
                );
            }
        };
    let target = match SingBoxTarget::current() {
        Ok(target) => target,
        Err(error) => {
            return domain_error_response(
                "run-url",
                LinuxCliExitCode::Unavailable,
                error,
                SOURCE_CLI_SING_BOX,
            );
        }
    };
    let install_request = SingBoxInstallRequest {
        install_root: install_root.clone(),
        target,
        force,
    };
    let install_report = match installer.install_latest(&install_request) {
        Ok(report) => report,
        Err(error) => {
            return LinuxCliResponse::failure(
                "run-url",
                LinuxCliExitCode::GeneralFailure,
                cli_diagnostic(
                    DiagnosticSeverity::Error,
                    CLI_SING_BOX_INSTALL_FAILED_CODE,
                    error.message,
                    SOURCE_CLI_SING_BOX,
                ),
            );
        }
    };
    let config_path = sing_box_run_config_path(&install_root, &generated_config.selected_node_id);
    if let Err(error) = write_sing_box_run_config(&config_path, &generated_config.json) {
        return LinuxCliResponse::failure(
            "run-url",
            LinuxCliExitCode::GeneralFailure,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_RUN_URL_CONFIG_WRITE_FAILED_CODE,
                error.message,
                SOURCE_CLI_SING_BOX,
            ),
        );
    }

    let run_request = SingBoxProcessRunRequest {
        executable_path: install_report.executable_path.clone(),
        config_path: config_path.clone(),
    };
    let run_report = match runner.run(&run_request) {
        Ok(report) => report,
        Err(error) => {
            return LinuxCliResponse::failure(
                "run-url",
                LinuxCliExitCode::GeneralFailure,
                cli_diagnostic(
                    DiagnosticSeverity::Error,
                    CLI_RUN_URL_PROCESS_FAILED_CODE,
                    error.message,
                    SOURCE_CLI_SING_BOX,
                ),
            );
        }
    };
    let mut diagnostics = install_report.diagnostics.clone();
    diagnostics.extend(document.diagnostics.clone());
    diagnostics.extend(generated_config.diagnostics.clone());
    diagnostics.extend(run_report.diagnostics.clone());
    let run_status = LinuxSingBoxRunStatus {
        node_id: generated_config.selected_node_id,
        node_name: generated_config.selected_node_name,
        listen_host: generated_config.listen_host,
        listen_port: generated_config.listen_port,
        executable_path: install_report.executable_path.display().to_string(),
        config_path: config_path.display().to_string(),
        process_exit_code: run_report.exit_code,
    };

    let response = LinuxCliResponse::success("run-url")
        .with_diagnostics(diagnostics)
        .with_sing_box_install(LinuxSingBoxInstallStatus::from(install_report))
        .with_sing_box_run(run_status);

    match run_report.exit_code {
        Some(0) => response,
        Some(130) => LinuxCliResponse {
            ok: false,
            exit_code: LinuxCliExitCode::Interrupted,
            ..response
        },
        _ => LinuxCliResponse {
            ok: false,
            exit_code: LinuxCliExitCode::GeneralFailure,
            ..response
        },
    }
}

pub fn render_response(response: &LinuxCliResponse, format: OutputFormat) -> String {
    match format {
        OutputFormat::Text => render_text_response(response),
        OutputFormat::Json => render_json_response(response),
    }
}

pub fn cli_diagnostic(
    severity: DiagnosticSeverity,
    code: impl Into<String>,
    message: impl Into<String>,
    source: impl Into<String>,
) -> Diagnostic {
    Diagnostic::new(severity, code, message, Some(source.into()))
}

fn parse_options(args: &[String]) -> Result<ParsedOptions, LinuxCliParseError> {
    let mut options = ParsedOptions::default();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--config" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--config requires a path value",
                    ));
                };
                options.config_path = Some(value.clone());
            }
            "--install-dir" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--install-dir requires a directory path value",
                    ));
                };
                options.install_dir = Some(value.clone());
            }
            "--force" => {
                options.force = true;
            }
            "--listen-host" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--listen-host requires an address value",
                    ));
                };
                options.listen_host = Some(value.clone());
            }
            "--listen-port" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--listen-port requires a port value",
                    ));
                };
                options.listen_port = Some(parse_listen_port(value)?);
            }
            "--format" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--format requires text or json",
                    ));
                };
                options.format = parse_output_format(value)?;
            }
            unknown => {
                return Err(parse_error(
                    CLI_ARGUMENT_UNKNOWN_CODE,
                    format!("unknown linux CLI argument: {unknown}"),
                ));
            }
        }

        index += 1;
    }

    Ok(options)
}

fn parse_run_url_command(args: &[String]) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(url) = args.first() else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "run-url requires a proxy URL argument",
        ));
    };
    if url.starts_with("--") {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "run-url requires a proxy URL before options",
        ));
    }
    let options = parse_options(&args[1..])?;

    Ok(LinuxCliCommand::RunUrl {
        url: url.clone(),
        listen_host: options
            .listen_host
            .unwrap_or_else(|| "127.0.0.1".to_string()),
        listen_port: options.listen_port.unwrap_or(7890),
        install_dir: options.install_dir,
        force: options.force,
        format: options.format,
    })
}

fn parse_mitm_command(args: &[String]) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(subcommand) = args.first() else {
        let options = parse_options(args)?;
        return Ok(LinuxCliCommand::MitmStatus {
            format: options.format,
        });
    };

    if subcommand.starts_with("--") {
        let options = parse_options(args)?;
        return Ok(LinuxCliCommand::MitmStatus {
            format: options.format,
        });
    }

    match subcommand.as_str() {
        "status" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmStatus {
                format: options.format,
            })
        }
        "diagnostics" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmDiagnostics {
                format: options.format,
            })
        }
        unknown => Err(parse_error(
            CLI_ARGUMENT_UNKNOWN_CODE,
            format!("unknown mitm subcommand: {unknown}; run networkcore-linux help"),
        )),
    }
}

fn parse_sing_box_command(args: &[String]) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(subcommand) = args.first() else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "sing-box requires a subcommand; run networkcore-linux help",
        ));
    };

    match subcommand.as_str() {
        "install" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::InstallSingBox {
                install_dir: options.install_dir,
                force: options.force,
                format: options.format,
            })
        }
        unknown => Err(parse_error(
            CLI_ARGUMENT_UNKNOWN_CODE,
            format!("unknown sing-box subcommand: {unknown}; run networkcore-linux help"),
        )),
    }
}

fn parse_listen_port(value: &str) -> Result<u16, LinuxCliParseError> {
    let parsed = value.parse::<u16>().map_err(|_| {
        parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "--listen-port must be between 1 and 65535",
        )
    })?;
    if parsed == 0 {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "--listen-port must be between 1 and 65535",
        ));
    }

    Ok(parsed)
}

pub const fn cli_help_text() -> &'static str {
    concat!(
        "NetworkCore Linux CLI\n",
        "\n",
        "Usage:\n",
        "  networkcore-linux help [--format text|json]\n",
        "  networkcore-linux version [--format text|json]\n",
        "  networkcore-linux capabilities [--format text|json]\n",
        "  networkcore-linux prepare-config --config <path> [--format text|json]\n",
        "  networkcore-linux start --config <path> [--format text|json]\n",
        "  networkcore-linux stop [--format text|json]\n",
        "  networkcore-linux status [--format text|json]\n",
        "  networkcore-linux diagnostics [--format text|json]\n",
        "  networkcore-linux mitm [status|diagnostics] [--format text|json]\n",
        "  networkcore-linux install-sing-box [--install-dir <dir>] [--force] [--format text|json]\n",
        "  networkcore-linux run-url <ss://url> [--listen-host <host>] [--listen-port <port>] [--install-dir <dir>] [--force] [--format text|json]\n",
        "  networkcore-linux sing-box install [--install-dir <dir>] [--force] [--format text|json]\n",
        "\n",
        "Commands:\n",
        "  help              Show this command table.\n",
        "  version           Print the networkcore-linux version.\n",
        "  capabilities      Report read-only Linux platform capabilities.\n",
        "  prepare-config    Read and normalize a NetworkCore TOML config.\n",
        "  start             Start the current foreground runtime from a config.\n",
        "  stop              Report that daemon stop is unavailable in this build.\n",
        "  status            Report platform-only status without a daemon context.\n",
        "  diagnostics       Print platform diagnostics.\n",
        "  mitm              Report MITM plugin policy status and deferred browser hijack gates.\n",
        "  install-sing-box  Download the latest official sing-box archive and cache its executable.\n",
        "  run-url           Parse a proxy URL, render sing-box config, and run a local foreground proxy.\n",
        "\n",
        "Options:\n",
        "  --config <path>       Config file for prepare-config and start.\n",
        "  --install-dir <dir>   Engine cache root for install-sing-box.\n",
        "  --listen-host <host>  Local proxy listen address for run-url. Defaults to 127.0.0.1.\n",
        "  --listen-port <port>  Local proxy listen port for run-url. Defaults to 7890.\n",
        "  --force               Redownload and replace an existing cached sing-box executable.\n",
        "  --format text|json    Output format. Defaults to text.\n",
    )
}

fn parse_output_format(value: &str) -> Result<OutputFormat, LinuxCliParseError> {
    match value {
        "text" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        _ => Err(parse_error(
            CLI_OUTPUT_FORMAT_UNSUPPORTED_CODE,
            format!("unsupported linux CLI output format: {value}"),
        )),
    }
}

fn parse_error(code: impl Into<String>, message: impl Into<String>) -> LinuxCliParseError {
    LinuxCliParseError::new(cli_diagnostic(
        DiagnosticSeverity::Error,
        code,
        message,
        SOURCE_CLI_ARGUMENT,
    ))
}

fn read_required_config<R>(
    command: &'static str,
    reader: &R,
    config_path: Option<&str>,
) -> Result<String, Box<LinuxCliResponse>>
where
    R: ConfigReader,
{
    let Some(path) = config_path else {
        return Err(Box::new(LinuxCliResponse::failure(
            command,
            LinuxCliExitCode::ArgumentOrConfig,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_CONFIG_PATH_MISSING_CODE,
                "linux CLI command requires --config <path>",
                SOURCE_CLI_CONFIG,
            ),
        )));
    };

    let raw_config = match reader.read_config(path) {
        Ok(raw_config) => raw_config,
        Err(error) => {
            return Err(Box::new(LinuxCliResponse::failure(
                command,
                LinuxCliExitCode::ArgumentOrConfig,
                cli_diagnostic(
                    DiagnosticSeverity::Error,
                    CLI_CONFIG_READ_FAILED_CODE,
                    format!("failed to read linux config {path}: {}", error.message),
                    SOURCE_CLI_CONFIG,
                ),
            )));
        }
    };

    if raw_config.trim().is_empty() {
        return Err(Box::new(LinuxCliResponse::failure(
            command,
            LinuxCliExitCode::ArgumentOrConfig,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_CONFIG_EMPTY_CODE,
                "linux CLI config is empty",
                SOURCE_CLI_CONFIG,
            ),
        )));
    }

    Ok(raw_config)
}

fn sing_box_run_config_path(install_root: &std::path::Path, node_id: &str) -> std::path::PathBuf {
    install_root
        .join("runtime")
        .join(format!("run-url-{}.json", sanitize_path_segment(node_id)))
}

fn write_sing_box_run_config(path: &std::path::Path, content: &str) -> Result<(), ConfigReadError> {
    let parent = path
        .parent()
        .ok_or_else(|| ConfigReadError::new("sing-box config path has no parent directory"))?;
    std::fs::create_dir_all(parent).map_err(|error| ConfigReadError::new(error.to_string()))?;
    std::fs::write(path, content).map_err(|error| ConfigReadError::new(error.to_string()))
}

fn sanitize_path_segment(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    let sanitized = sanitized.trim_matches('-');

    if sanitized.is_empty() {
        "node".to_string()
    } else {
        sanitized.to_string()
    }
}

fn start_error_response(error: DomainError) -> LinuxCliResponse {
    if error.code.starts_with("runtime.platform.") {
        return LinuxCliResponse::failure(
            "start",
            LinuxCliExitCode::PlatformDenied,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_START_PLATFORM_DENIED_CODE,
                error.message,
                SOURCE_CLI_START,
            ),
        );
    }

    if error.code.starts_with("runtime.config.") {
        return LinuxCliResponse::failure(
            "start",
            LinuxCliExitCode::ConfigValidation,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_START_CONFIG_DENIED_CODE,
                error.message,
                SOURCE_CLI_START,
            ),
        );
    }

    if error.code.starts_with("runtime.engine") || error.code.starts_with("engine.") {
        return LinuxCliResponse::failure(
            "start",
            LinuxCliExitCode::EngineDenied,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_START_ENGINE_DENIED_CODE,
                error.message,
                SOURCE_CLI_START,
            ),
        );
    }

    domain_error_response(
        "start",
        LinuxCliExitCode::GeneralFailure,
        error,
        SOURCE_CLI_START,
    )
}

fn domain_error_response(
    command: &'static str,
    exit_code: LinuxCliExitCode,
    error: DomainError,
    source: &'static str,
) -> LinuxCliResponse {
    LinuxCliResponse::failure(
        command,
        exit_code,
        cli_diagnostic(DiagnosticSeverity::Error, error.code, error.message, source),
    )
}

fn handle_unwired_command(command: &'static str) -> LinuxCliResponse {
    LinuxCliResponse::failure(
        command,
        LinuxCliExitCode::Unavailable,
        cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_RUNTIME_UNWIRED_CODE,
            "linux CLI runtime wiring is not available for this command",
            SOURCE_CLI_RUNTIME,
        ),
    )
}

fn unavailable_engine_error() -> DomainError {
    DomainError::new(
        CLI_RUNTIME_UNWIRED_CODE,
        "linux proxy engine adapter is not wired",
    )
}

fn platform_diagnostics(status: &PlatformCapabilityStatus) -> Vec<Diagnostic> {
    let mut diagnostics = status.diagnostics.clone();
    diagnostics.extend(status.mitm_certificate.diagnostics.clone());
    diagnostics
}

fn render_text_response(response: &LinuxCliResponse) -> String {
    if response.ok && response.command == "help" {
        return response
            .help
            .clone()
            .unwrap_or_else(|| cli_help_text().to_string());
    }

    let state = if response.ok { "ok" } else { "error" };
    let mut lines = vec![format!("{}: {state}", response.command)];

    if let Some(install) = &response.sing_box_install {
        lines.push(format!("sing-box version: {}", install.version));
        lines.push(format!("target: {}", install.target));
        lines.push(format!("asset: {}", install.asset_name));
        if let Some(sha256) = &install.asset_sha256 {
            lines.push(format!("sha256: {sha256}"));
        }
        lines.push(format!("archive: {}", install.archive_path));
        lines.push(format!("executable: {}", install.executable_path));
        lines.push(format!("downloaded: {}", install.downloaded));
    }

    if let Some(run) = &response.sing_box_run {
        lines.push(format!("node: {} ({})", run.node_name, run.node_id));
        lines.push(format!(
            "local proxy: {}:{}",
            run.listen_host, run.listen_port
        ));
        lines.push(format!("config: {}", run.config_path));
        lines.push(format!("process exit code: {:?}", run.process_exit_code));
    }

    if let Some(mitm) = &response.mitm_status {
        lines.push(format!("mitm stage: {}", mitm.stage));
        lines.push(format!(
            "user-facing mitm ready: {}",
            mitm.user_facing_ready
        ));
        lines.push(format!("browser hijack: {}", mitm.browser_hijack));
        lines.push(format!(
            "platform mitm available: {}",
            mitm.platform_mitm_available
        ));
        lines.push(format!("certificate state: {}", mitm.certificate_state));
        lines.push(format!(
            "policy engine: {} {}",
            mitm.policy.engine, mitm.policy.engine_version
        ));
        lines.push(format!(
            "plugin: {} {} loaded={}",
            mitm.policy.plugin_id, mitm.policy.plugin_version, mitm.policy.plugin_loaded
        ));
        lines.push(format!(
            "rules: mitm={} rewrite={} script={} arguments={}",
            mitm.policy.mitm_pattern_count,
            mitm.policy.rewrite_rule_count,
            mitm.policy.script_rule_count,
            mitm.policy.argument_count
        ));
        for gate in &mitm.gates {
            lines.push(format!(
                "gate {}: {} ({})",
                gate.gate, gate.status, gate.reason
            ));
        }
    }

    for diagnostic in &response.diagnostics {
        lines.push(format!(
            "{} {}: {}",
            severity_name(diagnostic.severity),
            diagnostic.code,
            diagnostic.message
        ));
    }

    if let Some(help) = &response.help {
        lines.push(String::new());
        lines.push(help.clone());
    }

    lines.join("\n")
}

fn render_json_response(response: &LinuxCliResponse) -> String {
    let dto = JsonCliResponse::from(response);
    serde_json::to_string(&dto).expect("CLI response serialization should not fail")
}

fn severity_name(severity: DiagnosticSeverity) -> &'static str {
    match severity {
        DiagnosticSeverity::Info => "info",
        DiagnosticSeverity::Warning => "warning",
        DiagnosticSeverity::Error => "error",
    }
}

fn os_name(os: OperatingSystem) -> &'static str {
    match os {
        OperatingSystem::Linux => "linux",
        OperatingSystem::Macos => "macos",
        OperatingSystem::Windows => "windows",
        OperatingSystem::Ios => "ios",
        OperatingSystem::Unknown => "unknown",
    }
}

fn certificate_state_name(state: CertificateTrustState) -> &'static str {
    match state {
        CertificateTrustState::NotInstalled => "not_installed",
        CertificateTrustState::InstalledUntrusted => "installed_untrusted",
        CertificateTrustState::Trusted => "trusted",
        CertificateTrustState::Revoked => "revoked",
        CertificateTrustState::Unknown => "unknown",
    }
}

#[derive(Serialize)]
struct JsonCliResponse {
    ok: bool,
    command: String,
    exit_code: i32,
    diagnostics: Vec<JsonDiagnostic>,
    platform: Option<JsonPlatform>,
    config_profiles: Vec<String>,
    version: Option<String>,
    help: Option<String>,
    sing_box_install: Option<JsonSingBoxInstallStatus>,
    sing_box_run: Option<JsonSingBoxRunStatus>,
    mitm_status: Option<JsonMitmStatus>,
}

impl From<&LinuxCliResponse> for JsonCliResponse {
    fn from(response: &LinuxCliResponse) -> Self {
        Self {
            ok: response.ok,
            command: response.command.clone(),
            exit_code: response.exit_code.code(),
            diagnostics: response
                .diagnostics
                .iter()
                .map(JsonDiagnostic::from)
                .collect(),
            platform: response.platform.as_ref().map(JsonPlatform::from),
            config_profiles: response.config_profiles.clone(),
            version: response.version.clone(),
            help: response.help.clone(),
            sing_box_install: response
                .sing_box_install
                .as_ref()
                .map(JsonSingBoxInstallStatus::from),
            sing_box_run: response
                .sing_box_run
                .as_ref()
                .map(JsonSingBoxRunStatus::from),
            mitm_status: response.mitm_status.as_ref().map(JsonMitmStatus::from),
        }
    }
}

#[derive(Serialize)]
struct JsonSingBoxInstallStatus {
    version: String,
    target: String,
    asset_name: String,
    asset_url: String,
    asset_sha256: Option<String>,
    archive_path: String,
    executable_path: String,
    downloaded: bool,
}

impl From<&LinuxSingBoxInstallStatus> for JsonSingBoxInstallStatus {
    fn from(status: &LinuxSingBoxInstallStatus) -> Self {
        Self {
            version: status.version.clone(),
            target: status.target.clone(),
            asset_name: status.asset_name.clone(),
            asset_url: status.asset_url.clone(),
            asset_sha256: status.asset_sha256.clone(),
            archive_path: status.archive_path.clone(),
            executable_path: status.executable_path.clone(),
            downloaded: status.downloaded,
        }
    }
}

#[derive(Serialize)]
struct JsonSingBoxRunStatus {
    node_id: String,
    node_name: String,
    listen_host: String,
    listen_port: u16,
    executable_path: String,
    config_path: String,
    process_exit_code: Option<i32>,
}

impl From<&LinuxSingBoxRunStatus> for JsonSingBoxRunStatus {
    fn from(status: &LinuxSingBoxRunStatus) -> Self {
        Self {
            node_id: status.node_id.clone(),
            node_name: status.node_name.clone(),
            listen_host: status.listen_host.clone(),
            listen_port: status.listen_port,
            executable_path: status.executable_path.clone(),
            config_path: status.config_path.clone(),
            process_exit_code: status.process_exit_code,
        }
    }
}

#[derive(Serialize)]
struct JsonMitmStatus {
    stage: String,
    user_facing_ready: bool,
    browser_hijack: String,
    platform_mitm_available: bool,
    certificate_state: String,
    policy: JsonMitmPolicyStatus,
    gates: Vec<JsonMitmGateStatus>,
}

impl From<&LinuxMitmStatus> for JsonMitmStatus {
    fn from(status: &LinuxMitmStatus) -> Self {
        Self {
            stage: status.stage.clone(),
            user_facing_ready: status.user_facing_ready,
            browser_hijack: status.browser_hijack.clone(),
            platform_mitm_available: status.platform_mitm_available,
            certificate_state: status.certificate_state.clone(),
            policy: JsonMitmPolicyStatus::from(&status.policy),
            gates: status.gates.iter().map(JsonMitmGateStatus::from).collect(),
        }
    }
}

#[derive(Serialize)]
struct JsonMitmPolicyStatus {
    engine: String,
    engine_version: String,
    plugin_id: String,
    plugin_version: String,
    plugin_loaded: bool,
    mitm_pattern_count: usize,
    rewrite_rule_count: usize,
    script_rule_count: usize,
    argument_count: usize,
}

impl From<&LinuxMitmPolicyStatus> for JsonMitmPolicyStatus {
    fn from(status: &LinuxMitmPolicyStatus) -> Self {
        Self {
            engine: status.engine.clone(),
            engine_version: status.engine_version.clone(),
            plugin_id: status.plugin_id.clone(),
            plugin_version: status.plugin_version.clone(),
            plugin_loaded: status.plugin_loaded,
            mitm_pattern_count: status.mitm_pattern_count,
            rewrite_rule_count: status.rewrite_rule_count,
            script_rule_count: status.script_rule_count,
            argument_count: status.argument_count,
        }
    }
}

#[derive(Serialize)]
struct JsonMitmGateStatus {
    gate: String,
    status: String,
    reason: String,
}

impl From<&LinuxMitmGateStatus> for JsonMitmGateStatus {
    fn from(status: &LinuxMitmGateStatus) -> Self {
        Self {
            gate: status.gate.clone(),
            status: status.status.clone(),
            reason: status.reason.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonDiagnostic {
    severity: &'static str,
    code: String,
    message: String,
    source: Option<String>,
}

impl From<&Diagnostic> for JsonDiagnostic {
    fn from(diagnostic: &Diagnostic) -> Self {
        Self {
            severity: severity_name(diagnostic.severity),
            code: diagnostic.code.clone(),
            message: diagnostic.message.clone(),
            source: diagnostic.source.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonPlatform {
    os: &'static str,
    tunnel: JsonFeatureState,
    mitm: JsonFeatureState,
    embedded_runtime: JsonFeatureState,
    remote_script_execution: JsonFeatureState,
    mitm_certificate: JsonCertificateStatus,
}

impl From<&PlatformCapabilityStatus> for JsonPlatform {
    fn from(status: &PlatformCapabilityStatus) -> Self {
        Self {
            os: os_name(status.os),
            tunnel: JsonFeatureState::from(&status.tunnel),
            mitm: JsonFeatureState::from(&status.mitm),
            embedded_runtime: JsonFeatureState::from(&status.embedded_runtime),
            remote_script_execution: JsonFeatureState::from(&status.remote_script_execution),
            mitm_certificate: JsonCertificateStatus::from(status),
        }
    }
}

#[derive(Serialize)]
struct JsonFeatureState {
    state: &'static str,
    reason: Option<String>,
}

impl From<&PlatformFeatureState> for JsonFeatureState {
    fn from(state: &PlatformFeatureState) -> Self {
        match state {
            PlatformFeatureState::Available => Self {
                state: "available",
                reason: None,
            },
            PlatformFeatureState::Unavailable { reason } => Self {
                state: "unavailable",
                reason: Some(reason.clone()),
            },
            PlatformFeatureState::Unknown => Self {
                state: "unknown",
                reason: state.denial_reason().map(ToString::to_string),
            },
        }
    }
}

#[derive(Serialize)]
struct JsonCertificateStatus {
    state: &'static str,
    subject: Option<String>,
    fingerprint_sha256: Option<String>,
}

impl From<&PlatformCapabilityStatus> for JsonCertificateStatus {
    fn from(status: &PlatformCapabilityStatus) -> Self {
        Self {
            state: certificate_state_name(status.mitm_certificate.state),
            subject: status.mitm_certificate.subject.clone(),
            fingerprint_sha256: status.mitm_certificate.fingerprint_sha256.clone(),
        }
    }
}
