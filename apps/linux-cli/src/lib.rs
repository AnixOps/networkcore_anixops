//! Linux CLI entrypoint contracts for NetworkCore.
//!
//! The crate contains command parsing, response mapping, config I/O boundaries,
//! and foreground runtime handoff. Daemon control, service installation, and
//! release packaging are deliberately outside this first source increment.

use control_domain::{
    CertificateTrustState, ConfigurationService, Diagnostic, DiagnosticSeverity, DomainError,
    DomainResult, OperatingSystem, PlatformCapabilityService, PlatformCapabilityStatus,
    PlatformFeatureState, ProxyEngineConfig, ProxyEngineDescriptor, ProxyEngineEvent,
    ProxyEngineLifecycleState, ProxyEngineService, ProxyEngineStatus,
};
use control_runtime::{RuntimeConfigRequest, RuntimeOperationResult, RuntimeOrchestrator};
use serde::Serialize;
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
pub const CLI_STOP_UNAVAILABLE_WITHOUT_DAEMON_CODE: &str =
    "cli.linux.stop.unavailable_without_daemon";
pub const CLI_STATUS_NO_RUNTIME_CONTEXT_CODE: &str = "cli.linux.status.no_runtime_context";
pub const CLI_STATUS_PLATFORM_ONLY_CODE: &str = "cli.linux.status.platform_only";
pub const CLI_RUNTIME_UNWIRED_CODE: &str = "cli.linux.runtime.unwired";

pub const SOURCE_CLI_ARGUMENT: &str = "cli.argument";
pub const SOURCE_CLI_CONFIG: &str = "cli.config";
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
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinuxCliCommand {
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
}

impl LinuxCliCommand {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Version { .. } => "version",
            Self::Capabilities { .. } => "capabilities",
            Self::PrepareConfig { .. } => "prepare-config",
            Self::Start { .. } => "start",
            Self::Stop { .. } => "stop",
            Self::Status { .. } => "status",
            Self::Diagnostics { .. } => "diagnostics",
        }
    }

    pub const fn format(&self) -> OutputFormat {
        match self {
            Self::Version { format }
            | Self::Capabilities { format }
            | Self::PrepareConfig { format, .. }
            | Self::Start { format, .. }
            | Self::Stop { format }
            | Self::Status { format }
            | Self::Diagnostics { format } => *format,
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

    pub fn with_diagnostics(mut self, diagnostics: Vec<Diagnostic>) -> Self {
        self.diagnostics = diagnostics;
        self
    }
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

pub trait ForegroundLifecycleHost {
    fn run_foreground(&self, request: &ForegroundLifecycleRequest) -> ForegroundLifecycleOutcome;
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
pub struct CurrentProcessForegroundLifecycleHost;

impl CurrentProcessForegroundLifecycleHost {
    pub const fn new() -> Self {
        Self
    }
}

impl ForegroundLifecycleHost for CurrentProcessForegroundLifecycleHost {
    fn run_foreground(&self, _request: &ForegroundLifecycleRequest) -> ForegroundLifecycleOutcome {
        loop {
            thread::park();
        }
    }
}

#[derive(Debug, Default)]
struct ParsedOptions {
    config_path: Option<String>,
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
            "missing linux CLI command",
        ));
    };
    let rest = args.collect::<Vec<_>>();

    match command.as_str() {
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
        _ => Err(parse_error(
            CLI_ARGUMENT_UNKNOWN_CODE,
            format!("unknown linux CLI command: {command}"),
        )),
    }
}

pub fn handle_parse_error(diagnostic: Diagnostic) -> LinuxCliResponse {
    LinuxCliResponse::failure("parse", LinuxCliExitCode::ArgumentOrConfig, diagnostic)
}

pub fn handle_entrypoint_skeleton(command: LinuxCliCommand) -> LinuxCliResponse {
    match command {
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
        LinuxCliCommand::Version { .. } => handle_version(),
        LinuxCliCommand::Capabilities { .. } => handle_capabilities(platform),
        LinuxCliCommand::Status { .. } => handle_status(platform),
        LinuxCliCommand::Diagnostics { .. } => handle_diagnostics(platform),
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
        Ok(result) => handle_foreground_lifecycle(result, lifecycle_host),
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
    }
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
    let state = if response.ok { "ok" } else { "error" };
    let mut lines = vec![format!("{}: {state}", response.command)];

    for diagnostic in &response.diagnostics {
        lines.push(format!(
            "{} {}: {}",
            severity_name(diagnostic.severity),
            diagnostic.code,
            diagnostic.message
        ));
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
