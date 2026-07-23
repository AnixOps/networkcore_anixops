//! Windows CLI entrypoint contracts for NetworkCore.
//!
//! The Windows CLI is the command surface for the managed client package. Service, driver,
//! installer, system proxy, trust-store, and managed lifecycle operations are implemented by
//! the GUI, SCM host, and `platform-windows`; JavaScript dispatch remains deferred.

use config_core::sdwan_delivery::{SdwanDeliveryVerifier, SDWAN_DELIVERY_EXPIRED_CODE};
use config_core::windows_tunnel::{
    plan_windows_tunnel, WindowsTunnelPlanRequest, WINDOWS_TUNNEL_DELIVERY_EXPIRED_CODE,
    WINDOWS_TUNNEL_DELIVERY_INVALID_CODE, WINDOWS_TUNNEL_SEQUENCE_REPLAYED_CODE,
};
use control_domain::{DomainError, DomainResult};
use platform_windows::{
    tunnel_config::{WindowsTunnelLifecycleState, WindowsTunnelState},
    tunnel_runtime::{
        native_windows_is_elevated, EasyTierCliRunner, EasyTierProcessRunner,
        NativeEasyTierCliRunner, NativeEasyTierProcessRunner, NativeWindowsRoutePort,
        WindowsRoutePort, WindowsTunnelSessionService, WindowsTunnelStartRequest,
        WINDOWS_TUNNEL_ADMIN_REQUIRED_CODE, WINDOWS_TUNNEL_CONFIRMATION_REQUIRED_CODE,
    },
    tunnel_security::{
        native_windows_prepare_easytier_artifact, native_windows_prepare_secret_file,
        native_windows_prepare_state_path, native_windows_prepare_tunnel_secure_paths,
        native_windows_validate_existing_state_path,
    },
    WindowsFeatureStatus, WindowsPlatformCapabilityService, WindowsPlatformSnapshot,
    WindowsTunnelPlan, WINDOWS_CLI_PACKAGE_STATUS, WINDOWS_CLI_RELEASE_ASSETS_STATUS,
    WINDOWS_CLI_SOURCE_IDENTITY, WINDOWS_SYSTEM_MUTATION_POLICY,
};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

mod tunnel_sequence_ledger;

use tunnel_sequence_ledger::NativeWindowsTunnelSequenceLedger;

pub const COMMAND_NAME: &str = "networkcore-windows";
pub const PLATFORM_NAME: &str = "windows";
pub const WINDOWS_CLI_SOURCE_CONTRACT_STATUS: &str = "active";
pub const WINDOWS_CLI_VERSION_SCOPE: &str = "v0.2.0-alpha.5";
pub const WINDOWS_CLI_SUBSCRIPTION_COMPATIBILITY_STATUS: &str =
    "parser-gates-active-run-compat-deferred";

pub const CLI_WINDOWS_ARGUMENT_UNKNOWN_CODE: &str = "cli.windows.argument.unknown";
pub const CLI_WINDOWS_ARGUMENT_VALUE_MISSING_CODE: &str = "cli.windows.argument.value_missing";
pub const CLI_WINDOWS_OUTPUT_FORMAT_UNSUPPORTED_CODE: &str =
    "cli.windows.output.format_unsupported";
pub const CLI_WINDOWS_ARTIFACT_READY_CODE: &str = "cli.windows.artifact.package_ready";
pub const CLI_WINDOWS_SYSTEM_INTEGRATION_ACTIVE_CODE: &str =
    "cli.windows.system_integration.active";
pub const CLI_WINDOWS_SUBSCRIPTION_DEFERRED_CODE: &str =
    "cli.windows.subscription_compatibility.deferred";
pub const CLI_WINDOWS_TUNNEL_UNAVAILABLE_CODE: &str = "cli.windows.tunnel.unavailable";

const CLI_WINDOWS_TUNNEL_ERROR_MESSAGE: &str = "Tunnel command could not be completed.";
const CLI_WINDOWS_TUNNEL_ERROR_SOURCE: &str = "cli.windows.tunnel.service";
const CLI_WINDOWS_TUNNEL_UNAVAILABLE_MESSAGE: &str = "Tunnel command service is unavailable.";
const CLI_WINDOWS_TUNNEL_UNAVAILABLE_SOURCE: &str = "cli.windows.tunnel";

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsTunnelPrepareStorageArgs {
    pub confirm: bool,
    pub format: OutputFormat,
}

impl WindowsTunnelPrepareStorageArgs {
    pub const fn format(&self) -> OutputFormat {
        self.format
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsTunnelStartArgs {
    pub client_envelope: PathBuf,
    pub pop_envelope: PathBuf,
    pub pop_id: String,
    pub device_id: String,
    pub delivery_public_key_file: PathBuf,
    pub easytier_binary: PathBuf,
    pub easytier_cli: PathBuf,
    pub easytier_version: String,
    pub easytier_sha256: String,
    pub easytier_cli_sha256: String,
    pub network_name: String,
    pub network_secret_file: PathBuf,
    pub state_path: PathBuf,
    pub confirm: bool,
    format: OutputFormat,
}

impl WindowsTunnelStartArgs {
    pub const fn format(&self) -> OutputFormat {
        self.format
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsTunnelStatusArgs {
    pub state_path: PathBuf,
    pub format: OutputFormat,
}

impl WindowsTunnelStatusArgs {
    pub const fn format(&self) -> OutputFormat {
        self.format
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsTunnelStopArgs {
    pub state_path: PathBuf,
    pub confirm: bool,
    pub format: OutputFormat,
}

impl WindowsTunnelStopArgs {
    pub const fn format(&self) -> OutputFormat {
        self.format
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsTunnelCommandResult {
    pub state: WindowsTunnelState,
    pub peer_ready: bool,
    pub route_ready: bool,
    pub route_count: usize,
}

pub trait WindowsTunnelCommandService {
    fn prepare_storage(&mut self, args: &WindowsTunnelPrepareStorageArgs) -> DomainResult<()>;

    fn start(&mut self, args: &WindowsTunnelStartArgs) -> DomainResult<WindowsTunnelCommandResult>;

    fn status(
        &mut self,
        args: &WindowsTunnelStatusArgs,
    ) -> DomainResult<WindowsTunnelCommandResult>;

    fn stop(&mut self, args: &WindowsTunnelStopArgs) -> DomainResult<WindowsTunnelCommandResult>;
}

/// Narrow lifecycle boundary used by the CLI bridge and deterministic tests.
pub trait WindowsTunnelLifecyclePort {
    fn start(&mut self, request: WindowsTunnelStartRequest) -> DomainResult<WindowsTunnelState>;

    fn status(&mut self, state_path: &Path) -> DomainResult<WindowsTunnelState>;

    fn stop(&mut self, state_path: &Path, confirm: bool) -> DomainResult<WindowsTunnelState>;
}

impl<P, C, R> WindowsTunnelLifecyclePort for WindowsTunnelSessionService<P, C, R>
where
    P: EasyTierProcessRunner,
    C: EasyTierCliRunner,
    R: WindowsRoutePort,
{
    fn start(&mut self, request: WindowsTunnelStartRequest) -> DomainResult<WindowsTunnelState> {
        WindowsTunnelSessionService::start(self, request)
    }

    fn status(&mut self, state_path: &Path) -> DomainResult<WindowsTunnelState> {
        WindowsTunnelSessionService::status(self, state_path)
    }

    fn stop(&mut self, state_path: &Path, confirm: bool) -> DomainResult<WindowsTunnelState> {
        WindowsTunnelSessionService::stop(self, state_path, confirm)
    }
}

/// Loads and verifies the signed delivery pair needed to start one tunnel.
pub trait WindowsTunnelDeliveryLoader {
    fn load_plan(&self, args: &WindowsTunnelStartArgs) -> DomainResult<WindowsTunnelPlan>;
}

/// Supplies the platform elevation check without granting a lifecycle port more authority.
pub trait WindowsTunnelPrivilegePort {
    fn is_elevated(&self) -> bool;
}

/// Guarded local paths approved for one foreground tunnel start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelStartInputPaths {
    pub state_path: PathBuf,
    pub network_secret_file: PathBuf,
    pub easytier_binary: PathBuf,
    pub easytier_cli: PathBuf,
}

/// Separates native input storage authority from the delivery and lifecycle ports.
pub trait WindowsTunnelInputPathPolicy {
    fn prepare_storage(&self) -> DomainResult<()>;

    fn prepare_start(
        &self,
        state_path: &Path,
        network_secret_file: &Path,
        easytier_binary: &Path,
        easytier_cli: &Path,
    ) -> DomainResult<TunnelStartInputPaths>;

    fn validate_existing_state(&self, state_path: &Path) -> DomainResult<PathBuf>;
}

/// Connects verified delivery and explicit Windows lifecycle operations to CLI commands.
pub struct DeliveryBackedWindowsTunnelCommandService<S, L, P, G> {
    session: S,
    delivery: L,
    privilege: P,
    paths: G,
}

impl<S, L, P, G> DeliveryBackedWindowsTunnelCommandService<S, L, P, G> {
    pub fn new(session: S, delivery: L, privilege: P, paths: G) -> Self {
        Self {
            session,
            delivery,
            privilege,
            paths,
        }
    }
}

impl<S, L, P, G> WindowsTunnelCommandService
    for DeliveryBackedWindowsTunnelCommandService<S, L, P, G>
where
    S: WindowsTunnelLifecyclePort,
    L: WindowsTunnelDeliveryLoader,
    P: WindowsTunnelPrivilegePort,
    G: WindowsTunnelInputPathPolicy,
{
    fn prepare_storage(&mut self, args: &WindowsTunnelPrepareStorageArgs) -> DomainResult<()> {
        if !self.privilege.is_elevated() {
            return Err(admin_required_error());
        }
        if !args.confirm {
            return Err(confirmation_required_error());
        }

        self.paths.prepare_storage()
    }

    fn start(&mut self, args: &WindowsTunnelStartArgs) -> DomainResult<WindowsTunnelCommandResult> {
        if !self.privilege.is_elevated() {
            return Err(admin_required_error());
        }
        if !args.confirm {
            return Err(confirmation_required_error());
        }

        let guarded = self.paths.prepare_start(
            &args.state_path,
            &args.network_secret_file,
            &args.easytier_binary,
            &args.easytier_cli,
        )?;
        let plan = self.delivery.load_plan(args)?;
        let state = self.session.start(WindowsTunnelStartRequest {
            plan,
            easytier_binary: guarded.easytier_binary,
            easytier_cli: guarded.easytier_cli,
            easytier_version: args.easytier_version.clone(),
            easytier_sha256: args.easytier_sha256.clone(),
            easytier_cli_sha256: args.easytier_cli_sha256.clone(),
            network_name: args.network_name.clone(),
            network_secret_file: guarded.network_secret_file,
            state_path: guarded.state_path,
            confirm: args.confirm,
        })?;
        Ok(running_tunnel_result(state))
    }

    fn status(
        &mut self,
        args: &WindowsTunnelStatusArgs,
    ) -> DomainResult<WindowsTunnelCommandResult> {
        if !self.privilege.is_elevated() {
            return Err(admin_required_error());
        }

        let state_path = self.paths.validate_existing_state(&args.state_path)?;
        self.session.status(&state_path).map(running_tunnel_result)
    }

    fn stop(&mut self, args: &WindowsTunnelStopArgs) -> DomainResult<WindowsTunnelCommandResult> {
        if !self.privilege.is_elevated() {
            return Err(admin_required_error());
        }

        let state_path = self.paths.validate_existing_state(&args.state_path)?;
        self.session
            .stop(&state_path, args.confirm)
            .map(stopped_tunnel_result)
    }
}

fn running_tunnel_result(state: WindowsTunnelState) -> WindowsTunnelCommandResult {
    WindowsTunnelCommandResult {
        route_count: state.runtime_ownership.route_cidrs.len(),
        state,
        peer_ready: true,
        route_ready: true,
    }
}

fn stopped_tunnel_result(state: WindowsTunnelState) -> WindowsTunnelCommandResult {
    WindowsTunnelCommandResult {
        state,
        peer_ready: false,
        route_ready: false,
        route_count: 0,
    }
}

fn admin_required_error() -> DomainError {
    DomainError::new(
        WINDOWS_TUNNEL_ADMIN_REQUIRED_CODE,
        "elevated Windows execution is required",
    )
}

fn confirmation_required_error() -> DomainError {
    DomainError::new(
        WINDOWS_TUNNEL_CONFIRMATION_REQUIRED_CODE,
        "tunnel mutation requires explicit confirmation",
    )
}

fn delivery_invalid_error() -> DomainError {
    DomainError::new(
        WINDOWS_TUNNEL_DELIVERY_INVALID_CODE,
        "signed tunnel delivery is invalid",
    )
}

fn delivery_expired_error() -> DomainError {
    DomainError::new(
        WINDOWS_TUNNEL_DELIVERY_EXPIRED_CODE,
        "signed tunnel delivery has expired",
    )
}

fn map_delivery_verification_error(error: DomainError) -> DomainError {
    if error.code == SDWAN_DELIVERY_EXPIRED_CODE {
        delivery_expired_error()
    } else {
        delivery_invalid_error()
    }
}

/// Native delivery loader that accepts exactly 32 raw Ed25519 public-key bytes.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeWindowsTunnelDeliveryLoader;

impl WindowsTunnelDeliveryLoader for NativeWindowsTunnelDeliveryLoader {
    fn load_plan(&self, args: &WindowsTunnelStartArgs) -> DomainResult<WindowsTunnelPlan> {
        let now = OffsetDateTime::now_utc();
        let public_key =
            fs::read(&args.delivery_public_key_file).map_err(|_| delivery_invalid_error())?;
        let verifier =
            SdwanDeliveryVerifier::new(&public_key).map_err(|_| delivery_invalid_error())?;
        let client_bytes = fs::read(&args.client_envelope).map_err(|_| delivery_invalid_error())?;
        let pop_bytes = fs::read(&args.pop_envelope).map_err(|_| delivery_invalid_error())?;
        let client = verifier
            .verify_json(&client_bytes, now)
            .map_err(map_delivery_verification_error)?;
        let pop = verifier
            .verify_json(&pop_bytes, now)
            .map_err(map_delivery_verification_error)?;

        let ledger = NativeWindowsTunnelSequenceLedger;
        let floors = ledger.read_floors(&client, &pop).map_err(|error| {
            if error.code == WINDOWS_TUNNEL_SEQUENCE_REPLAYED_CODE {
                error
            } else {
                DomainError::new(
                    WINDOWS_TUNNEL_DELIVERY_INVALID_CODE,
                    "signed tunnel delivery is invalid",
                )
            }
        })?;
        let plan = plan_windows_tunnel(WindowsTunnelPlanRequest {
            client: &client,
            pop: &pop,
            device_id: &args.device_id,
            selected_pop_id: &args.pop_id,
            last_client_sequence: floors.client,
            last_pop_sequence: floors.pop,
            now,
        })?;
        ledger.reserve_pair(&client, &pop).map_err(|error| {
            if error.code == WINDOWS_TUNNEL_SEQUENCE_REPLAYED_CODE {
                error
            } else {
                DomainError::new(
                    WINDOWS_TUNNEL_DELIVERY_INVALID_CODE,
                    "signed tunnel delivery is invalid",
                )
            }
        })?;
        Ok(plan)
    }
}

/// Native privilege adapter with no independent platform behavior.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeWindowsTunnelPrivilegeChecker;

impl WindowsTunnelPrivilegePort for NativeWindowsTunnelPrivilegeChecker {
    fn is_elevated(&self) -> bool {
        native_windows_is_elevated()
    }
}

/// Native secure-storage adapter used only by the production Windows tunnel bridge.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeWindowsTunnelInputPathPolicy;

impl WindowsTunnelInputPathPolicy for NativeWindowsTunnelInputPathPolicy {
    fn prepare_storage(&self) -> DomainResult<()> {
        native_windows_prepare_tunnel_secure_paths().map(|_| ())
    }

    fn prepare_start(
        &self,
        state_path: &Path,
        network_secret_file: &Path,
        easytier_binary: &Path,
        easytier_cli: &Path,
    ) -> DomainResult<TunnelStartInputPaths> {
        Ok(TunnelStartInputPaths {
            state_path: native_windows_prepare_state_path(state_path)?,
            network_secret_file: native_windows_prepare_secret_file(network_secret_file)?,
            easytier_binary: native_windows_prepare_easytier_artifact(easytier_binary)?,
            easytier_cli: native_windows_prepare_easytier_artifact(easytier_cli)?,
        })
    }

    fn validate_existing_state(&self, state_path: &Path) -> DomainResult<PathBuf> {
        native_windows_validate_existing_state_path(state_path)
    }
}

pub type NativeWindowsTunnelCommandService = DeliveryBackedWindowsTunnelCommandService<
    WindowsTunnelSessionService<
        NativeEasyTierProcessRunner,
        NativeEasyTierCliRunner,
        NativeWindowsRoutePort,
    >,
    NativeWindowsTunnelDeliveryLoader,
    NativeWindowsTunnelPrivilegeChecker,
    NativeWindowsTunnelInputPathPolicy,
>;

#[cfg(windows)]
fn native_windows_route_port() -> NativeWindowsRoutePort {
    NativeWindowsRoutePort::default()
}

#[cfg(not(windows))]
fn native_windows_route_port() -> NativeWindowsRoutePort {
    NativeWindowsRoutePort
}

/// Produces the only native production bridge used by the tunnel CLI variants.
pub fn native_windows_tunnel_command_service() -> NativeWindowsTunnelCommandService {
    DeliveryBackedWindowsTunnelCommandService::new(
        WindowsTunnelSessionService::new(
            NativeEasyTierProcessRunner::default(),
            NativeEasyTierCliRunner,
            native_windows_route_port(),
        ),
        NativeWindowsTunnelDeliveryLoader,
        NativeWindowsTunnelPrivilegeChecker,
        NativeWindowsTunnelInputPathPolicy,
    )
}

// The public parser contract requires direct typed tuple variants, not boxed indirection.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowsCliCommand {
    Help { format: OutputFormat },
    Version { format: OutputFormat },
    Capabilities { format: OutputFormat },
    Status { format: OutputFormat },
    Diagnostics { format: OutputFormat },
    TunnelPrepareStorage(WindowsTunnelPrepareStorageArgs),
    TunnelStart(WindowsTunnelStartArgs),
    TunnelStatus(WindowsTunnelStatusArgs),
    TunnelStop(WindowsTunnelStopArgs),
}

impl WindowsCliCommand {
    pub const fn format(&self) -> OutputFormat {
        match self {
            Self::Help { format }
            | Self::Version { format }
            | Self::Capabilities { format }
            | Self::Status { format }
            | Self::Diagnostics { format } => *format,
            Self::TunnelPrepareStorage(args) => args.format(),
            Self::TunnelStart(args) => args.format(),
            Self::TunnelStatus(args) => args.format(),
            Self::TunnelStop(args) => args.format(),
        }
    }

    pub const fn name(&self) -> &'static str {
        match self {
            Self::Help { .. } => "help",
            Self::Version { .. } => "version",
            Self::Capabilities { .. } => "capabilities",
            Self::Status { .. } => "status",
            Self::Diagnostics { .. } => "diagnostics",
            Self::TunnelPrepareStorage(_)
            | Self::TunnelStart(_)
            | Self::TunnelStatus(_)
            | Self::TunnelStop(_) => "tunnel",
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
    pub foreground_tunnel: WindowsFeatureReport,
    pub service: WindowsFeatureReport,
    pub driver: WindowsFeatureReport,
    pub installer: WindowsFeatureReport,
    pub system_proxy_mutation: WindowsFeatureReport,
    pub trust_store_mutation: WindowsFeatureReport,
    pub https_mitm: WindowsFeatureReport,
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
            foreground_tunnel: WindowsFeatureReport::from(&snapshot.foreground_tunnel),
            service: WindowsFeatureReport::from(&snapshot.service),
            driver: WindowsFeatureReport::from(&snapshot.driver),
            installer: WindowsFeatureReport::from(&snapshot.installer),
            system_proxy_mutation: WindowsFeatureReport::from(&snapshot.system_proxy_mutation),
            trust_store_mutation: WindowsFeatureReport::from(&snapshot.trust_store_mutation),
            https_mitm: WindowsFeatureReport::from(&snapshot.https_mitm),
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
    pub foreground_tunnel: &'static str,
    pub service: &'static str,
    pub driver: &'static str,
    pub installer: &'static str,
    pub system_proxy_mutation: &'static str,
    pub trust_store_mutation: &'static str,
    pub https_mitm: &'static str,
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
            foreground_tunnel: snapshot.foreground_tunnel.status,
            service: snapshot.service.status,
            driver: snapshot.driver.status,
            installer: snapshot.installer.status,
            system_proxy_mutation: snapshot.system_proxy_mutation.status,
            trust_store_mutation: snapshot.trust_store_mutation.status,
            https_mitm: snapshot.https_mitm.status,
            script_dispatch: snapshot.script_dispatch.status,
            managed_lifecycle: snapshot.managed_lifecycle.status,
            system_mutation_policy: WINDOWS_SYSTEM_MUTATION_POLICY,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WindowsTunnelReport {
    pub session_id: String,
    pub selected_pop_id: String,
    pub selected_endpoint: String,
    pub plan_digest: String,
    pub client_bundle_id: String,
    pub client_sequence: u64,
    pub pop_bundle_id: String,
    pub pop_sequence: u64,
    pub easytier_version: String,
    pub state: WindowsTunnelLifecycleState,
    pub peer_ready: bool,
    pub route_ready: bool,
    pub route_count: usize,
    pub rollback_status: String,
    pub system_mutation_policy: &'static str,
}

impl From<WindowsTunnelCommandResult> for WindowsTunnelReport {
    fn from(result: WindowsTunnelCommandResult) -> Self {
        Self {
            session_id: result.state.session_id,
            selected_pop_id: result.state.selected_pop_id,
            selected_endpoint: result.state.selected_endpoint,
            plan_digest: result.state.plan_digest,
            client_bundle_id: result.state.client_bundle_id,
            client_sequence: result.state.client_sequence,
            pop_bundle_id: result.state.pop_bundle_id,
            pop_sequence: result.state.pop_sequence,
            easytier_version: result.state.easytier_version,
            state: result.state.state,
            peer_ready: result.peer_ready,
            route_ready: result.route_ready,
            route_count: result.route_count,
            rollback_status: result.state.rollback_status,
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
    pub tunnel: Option<WindowsTunnelReport>,
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
            tunnel: None,
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
            tunnel: None,
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

    fn with_tunnel(mut self, tunnel: WindowsTunnelReport) -> Self {
        self.tunnel = Some(tunnel);
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
    match command.as_str() {
        "tunnel" => parse_tunnel_command(&values, format),
        "help" | "--help" | "-h" => {
            reject_legacy_command_arguments(&values)?;
            Ok(WindowsCliCommand::Help { format })
        }
        "version" | "--version" | "-V" => {
            reject_legacy_command_arguments(&values)?;
            Ok(WindowsCliCommand::Version { format })
        }
        "capabilities" => {
            reject_legacy_command_arguments(&values)?;
            Ok(WindowsCliCommand::Capabilities { format })
        }
        "status" => {
            reject_legacy_command_arguments(&values)?;
            Ok(WindowsCliCommand::Status { format })
        }
        "diagnostics" => {
            reject_legacy_command_arguments(&values)?;
            Ok(WindowsCliCommand::Diagnostics { format })
        }
        unknown => Err(parse_error(
            CLI_WINDOWS_ARGUMENT_UNKNOWN_CODE,
            format!("unknown windows CLI command: {unknown}"),
        )),
    }
}

fn reject_legacy_command_arguments(values: &[String]) -> Result<(), WindowsCliParseError> {
    if values.is_empty() {
        return Ok(());
    }

    Err(parse_error(
        CLI_WINDOWS_ARGUMENT_UNKNOWN_CODE,
        format!("unknown windows CLI argument: {}", values[0]),
    ))
}

fn parse_tunnel_command(
    values: &[String],
    format: OutputFormat,
) -> Result<WindowsCliCommand, WindowsCliParseError> {
    let (subcommand, values) = values.split_first().ok_or_else(|| {
        tunnel_parse_error(
            CLI_WINDOWS_ARGUMENT_VALUE_MISSING_CODE,
            "tunnel requires a prepare-storage, start, status, or stop command",
        )
    })?;

    match subcommand.as_str() {
        "prepare-storage" => parse_tunnel_prepare_storage_command(values, format),
        "start" => parse_tunnel_start_command(values, format),
        "status" => parse_tunnel_status_command(values, format),
        "stop" => parse_tunnel_stop_command(values, format),
        _ => Err(tunnel_parse_error(
            CLI_WINDOWS_ARGUMENT_UNKNOWN_CODE,
            "unknown tunnel command",
        )),
    }
}

fn parse_tunnel_prepare_storage_command(
    values: &[String],
    format: OutputFormat,
) -> Result<WindowsCliCommand, WindowsCliParseError> {
    let mut confirm = false;

    for value in values {
        match value.as_str() {
            "--confirm" => {
                if confirm {
                    return Err(tunnel_parse_error(
                        CLI_WINDOWS_ARGUMENT_UNKNOWN_CODE,
                        "tunnel option --confirm may only be specified once",
                    ));
                }
                confirm = true;
            }
            _ if value.starts_with('-') => {
                return Err(tunnel_parse_error(
                    CLI_WINDOWS_ARGUMENT_UNKNOWN_CODE,
                    "tunnel command contains an unsupported option",
                ));
            }
            _ => {
                return Err(tunnel_parse_error(
                    CLI_WINDOWS_ARGUMENT_UNKNOWN_CODE,
                    "tunnel prepare-storage received an unexpected positional argument",
                ));
            }
        }
    }

    if !confirm {
        return Err(tunnel_parse_error(
            CLI_WINDOWS_ARGUMENT_VALUE_MISSING_CODE,
            "tunnel mutations require --confirm",
        ));
    }

    Ok(WindowsCliCommand::TunnelPrepareStorage(
        WindowsTunnelPrepareStorageArgs { confirm, format },
    ))
}

fn parse_tunnel_start_command(
    values: &[String],
    format: OutputFormat,
) -> Result<WindowsCliCommand, WindowsCliParseError> {
    let mut positional = Vec::new();
    let mut pop_id = None;
    let mut device_id = None;
    let mut delivery_public_key_file = None;
    let mut easytier_binary = None;
    let mut easytier_cli = None;
    let mut easytier_version = None;
    let mut easytier_sha256 = None;
    let mut easytier_cli_sha256 = None;
    let mut network_name = None;
    let mut network_secret_file = None;
    let mut state_path = None;
    let mut confirm = false;
    let mut index = 0;

    while index < values.len() {
        let value = &values[index];
        if !value.starts_with('-') {
            positional.push(value.clone());
            index += 1;
            continue;
        }

        match value.as_str() {
            "--pop-id" => take_tunnel_option_value(&mut pop_id, values, &mut index, "--pop-id")?,
            "--device-id" => {
                take_tunnel_option_value(&mut device_id, values, &mut index, "--device-id")?
            }
            "--delivery-public-key-file" => take_tunnel_option_value(
                &mut delivery_public_key_file,
                values,
                &mut index,
                "--delivery-public-key-file",
            )?,
            "--easytier-bin" => take_tunnel_option_value(
                &mut easytier_binary,
                values,
                &mut index,
                "--easytier-bin",
            )?,
            "--easytier-cli" => {
                take_tunnel_option_value(&mut easytier_cli, values, &mut index, "--easytier-cli")?
            }
            "--easytier-version" => take_tunnel_option_value(
                &mut easytier_version,
                values,
                &mut index,
                "--easytier-version",
            )?,
            "--easytier-sha256" => take_tunnel_option_value(
                &mut easytier_sha256,
                values,
                &mut index,
                "--easytier-sha256",
            )?,
            "--easytier-cli-sha256" => take_tunnel_option_value(
                &mut easytier_cli_sha256,
                values,
                &mut index,
                "--easytier-cli-sha256",
            )?,
            "--network-name" => {
                take_tunnel_option_value(&mut network_name, values, &mut index, "--network-name")?
            }
            "--network-secret-file" => take_tunnel_option_value(
                &mut network_secret_file,
                values,
                &mut index,
                "--network-secret-file",
            )?,
            "--state-path" => {
                take_tunnel_option_value(&mut state_path, values, &mut index, "--state-path")?
            }
            "--confirm" => {
                if confirm {
                    return Err(tunnel_parse_error(
                        CLI_WINDOWS_ARGUMENT_UNKNOWN_CODE,
                        "tunnel option --confirm may only be specified once",
                    ));
                }
                confirm = true;
                index += 1;
            }
            _ => {
                return Err(tunnel_parse_error(
                    CLI_WINDOWS_ARGUMENT_UNKNOWN_CODE,
                    "tunnel command contains an unsupported option",
                ));
            }
        }
    }

    let mut positional = positional.into_iter();
    let client_envelope = positional.next().ok_or_else(|| {
        tunnel_parse_error(
            CLI_WINDOWS_ARGUMENT_VALUE_MISSING_CODE,
            "tunnel start requires client and POP envelope paths",
        )
    })?;
    let pop_envelope = positional.next().ok_or_else(|| {
        tunnel_parse_error(
            CLI_WINDOWS_ARGUMENT_VALUE_MISSING_CODE,
            "tunnel start requires client and POP envelope paths",
        )
    })?;
    if positional.next().is_some() {
        return Err(tunnel_parse_error(
            CLI_WINDOWS_ARGUMENT_UNKNOWN_CODE,
            "tunnel start received an unexpected positional argument",
        ));
    }

    let state_path = require_tunnel_start_option(state_path, "--state-path", true)?;
    let network_secret_file =
        require_tunnel_start_option(network_secret_file, "--network-secret-file", false)?;
    if !confirm {
        return Err(tunnel_parse_error(
            CLI_WINDOWS_ARGUMENT_VALUE_MISSING_CODE,
            "tunnel mutations require --confirm",
        ));
    }

    Ok(WindowsCliCommand::TunnelStart(WindowsTunnelStartArgs {
        client_envelope: PathBuf::from(client_envelope),
        pop_envelope: PathBuf::from(pop_envelope),
        pop_id: require_tunnel_start_option(pop_id, "--pop-id", false)?,
        device_id: require_tunnel_start_option(device_id, "--device-id", false)?,
        delivery_public_key_file: PathBuf::from(require_tunnel_start_option(
            delivery_public_key_file,
            "--delivery-public-key-file",
            false,
        )?),
        easytier_binary: PathBuf::from(require_tunnel_start_option(
            easytier_binary,
            "--easytier-bin",
            false,
        )?),
        easytier_cli: PathBuf::from(require_tunnel_start_option(
            easytier_cli,
            "--easytier-cli",
            false,
        )?),
        easytier_version: require_tunnel_start_option(
            easytier_version,
            "--easytier-version",
            false,
        )?,
        easytier_sha256: require_tunnel_start_option(easytier_sha256, "--easytier-sha256", false)?,
        easytier_cli_sha256: require_tunnel_start_option(
            easytier_cli_sha256,
            "--easytier-cli-sha256",
            false,
        )?,
        network_name: require_tunnel_start_option(network_name, "--network-name", false)?,
        network_secret_file: PathBuf::from(network_secret_file),
        state_path: PathBuf::from(state_path),
        confirm,
        format,
    }))
}

fn parse_tunnel_status_command(
    values: &[String],
    format: OutputFormat,
) -> Result<WindowsCliCommand, WindowsCliParseError> {
    let state_path = parse_tunnel_state_path(values)?;
    Ok(WindowsCliCommand::TunnelStatus(WindowsTunnelStatusArgs {
        state_path,
        format,
    }))
}

fn parse_tunnel_stop_command(
    values: &[String],
    format: OutputFormat,
) -> Result<WindowsCliCommand, WindowsCliParseError> {
    let mut state_path = None;
    let mut confirm = false;

    for value in values {
        match value.as_str() {
            "--confirm" => {
                if confirm {
                    return Err(tunnel_parse_error(
                        CLI_WINDOWS_ARGUMENT_UNKNOWN_CODE,
                        "tunnel option --confirm may only be specified once",
                    ));
                }
                confirm = true;
            }
            _ if value.starts_with('-') => {
                return Err(tunnel_parse_error(
                    CLI_WINDOWS_ARGUMENT_UNKNOWN_CODE,
                    "tunnel command contains an unsupported option",
                ));
            }
            _ if state_path.is_some() => {
                return Err(tunnel_parse_error(
                    CLI_WINDOWS_ARGUMENT_UNKNOWN_CODE,
                    "tunnel stop received an unexpected positional argument",
                ));
            }
            _ => state_path = Some(PathBuf::from(value)),
        }
    }

    let state_path = state_path.ok_or_else(|| {
        tunnel_parse_error(
            CLI_WINDOWS_ARGUMENT_VALUE_MISSING_CODE,
            "tunnel state path is required",
        )
    })?;
    if !confirm {
        return Err(tunnel_parse_error(
            CLI_WINDOWS_ARGUMENT_VALUE_MISSING_CODE,
            "tunnel mutations require --confirm",
        ));
    }

    Ok(WindowsCliCommand::TunnelStop(WindowsTunnelStopArgs {
        state_path,
        confirm,
        format,
    }))
}

fn parse_tunnel_state_path(values: &[String]) -> Result<PathBuf, WindowsCliParseError> {
    let Some((state_path, remaining)) = values.split_first() else {
        return Err(tunnel_parse_error(
            CLI_WINDOWS_ARGUMENT_VALUE_MISSING_CODE,
            "tunnel state path is required",
        ));
    };
    if state_path.starts_with('-') {
        return Err(tunnel_parse_error(
            CLI_WINDOWS_ARGUMENT_VALUE_MISSING_CODE,
            "tunnel state path is required",
        ));
    }
    if !remaining.is_empty() {
        return Err(tunnel_parse_error(
            CLI_WINDOWS_ARGUMENT_UNKNOWN_CODE,
            "tunnel status received an unexpected argument",
        ));
    }

    Ok(PathBuf::from(state_path))
}

fn take_tunnel_option_value(
    target: &mut Option<String>,
    values: &[String],
    index: &mut usize,
    option: &'static str,
) -> Result<(), WindowsCliParseError> {
    if target.is_some() {
        return Err(tunnel_parse_error(
            CLI_WINDOWS_ARGUMENT_UNKNOWN_CODE,
            format!("tunnel option {option} may only be specified once"),
        ));
    }

    let value = values
        .get(*index + 1)
        .filter(|value| !value.starts_with('-'))
        .cloned()
        .ok_or_else(|| {
            tunnel_parse_error(
                CLI_WINDOWS_ARGUMENT_VALUE_MISSING_CODE,
                format!("tunnel option {option} requires a value"),
            )
        })?;
    *target = Some(value);
    *index += 2;
    Ok(())
}

fn require_tunnel_start_option(
    value: Option<String>,
    option: &'static str,
    state_path: bool,
) -> Result<String, WindowsCliParseError> {
    value.ok_or_else(|| {
        let message = if state_path {
            "tunnel state path is required; supply --state-path".to_string()
        } else {
            format!("tunnel start requires {option}")
        };
        tunnel_parse_error(CLI_WINDOWS_ARGUMENT_VALUE_MISSING_CODE, message)
    })
}

pub fn handle_entrypoint(
    command: WindowsCliCommand,
    platform: &impl WindowsPlatformCapabilityService,
) -> WindowsCliResponse {
    let snapshot = platform.snapshot();
    match command {
        WindowsCliCommand::Help { .. } => WindowsCliResponse::success("help"),
        WindowsCliCommand::Version { .. } => {
            WindowsCliResponse::success("version").with_version(WindowsCliVersion {
                package: COMMAND_NAME,
                version: env!("CARGO_PKG_VERSION"),
                source_identity: WINDOWS_CLI_SOURCE_IDENTITY,
                version_scope: WINDOWS_CLI_VERSION_SCOPE,
            })
        }
        WindowsCliCommand::Capabilities { .. } => WindowsCliResponse::success("capabilities")
            .with_capabilities(WindowsCliCapabilities::from_snapshot(&snapshot)),
        WindowsCliCommand::Status { .. } => WindowsCliResponse::success("status")
            .with_status(WindowsCliStatus::from_snapshot(&snapshot)),
        WindowsCliCommand::Diagnostics { .. } => WindowsCliResponse::success("diagnostics")
            .with_status(WindowsCliStatus::from_snapshot(&snapshot))
            .with_diagnostics(windows_cli_diagnostics(&snapshot)),
        WindowsCliCommand::TunnelPrepareStorage(_)
        | WindowsCliCommand::TunnelStart(_)
        | WindowsCliCommand::TunnelStatus(_)
        | WindowsCliCommand::TunnelStop(_) => tunnel_service_unavailable_response(),
    }
}

pub fn handle_entrypoint_with_tunnel<T>(
    command: WindowsCliCommand,
    platform: &impl WindowsPlatformCapabilityService,
    tunnel: &mut T,
) -> WindowsCliResponse
where
    T: WindowsTunnelCommandService,
{
    match command {
        WindowsCliCommand::TunnelPrepareStorage(args) => {
            tunnel_storage_preparation_response(tunnel.prepare_storage(&args))
        }
        WindowsCliCommand::TunnelStart(args) => tunnel_command_response(tunnel.start(&args)),
        WindowsCliCommand::TunnelStatus(args) => tunnel_command_response(tunnel.status(&args)),
        WindowsCliCommand::TunnelStop(args) => tunnel_command_response(tunnel.stop(&args)),
        command => handle_entrypoint(command, platform),
    }
}

fn tunnel_storage_preparation_response(result: DomainResult<()>) -> WindowsCliResponse {
    match result {
        Ok(()) => WindowsCliResponse::success("tunnel"),
        Err(error) => tunnel_service_error_response(error),
    }
}

fn tunnel_command_response(result: DomainResult<WindowsTunnelCommandResult>) -> WindowsCliResponse {
    match result {
        Ok(result) => {
            WindowsCliResponse::success("tunnel").with_tunnel(WindowsTunnelReport::from(result))
        }
        Err(error) => tunnel_service_error_response(error),
    }
}

fn tunnel_service_error_response(error: DomainError) -> WindowsCliResponse {
    WindowsCliResponse::failure(
        "tunnel",
        WindowsCliDiagnostic::new(
            WindowsCliDiagnosticSeverity::Error,
            error.code,
            CLI_WINDOWS_TUNNEL_ERROR_MESSAGE,
            CLI_WINDOWS_TUNNEL_ERROR_SOURCE,
        ),
    )
}

fn tunnel_service_unavailable_response() -> WindowsCliResponse {
    WindowsCliResponse::failure(
        "tunnel",
        WindowsCliDiagnostic::new(
            WindowsCliDiagnosticSeverity::Error,
            CLI_WINDOWS_TUNNEL_UNAVAILABLE_CODE,
            CLI_WINDOWS_TUNNEL_UNAVAILABLE_MESSAGE,
            CLI_WINDOWS_TUNNEL_UNAVAILABLE_SOURCE,
        ),
    )
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
        "  networkcore-windows tunnel prepare-storage --confirm [--format text|json]",
        "  networkcore-windows tunnel start <client-envelope> <pop-envelope> --pop-id <id> --device-id <id> --delivery-public-key-file <path> --easytier-bin <path> --easytier-cli <path> --easytier-version <version> --easytier-sha256 <sha256> --easytier-cli-sha256 <sha256> --network-name <name> --network-secret-file <path> --state-path <path> --confirm [--format text|json]",
        "  networkcore-windows tunnel status <state-path> [--format text|json]",
        "  networkcore-windows tunnel stop <state-path> --confirm [--format text|json]",
        "",
        "Current boundary:",
        "  artifact_gate: windows-managed-client-active",
        "  source_identity: apps/windows-cli",
        "  install_model: wix-per-machine-msi",
        "  system_mutation_policy: managed-apply-and-rollback",
        "",
        "Foreground tunnel boundary:",
        "  Requires a preinstalled EasyTier installation and elevated execution.",
        "  Tunnel mutations require --confirm.",
        "  Prepare storage before creating the direct-child secret file.",
        "  Tunnel status requires elevated execution for live ownership proof.",
        "",
        "Managed client:",
        "  windows-service, signed-inf-driver-package, windows-installer, system-proxy-mutation,",
        "  system-trust-store-mutation, controlled-http1-https-mitm, and managed-daemon-lifecycle are active.",
        "  javascript-script-dispatch remains blocked.",
    ]
    .join("\n")
}

fn parse_output_format(values: &mut Vec<String>) -> Result<OutputFormat, WindowsCliParseError> {
    let mut format = OutputFormat::Text;
    let mut seen_format = false;
    let mut index = 0;
    while index < values.len() {
        if values[index] == "--format" {
            if seen_format {
                return Err(parse_error(
                    CLI_WINDOWS_ARGUMENT_UNKNOWN_CODE,
                    "windows CLI --format may only be specified once",
                ));
            }
            let value = values
                .get(index + 1)
                .filter(|value| !value.starts_with('-'))
                .cloned()
                .ok_or_else(|| {
                    parse_error(
                        CLI_WINDOWS_ARGUMENT_VALUE_MISSING_CODE,
                        "windows CLI --format requires text or json",
                    )
                })?;
            format = match value.as_str() {
                "text" => OutputFormat::Text,
                "json" => OutputFormat::Json,
                _ => {
                    return Err(parse_error(
                        CLI_WINDOWS_OUTPUT_FORMAT_UNSUPPORTED_CODE,
                        "unsupported windows CLI output format",
                    ))
                }
            };
            seen_format = true;
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

fn tunnel_parse_error(code: impl Into<String>, message: impl Into<String>) -> WindowsCliParseError {
    WindowsCliParseError::new(WindowsCliDiagnostic::new(
        WindowsCliDiagnosticSeverity::Error,
        code,
        message,
        "cli.windows.tunnel.argument",
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
            CLI_WINDOWS_SYSTEM_INTEGRATION_ACTIVE_CODE,
            "Windows GUI, service, signed INF driver package lifecycle, MSI installer, system proxy mutation, trust store mutation, controlled HTTP/1.1 HTTPS MITM, and managed daemon lifecycle are active.",
            "cli.windows.system",
        ),
        WindowsCliDiagnostic::new(
            WindowsCliDiagnosticSeverity::Info,
            CLI_WINDOWS_SUBSCRIPTION_DEFERRED_CODE,
            "Shared subscription parser gates are active in config-core, but Windows subscription run compatibility remains deferred to later v0.1.1 alpha slices.",
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
        lines.push(format!(
            "foreground_tunnel: {}",
            capabilities.foreground_tunnel.status
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
        lines.push(format!("https_mitm: {}", capabilities.https_mitm.status));
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
        lines.push(format!("foreground_tunnel: {}", status.foreground_tunnel));
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
        lines.push(format!("https_mitm: {}", status.https_mitm));
        lines.push(format!("script_dispatch: {}", status.script_dispatch));
        lines.push(format!("managed_lifecycle: {}", status.managed_lifecycle));
        lines.push(format!(
            "system_mutation_policy: {}",
            status.system_mutation_policy
        ));
    }

    if let Some(tunnel) = &response.tunnel {
        lines.push(format!("session_id: {}", tunnel.session_id));
        lines.push(format!("selected_pop_id: {}", tunnel.selected_pop_id));
        lines.push(format!("selected_endpoint: {}", tunnel.selected_endpoint));
        lines.push(format!("plan_digest: {}", tunnel.plan_digest));
        lines.push(format!("client_bundle_id: {}", tunnel.client_bundle_id));
        lines.push(format!("client_sequence: {}", tunnel.client_sequence));
        lines.push(format!("pop_bundle_id: {}", tunnel.pop_bundle_id));
        lines.push(format!("pop_sequence: {}", tunnel.pop_sequence));
        lines.push(format!("easytier_version: {}", tunnel.easytier_version));
        lines.push(format!("state: {}", tunnel_state_name(tunnel.state)));
        lines.push(format!("peer_ready: {}", tunnel.peer_ready));
        lines.push(format!("route_ready: {}", tunnel.route_ready));
        lines.push(format!("route_count: {}", tunnel.route_count));
        lines.push(format!("rollback_status: {}", tunnel.rollback_status));
        lines.push(format!(
            "system_mutation_policy: {}",
            tunnel.system_mutation_policy
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

fn tunnel_state_name(state: WindowsTunnelLifecycleState) -> &'static str {
    match state {
        WindowsTunnelLifecycleState::Starting => "starting",
        WindowsTunnelLifecycleState::Running => "running",
        WindowsTunnelLifecycleState::Stopping => "stopping",
        WindowsTunnelLifecycleState::Stopped => "stopped",
        WindowsTunnelLifecycleState::Failed => "failed",
    }
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
    tunnel: Option<&'a WindowsTunnelReport>,
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
            tunnel: response.tunnel.as_ref(),
        }
    }
}

fn render_json_response(response: &WindowsCliResponse) -> String {
    serde_json::to_string_pretty(&JsonWindowsCliResponse::from(response))
        .expect("windows CLI response JSON serialization should be infallible")
}
