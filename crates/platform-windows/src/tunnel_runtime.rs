//! Foreground EasyTier session orchestration and route-safety ports.
//!
//! The generic service owns only processes and route bypasses that it starts in
//! the current instance or rehydrates through an exact injected proof. It never
//! discovers, adopts, or terminates arbitrary system processes.

use control_domain::{DomainError, DomainResult};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[cfg(windows)]
use std::collections::BTreeSet;
#[cfg(windows)]
use std::io;
#[cfg(windows)]
use std::net::Ipv4Addr;
#[cfg(windows)]
use std::process::{Command, Stdio};

use crate::tunnel_config::{
    canonical_destination_ipv4_cidrs, is_safe_tunnel_file_name, read_tunnel_state,
    render_easytier_config, verify_file_sha256, write_tunnel_state, EasyTierConfigRequest,
    EasyTierLaunchSpec, OwnedProcessHandle, WindowsRouteSnapshotEntry, WindowsTunnelLifecycleState,
    WindowsTunnelRuntimeOwnership, WindowsTunnelState,
};
#[cfg(windows)]
use crate::tunnel_security::{
    native_windows_hardened_command, native_windows_system_command,
    native_windows_validate_existing_easytier_artifact, NativeWindowsSystemTool,
};
use crate::WindowsTunnelPlan;

pub const WINDOWS_TUNNEL_CONFIRMATION_REQUIRED_CODE: &str = "windows.tunnel.confirmation_required";
pub const WINDOWS_TUNNEL_ADMIN_REQUIRED_CODE: &str = "windows.tunnel.admin_required";
pub const WINDOWS_TUNNEL_SECRET_FILE_INVALID_CODE: &str = "windows.tunnel.secret_file_invalid";
pub const WINDOWS_TUNNEL_EASYTIER_VERSION_MISMATCH_CODE: &str =
    "windows.tunnel.easytier_version_mismatch";
pub const WINDOWS_TUNNEL_ENDPOINT_BYPASS_FAILED_CODE: &str =
    "windows.tunnel.endpoint_bypass_failed";
pub const WINDOWS_TUNNEL_START_FAILED_CODE: &str = "windows.tunnel.start_failed";
pub const WINDOWS_TUNNEL_PEER_NOT_READY_CODE: &str = "windows.tunnel.peer_not_ready";
pub const WINDOWS_TUNNEL_ROUTE_NOT_READY_CODE: &str = "windows.tunnel.route_not_ready";
pub const WINDOWS_TUNNEL_STATUS_UNAVAILABLE_CODE: &str = "windows.tunnel.status_unavailable";
pub const WINDOWS_TUNNEL_STOP_FAILED_CODE: &str = "windows.tunnel.stop_failed";
pub const WINDOWS_TUNNEL_ROLLBACK_FAILED_CODE: &str = "windows.tunnel.rollback_failed";
pub const WINDOWS_TUNNEL_OWNERSHIP_MISMATCH_CODE: &str = "windows.tunnel.ownership_mismatch";

#[cfg(windows)]
pub fn native_windows_is_elevated() -> bool {
    use windows_sys::Win32::UI::Shell::IsUserAnAdmin;

    unsafe { IsUserAnAdmin() != 0 }
}

#[cfg(not(windows))]
pub fn native_windows_is_elevated() -> bool {
    false
}

/// Starts and stops only an EasyTier process created by the current session service.
pub trait EasyTierProcessRunner {
    fn start(&mut self, spec: &EasyTierLaunchSpec) -> DomainResult<OwnedProcessHandle>;
    fn recover(&mut self, spec: &EasyTierRecoverySpec) -> DomainResult<RecoveredEasyTierProcess>;
    fn recover_for_cleanup(
        &mut self,
        spec: &EasyTierRecoverySpec,
    ) -> DomainResult<EasyTierCleanupRecovery> {
        self.recover(spec).map(EasyTierCleanupRecovery::Present)
    }
    fn stop(&mut self, handle: &OwnedProcessHandle) -> DomainResult<()>;
}

/// Exact persisted process and artifact proof required for a fresh service instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EasyTierRecoverySpec {
    pub expected_process: OwnedProcessHandle,
    pub expected_binary_sha256: String,
    pub expected_cli_sha256: String,
    pub config_path: PathBuf,
    pub cli_file_name: String,
}

/// A process proven by the injected platform runner for a persisted session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredEasyTierProcess {
    pub process: OwnedProcessHandle,
    pub binary_path: PathBuf,
    pub cli_path: PathBuf,
}

/// Exact cleanup recovery result for a persisted EasyTier process proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EasyTierCleanupRecovery {
    Present(RecoveredEasyTierProcess),
    Absent,
}

/// Queries one explicitly configured EasyTier CLI executable.
pub trait EasyTierCliRunner {
    fn version(&mut self, path: &Path, expected_sha256: &str) -> DomainResult<String>;
    fn peer_ready(&mut self, path: &Path, expected_sha256: &str) -> DomainResult<bool>;
    fn route_cidrs(&mut self, path: &Path, expected_sha256: &str) -> DomainResult<Vec<String>>;
}

/// Owns the physical underlay bypass route transaction for a foreground session.
pub trait WindowsRoutePort {
    fn snapshot(&mut self, endpoints: &[IpAddr]) -> DomainResult<Vec<WindowsRouteSnapshotEntry>>;
    fn add_endpoint_bypass(&mut self, endpoints: &[IpAddr]) -> DomainResult<()>;
    fn recover_owned_bypass(&mut self, snapshot: &[WindowsRouteSnapshotEntry]) -> DomainResult<()>;
    fn recover_cleanup_bypass(
        &mut self,
        snapshot: &[WindowsRouteSnapshotEntry],
    ) -> DomainResult<()> {
        self.recover_owned_bypass(snapshot)
    }
    fn restore(&mut self, snapshot: &[WindowsRouteSnapshotEntry]) -> DomainResult<()>;
    fn snapshot_destination_routes(
        &mut self,
        destination_cidrs: &[String],
    ) -> DomainResult<Vec<WindowsRouteSnapshotEntry>>;
    fn capture_owned_destination_routes(
        &mut self,
        before: &[WindowsRouteSnapshotEntry],
        destination_cidrs: &[String],
    ) -> DomainResult<Vec<WindowsRouteSnapshotEntry>>;
    fn recover_owned_destination_routes(
        &mut self,
        owned: &[WindowsRouteSnapshotEntry],
    ) -> DomainResult<()>;
    fn recover_cleanup_destination_routes(
        &mut self,
        owned: &[WindowsRouteSnapshotEntry],
    ) -> DomainResult<()> {
        self.recover_owned_destination_routes(owned)
    }
    fn remove_owned_destination_routes(
        &mut self,
        owned: &[WindowsRouteSnapshotEntry],
    ) -> DomainResult<()>;
}

/// Durable session-state access used by every lifecycle operation.
pub trait WindowsTunnelStatePort {
    fn read(&mut self, path: &Path) -> DomainResult<WindowsTunnelState>;
    fn write(&mut self, path: &Path, state: &WindowsTunnelState) -> DomainResult<()>;
}

#[derive(Default)]
struct FileWindowsTunnelStatePort;

impl WindowsTunnelStatePort for FileWindowsTunnelStatePort {
    fn read(&mut self, path: &Path) -> DomainResult<WindowsTunnelState> {
        read_tunnel_state(path)
    }

    fn write(&mut self, path: &Path, state: &WindowsTunnelState) -> DomainResult<()> {
        write_tunnel_state(path, state)
    }
}

/// Explicit operator inputs for a foreground EasyTier session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsTunnelStartRequest {
    pub plan: WindowsTunnelPlan,
    pub easytier_binary: PathBuf,
    pub easytier_cli: PathBuf,
    pub easytier_version: String,
    pub easytier_sha256: String,
    pub easytier_cli_sha256: String,
    pub network_name: String,
    pub network_secret_file: PathBuf,
    pub state_path: PathBuf,
    pub confirm: bool,
}

enum StartProcessCleanup<'a> {
    NotStarted,
    Owned(&'a OwnedProcessHandle),
    Unproven,
}

/// Session service composed from explicit process, CLI, and route ports.
pub struct WindowsTunnelSessionService<P, C, R> {
    process_runner: P,
    cli_runner: C,
    route_port: R,
    state_port: Box<dyn WindowsTunnelStatePort>,
    owned_sessions: BTreeMap<PathBuf, OwnedTunnelSession>,
}

impl<P, C, R> WindowsTunnelSessionService<P, C, R> {
    pub fn new(process_runner: P, cli_runner: C, route_port: R) -> Self {
        Self::new_with_state_port(
            process_runner,
            cli_runner,
            route_port,
            FileWindowsTunnelStatePort,
        )
    }

    pub fn new_with_state_port<S>(
        process_runner: P,
        cli_runner: C,
        route_port: R,
        state_port: S,
    ) -> Self
    where
        S: WindowsTunnelStatePort + 'static,
    {
        Self {
            process_runner,
            cli_runner,
            route_port,
            state_port: Box::new(state_port),
            owned_sessions: BTreeMap::new(),
        }
    }
}

impl<P, C, R> WindowsTunnelSessionService<P, C, R>
where
    P: EasyTierProcessRunner,
    C: EasyTierCliRunner,
    R: WindowsRoutePort,
{
    /// Starts one foreground session after all local preflight checks pass.
    pub fn start(
        &mut self,
        request: WindowsTunnelStartRequest,
    ) -> DomainResult<WindowsTunnelState> {
        let mut prepared = self.prepare_start(request)?;

        let destination_before = self
            .route_port
            .snapshot_destination_routes(&prepared.route_cidrs)
            .map_err(|_| start_error("destination route snapshot could not be captured"))?;
        let route_snapshot = self
            .route_port
            .snapshot(&[prepared.endpoint])
            .map_err(|_| endpoint_bypass_error("underlay route snapshot could not be captured"))?;
        if let Err(_error) = self.route_port.add_endpoint_bypass(&[prepared.endpoint]) {
            return Err(self.rollback_routes_after_start_error(
                &route_snapshot,
                endpoint_bypass_error("underlay endpoint bypass could not be installed"),
            ));
        }

        match write_exclusive_config(&prepared.config_path, &prepared.config_toml) {
            Ok(()) => {}
            Err(ExclusiveConfigWriteError::Create) => {
                return Err(self.rollback_routes_after_start_error(
                    &route_snapshot,
                    start_error("EasyTier session configuration could not be written"),
                ));
            }
            Err(ExclusiveConfigWriteError::Write) => {
                return Err(self.rollback_failed_start(
                    &route_snapshot,
                    None,
                    StartProcessCleanup::NotStarted,
                    &prepared.config_path,
                    start_error("EasyTier session configuration could not be written"),
                ));
            }
        }
        let state_directory = prepared
            .state_path
            .parent()
            .expect("canonical state path always has a parent directory");
        let config_path =
            match canonical_file_under_directory(state_directory, &prepared.config_file_name) {
                Some(path) => path,
                None => {
                    return Err(self.rollback_failed_start(
                        &route_snapshot,
                        None,
                        StartProcessCleanup::NotStarted,
                        &prepared.config_path,
                        start_error("EasyTier session configuration path is invalid"),
                    ));
                }
            };
        prepared.config_path = config_path;

        let spec = EasyTierLaunchSpec {
            session_id: prepared.plan.session_id.clone(),
            binary_path: prepared.binary_path.clone(),
            cli_path: prepared.cli_path.clone(),
            config_path: prepared.config_path.clone(),
            expected_version: prepared.expected_version.clone(),
            expected_sha256: prepared.expected_sha256.clone(),
            expected_cli_sha256: prepared.expected_cli_sha256.clone(),
        };
        let process_handle = match self.process_runner.start(&spec) {
            Ok(handle) => handle,
            Err(error) => {
                let process = if error.code == WINDOWS_TUNNEL_ROLLBACK_FAILED_CODE {
                    StartProcessCleanup::Unproven
                } else {
                    StartProcessCleanup::NotStarted
                };
                return Err(self.rollback_failed_start(
                    &route_snapshot,
                    None,
                    process,
                    &prepared.config_path,
                    start_error("EasyTier process could not be started"),
                ));
            }
        };
        if process_handle.session_id != spec.session_id {
            return Err(self.rollback_failed_start(
                &route_snapshot,
                None,
                StartProcessCleanup::Owned(&process_handle),
                &prepared.config_path,
                start_error("EasyTier process session identity does not match the tunnel plan"),
            ));
        }

        let readiness = self.verify_readiness(
            &prepared.cli_path,
            &prepared.expected_cli_sha256,
            &prepared.plan,
        );
        if let Err(error) = readiness {
            return Err(self.rollback_failed_start(
                &route_snapshot,
                None,
                StartProcessCleanup::Owned(&process_handle),
                &prepared.config_path,
                error,
            ));
        }

        let virtual_route_snapshot = match self
            .route_port
            .capture_owned_destination_routes(&destination_before, &prepared.route_cidrs)
        {
            Ok(snapshot) => snapshot,
            Err(_) => {
                return Err(
                    self.rollback_unproven_destination_capture(&route_snapshot, &process_handle)
                );
            }
        };

        let state = WindowsTunnelState {
            schema_version: crate::tunnel_config::WINDOWS_TUNNEL_STATE_SCHEMA_VERSION,
            session_id: prepared.plan.session_id.clone(),
            plan_digest: prepared.plan.plan_digest.clone(),
            selected_pop_id: prepared.plan.selected_pop_id.clone(),
            selected_endpoint: prepared.plan.selected_endpoint.clone(),
            state: WindowsTunnelLifecycleState::Running,
            config_path: prepared.config_file_name.clone(),
            last_client_sequence: prepared.plan.client_sequence,
            last_pop_sequence: prepared.plan.pop_sequence,
            client_bundle_id: prepared.plan.client_bundle_id.clone(),
            client_sequence: prepared.plan.client_sequence,
            pop_bundle_id: prepared.plan.pop_bundle_id.clone(),
            pop_sequence: prepared.plan.pop_sequence,
            easytier_version: prepared.expected_version.clone(),
            route_snapshot: route_snapshot.clone(),
            rollback_status: "clean".to_string(),
            runtime_ownership: WindowsTunnelRuntimeOwnership {
                process: process_handle.clone(),
                binary_sha256: prepared.expected_sha256.clone(),
                cli_file_name: prepared.cli_file_name.clone(),
                cli_sha256: prepared.expected_cli_sha256.clone(),
                route_cidrs: prepared.route_cidrs.clone(),
                virtual_route_snapshot: virtual_route_snapshot.clone(),
            },
        };
        if let Err(error) = self.state_port.write(&prepared.state_path, &state) {
            return Err(self.rollback_failed_start(
                &route_snapshot,
                Some(&virtual_route_snapshot),
                StartProcessCleanup::Owned(&process_handle),
                &prepared.config_path,
                error,
            ));
        }

        self.owned_sessions.insert(
            prepared.state_path.clone(),
            OwnedTunnelSession {
                session_id: state.session_id.clone(),
                process_handle,
                cli_path: prepared.cli_path,
                cli_sha256: prepared.expected_cli_sha256,
                route_snapshot,
                route_cidrs: prepared.route_cidrs,
                virtual_route_snapshot,
                config_path: prepared.config_path,
                bypass_recovery_required: false,
                destination_recovery_required: false,
            },
        );

        Ok(state)
    }

    /// Queries readiness through the same explicit CLI path used at start time.
    pub fn status(&mut self, state_path: &Path) -> DomainResult<WindowsTunnelState> {
        let state_path = canonical_state_path(state_path)
            .map_err(|_| status_error("tunnel state path is invalid"))?;
        let state = self.state_port.read(&state_path)?;
        if state.state != WindowsTunnelLifecycleState::Running {
            return Err(status_error("tunnel state is not running"));
        }
        self.ensure_owned_session(&state_path, &state)?;
        let (cli_path, cli_sha256, expected_route_cidrs) = self
            .owned_sessions
            .get(&state_path)
            .map(|owned| {
                (
                    owned.cli_path.clone(),
                    owned.cli_sha256.clone(),
                    owned.route_cidrs.clone(),
                )
            })
            .expect("owned tunnel session was checked before CLI readiness");

        verify_file_sha256(&cli_path, &cli_sha256)
            .map_err(|_| status_error("EasyTier peer readiness is unavailable"))?;
        let peer_ready = self
            .cli_runner
            .peer_ready(&cli_path, &cli_sha256)
            .map_err(|_| status_error("EasyTier peer readiness is unavailable"))?;
        verify_file_sha256(&cli_path, &cli_sha256)
            .map_err(|_| status_error("EasyTier route readiness is unavailable"))?;
        let route_cidrs = self
            .cli_runner
            .route_cidrs(&cli_path, &cli_sha256)
            .map_err(|_| status_error("EasyTier route readiness is unavailable"))?;
        if !peer_ready
            || !expected_route_cidrs
                .iter()
                .all(|cidr| route_cidrs.contains(cidr))
        {
            return Err(status_error("EasyTier session is not ready"));
        }

        Ok(state)
    }

    /// Removes session-owned route state and terminates only the owned process.
    pub fn stop(&mut self, state_path: &Path, confirm: bool) -> DomainResult<WindowsTunnelState> {
        if !confirm {
            return Err(confirmation_error());
        }

        let state_path = canonical_state_path(state_path)
            .map_err(|_| stop_error("tunnel state path is invalid"))?;
        let state = self.state_port.read(&state_path)?;
        let (cleanup_state, cleanup_result) = match state.state {
            WindowsTunnelLifecycleState::Running => {
                self.recover_running_session(&state_path, &state)?;

                let mut stopping = state.clone();
                stopping.state = WindowsTunnelLifecycleState::Stopping;
                stopping.rollback_status = "pending".to_string();
                self.state_port.write(&state_path, &stopping)?;

                let owned = self.owned_sessions.remove(&state_path);
                let owned = owned.expect("owned tunnel session was checked before cleanup");
                (
                    stopping,
                    self.cleanup_owned_resources(&CleanupOwnedTunnelSession::from(owned)),
                )
            }
            WindowsTunnelLifecycleState::Stopping | WindowsTunnelLifecycleState::Failed => {
                let cleanup_result =
                    self.recover_cleanup_session(&state_path, &state)
                        .and_then(|owned| {
                            self.recover_cleanup_routes(&owned)?;
                            self.cleanup_owned_resources(&owned)
                        });
                (state.clone(), cleanup_result)
            }
            WindowsTunnelLifecycleState::Starting | WindowsTunnelLifecycleState::Stopped => {
                return Err(stop_error("tunnel state cannot be cleaned up"));
            }
        };

        if cleanup_result.is_err() {
            let mut failed = cleanup_state.clone();
            failed.state = WindowsTunnelLifecycleState::Failed;
            failed.rollback_status = "rollback_failed".to_string();
            let _ = self.state_port.write(&state_path, &failed);
            return Err(rollback_error());
        }

        let mut stopped = cleanup_state;
        stopped.state = WindowsTunnelLifecycleState::Stopped;
        stopped.rollback_status = "clean".to_string();
        self.state_port.write(&state_path, &stopped)?;
        Ok(stopped)
    }

    fn prepare_start(&mut self, request: WindowsTunnelStartRequest) -> DomainResult<PreparedStart> {
        if !request.confirm {
            return Err(confirmation_error());
        }
        if request.plan.session_id.trim().is_empty()
            || request.plan.plan_digest.trim().is_empty()
            || !request.plan.endpoint_bypass_required
            || request.plan.route_intents.is_empty()
            || request
                .plan
                .route_intents
                .iter()
                .any(|route| route.direct_fallback)
        {
            return Err(start_error(
                "tunnel plan is not safe for foreground execution",
            ));
        }
        let route_cidrs = canonical_destination_ipv4_cidrs(
            request
                .plan
                .route_intents
                .iter()
                .map(|route| route.destination_cidr.as_str()),
        )
        .map_err(|_| start_error("tunnel plan contains an invalid destination policy route"))?;
        let state_path = canonical_state_path(&request.state_path).map_err(|_| {
            start_error("state path must use an existing directory and safe file name")
        })?;
        if self.owned_sessions.contains_key(&state_path) || state_path.exists() {
            return Err(start_error("state path is already owned or occupied"));
        }
        let (binary_path, cli_path) =
            canonical_sibling_artifacts(&request.easytier_binary, &request.easytier_cli)
                .ok_or_else(|| start_error("configured EasyTier executable path is invalid"))?;
        let cli_file_name = safe_file_name_from_path(&cli_path)
            .ok_or_else(|| start_error("configured EasyTier CLI file name is invalid"))?;
        verify_file_sha256(&binary_path, &request.easytier_sha256)?;
        verify_file_sha256(&cli_path, &request.easytier_cli_sha256)?;

        let configured_version = required_text(&request.easytier_version, "EasyTier version")?;
        let runtime_version = self
            .cli_runner
            .version(&cli_path, &request.easytier_cli_sha256)
            .map_err(|_| start_error("EasyTier CLI version query failed"))?;
        if runtime_version.trim() != configured_version {
            return Err(DomainError::new(
                WINDOWS_TUNNEL_EASYTIER_VERSION_MISMATCH_CODE,
                "EasyTier CLI version does not match the configured pin",
            ));
        }

        let network_secret = fs::read_to_string(&request.network_secret_file)
            .map_err(|_| secret_error())?
            .trim()
            .to_string();
        if network_secret.is_empty() {
            return Err(secret_error());
        }

        let endpoint = endpoint_ip(&request.plan.selected_endpoint)?;
        let state_file_name = safe_file_name_from_path(&state_path)
            .ok_or_else(|| start_error("state file name is invalid"))?;
        let config_file_name = config_file_name_for_state(&state_file_name)
            .ok_or_else(|| start_error("session configuration file name is invalid"))?;
        let state_directory = state_path
            .parent()
            .expect("canonical state path always has a parent directory");
        let config_path = state_directory.join(&config_file_name);
        let config = render_easytier_config(EasyTierConfigRequest {
            plan: &request.plan,
            network_name: &request.network_name,
            network_secret: &network_secret,
            virtual_ipv4: None,
        })?;

        Ok(PreparedStart {
            plan: request.plan,
            binary_path,
            cli_path,
            expected_version: configured_version,
            expected_sha256: request.easytier_sha256,
            expected_cli_sha256: request.easytier_cli_sha256,
            state_path,
            config_path,
            config_file_name,
            cli_file_name,
            config_toml: config.toml,
            route_cidrs,
            endpoint,
        })
    }

    fn ensure_owned_session(
        &mut self,
        state_path: &Path,
        state: &WindowsTunnelState,
    ) -> DomainResult<()> {
        let state_path = canonical_state_path(state_path).map_err(|_| ownership_error())?;
        if let Some(owned) = self.owned_sessions.get(&state_path) {
            if owned.session_id != state.session_id {
                return Err(ownership_error());
            }
            return Ok(());
        }

        let recovered = self.recover_owned_session(&state_path, state)?;
        self.owned_sessions.insert(state_path, recovered);
        Ok(())
    }

    fn recover_running_session(
        &mut self,
        state_path: &Path,
        state: &WindowsTunnelState,
    ) -> DomainResult<()> {
        let recovered = self.recover_owned_session(state_path, state)?;
        self.owned_sessions
            .insert(state_path.to_path_buf(), recovered);
        self.recover_running_routes(state_path)
    }

    fn recover_owned_session(
        &mut self,
        state_path: &Path,
        state: &WindowsTunnelState,
    ) -> DomainResult<OwnedTunnelSession> {
        let state_path = canonical_state_path(state_path).map_err(|_| ownership_error())?;
        let state_directory = state_path
            .parent()
            .expect("canonical state path always has a parent directory");
        if !is_safe_tunnel_file_name(&state.config_path) {
            return Err(ownership_error());
        }
        let config_path = canonical_file_under_directory(state_directory, &state.config_path)
            .ok_or_else(ownership_error)?;
        let ownership = state.runtime_ownership.clone();
        if ownership.process.session_id != state.session_id {
            return Err(ownership_error());
        }
        let spec = EasyTierRecoverySpec {
            expected_process: ownership.process.clone(),
            expected_binary_sha256: ownership.binary_sha256.clone(),
            expected_cli_sha256: ownership.cli_sha256.clone(),
            config_path: config_path.clone(),
            cli_file_name: ownership.cli_file_name.clone(),
        };
        let recovered = self
            .process_runner
            .recover(&spec)
            .map_err(|_| ownership_error())?;
        if recovered.process.process_id != ownership.process.process_id
            || recovered.process.creation_marker != ownership.process.creation_marker
            || recovered.process.session_id != ownership.process.session_id
            || recovered.process.session_id != state.session_id
        {
            return Err(ownership_error());
        }
        let (binary_path, cli_path) =
            canonical_sibling_artifacts(&recovered.binary_path, &recovered.cli_path)
                .ok_or_else(ownership_error)?;
        if verify_file_sha256(&binary_path, &spec.expected_binary_sha256).is_err() {
            return Err(ownership_error());
        }
        if verify_file_sha256(&cli_path, &spec.expected_cli_sha256).is_err() {
            return Err(ownership_error());
        }
        let recovered_cli_file_name =
            safe_file_name_from_path(&cli_path).ok_or_else(ownership_error)?;
        if recovered_cli_file_name != ownership.cli_file_name {
            return Err(ownership_error());
        }

        Ok(OwnedTunnelSession {
            session_id: state.session_id.clone(),
            process_handle: recovered.process,
            cli_path,
            cli_sha256: ownership.cli_sha256,
            route_snapshot: state.route_snapshot.clone(),
            route_cidrs: ownership.route_cidrs,
            virtual_route_snapshot: ownership.virtual_route_snapshot,
            config_path,
            bypass_recovery_required: true,
            destination_recovery_required: true,
        })
    }

    fn recover_running_routes(&mut self, state_path: &Path) -> DomainResult<()> {
        let bypass_recovery_required = self
            .owned_sessions
            .get(state_path)
            .map(|owned| owned.bypass_recovery_required)
            .expect("owned tunnel session was checked before route recovery");
        if bypass_recovery_required {
            let route_snapshot = self
                .owned_sessions
                .get(state_path)
                .map(|owned| owned.route_snapshot.clone())
                .expect("owned tunnel session was checked before route recovery");
            self.route_port
                .recover_owned_bypass(&route_snapshot)
                .map_err(|_| {
                    endpoint_bypass_error("persisted endpoint-bypass recovery could not be proven")
                })?;
            self.owned_sessions
                .get_mut(state_path)
                .expect("owned tunnel session was checked before route recovery")
                .bypass_recovery_required = false;
        }

        let destination_recovery_required = self
            .owned_sessions
            .get(state_path)
            .map(|owned| owned.destination_recovery_required)
            .expect("owned tunnel session was checked before destination route recovery");
        if destination_recovery_required {
            let virtual_route_snapshot = self
                .owned_sessions
                .get(state_path)
                .map(|owned| owned.virtual_route_snapshot.clone())
                .expect("owned tunnel session was checked before destination route recovery");
            self.route_port
                .recover_owned_destination_routes(&virtual_route_snapshot)
                .map_err(|_| rollback_error())?;
            self.owned_sessions
                .get_mut(state_path)
                .expect("owned tunnel session was checked before destination route recovery")
                .destination_recovery_required = false;
        }
        Ok(())
    }

    fn recover_cleanup_session(
        &mut self,
        state_path: &Path,
        state: &WindowsTunnelState,
    ) -> DomainResult<CleanupOwnedTunnelSession> {
        let state_path = canonical_state_path(state_path).map_err(|_| ownership_error())?;
        let state_directory = state_path
            .parent()
            .expect("canonical state path always has a parent directory");
        if !is_safe_tunnel_file_name(&state.config_path) {
            return Err(ownership_error());
        }
        let ownership = state.runtime_ownership.clone();
        if ownership.process.session_id != state.session_id {
            return Err(ownership_error());
        }
        let spec = EasyTierRecoverySpec {
            expected_process: ownership.process.clone(),
            expected_binary_sha256: ownership.binary_sha256.clone(),
            expected_cli_sha256: ownership.cli_sha256.clone(),
            config_path: state_directory.join(&state.config_path),
            cli_file_name: ownership.cli_file_name.clone(),
        };
        let recovery = self
            .process_runner
            .recover_for_cleanup(&spec)
            .map_err(|_| ownership_error())?;
        let config_path = cleanup_config_path(state_directory, &state.config_path)
            .map_err(|_| ownership_error())?;
        let process_handle = match recovery {
            EasyTierCleanupRecovery::Present(recovered) => {
                if config_path.is_none() {
                    return Err(ownership_error());
                }
                Some(Self::validate_recovered_process(
                    state, &ownership, &spec, recovered,
                )?)
            }
            EasyTierCleanupRecovery::Absent => None,
        };

        Ok(CleanupOwnedTunnelSession {
            process_handle,
            route_snapshot: state.route_snapshot.clone(),
            virtual_route_snapshot: ownership.virtual_route_snapshot,
            config_path,
        })
    }

    fn validate_recovered_process(
        state: &WindowsTunnelState,
        ownership: &WindowsTunnelRuntimeOwnership,
        spec: &EasyTierRecoverySpec,
        recovered: RecoveredEasyTierProcess,
    ) -> DomainResult<OwnedProcessHandle> {
        if recovered.process.process_id != ownership.process.process_id
            || recovered.process.creation_marker != ownership.process.creation_marker
            || recovered.process.session_id != ownership.process.session_id
            || recovered.process.session_id != state.session_id
        {
            return Err(ownership_error());
        }
        let (binary_path, cli_path) =
            canonical_sibling_artifacts(&recovered.binary_path, &recovered.cli_path)
                .ok_or_else(ownership_error)?;
        if verify_file_sha256(&binary_path, &spec.expected_binary_sha256).is_err() {
            return Err(ownership_error());
        }
        let recovered_cli_file_name =
            safe_file_name_from_path(&cli_path).ok_or_else(ownership_error)?;
        if recovered_cli_file_name != ownership.cli_file_name {
            return Err(ownership_error());
        }
        Ok(recovered.process)
    }

    fn recover_cleanup_routes(&mut self, owned: &CleanupOwnedTunnelSession) -> DomainResult<()> {
        self.route_port
            .recover_cleanup_bypass(&owned.route_snapshot)
            .map_err(|_| {
                endpoint_bypass_error("persisted endpoint-bypass cleanup could not be proven")
            })?;
        self.route_port
            .recover_cleanup_destination_routes(&owned.virtual_route_snapshot)
            .map_err(|_| rollback_error())
    }

    fn cleanup_owned_resources(&mut self, owned: &CleanupOwnedTunnelSession) -> DomainResult<()> {
        self.route_port
            .remove_owned_destination_routes(&owned.virtual_route_snapshot)
            .map_err(|_| rollback_error())?;
        self.route_port
            .restore(&owned.route_snapshot)
            .map_err(|_| rollback_error())?;
        if let Some(process_handle) = &owned.process_handle {
            self.process_runner
                .stop(process_handle)
                .map_err(|_| rollback_error())?;
        }
        if let Some(config_path) = &owned.config_path {
            fs::remove_file(config_path).map_err(|_| rollback_error())?;
        }
        Ok(())
    }

    fn verify_readiness(
        &mut self,
        cli_path: &Path,
        expected_cli_sha256: &str,
        plan: &WindowsTunnelPlan,
    ) -> DomainResult<()> {
        verify_file_sha256(cli_path, expected_cli_sha256).map_err(|_| peer_not_ready_error())?;
        let peer_ready = self
            .cli_runner
            .peer_ready(cli_path, expected_cli_sha256)
            .map_err(|_| peer_not_ready_error())?;
        if !peer_ready {
            return Err(peer_not_ready_error());
        }

        verify_file_sha256(cli_path, expected_cli_sha256).map_err(|_| route_not_ready_error())?;
        let route_cidrs = self
            .cli_runner
            .route_cidrs(cli_path, expected_cli_sha256)
            .map_err(|_| route_not_ready_error())?;
        if !plan
            .route_intents
            .iter()
            .all(|route| route_cidrs.contains(&route.destination_cidr))
        {
            return Err(route_not_ready_error());
        }

        Ok(())
    }

    fn rollback_routes_after_start_error(
        &mut self,
        snapshot: &[WindowsRouteSnapshotEntry],
        original: DomainError,
    ) -> DomainError {
        if self.route_port.restore(snapshot).is_err() {
            rollback_error()
        } else {
            original
        }
    }

    fn rollback_failed_start(
        &mut self,
        snapshot: &[WindowsRouteSnapshotEntry],
        virtual_route_snapshot: Option<&[WindowsRouteSnapshotEntry]>,
        process: StartProcessCleanup<'_>,
        config_path: &Path,
        original: DomainError,
    ) -> DomainError {
        let destination_routes_removed = virtual_route_snapshot
            .map(|routes| {
                self.route_port
                    .remove_owned_destination_routes(routes)
                    .is_ok()
            })
            .unwrap_or(true);
        let routes_restored = self.route_port.restore(snapshot).is_ok();
        let process_stopped = match process {
            StartProcessCleanup::NotStarted => true,
            StartProcessCleanup::Owned(handle) => self.process_runner.stop(handle).is_ok(),
            StartProcessCleanup::Unproven => false,
        };
        if !(destination_routes_removed && routes_restored && process_stopped) {
            return rollback_error();
        }
        if fs::remove_file(config_path).is_ok() {
            original
        } else {
            rollback_error()
        }
    }

    fn rollback_unproven_destination_capture(
        &mut self,
        snapshot: &[WindowsRouteSnapshotEntry],
        process_handle: &OwnedProcessHandle,
    ) -> DomainError {
        let _ = self.route_port.restore(snapshot);
        let _ = self.process_runner.stop(process_handle);
        rollback_error()
    }
}

struct OwnedTunnelSession {
    session_id: String,
    process_handle: OwnedProcessHandle,
    cli_path: PathBuf,
    cli_sha256: String,
    route_snapshot: Vec<WindowsRouteSnapshotEntry>,
    route_cidrs: Vec<String>,
    virtual_route_snapshot: Vec<WindowsRouteSnapshotEntry>,
    config_path: PathBuf,
    bypass_recovery_required: bool,
    destination_recovery_required: bool,
}

struct CleanupOwnedTunnelSession {
    process_handle: Option<OwnedProcessHandle>,
    route_snapshot: Vec<WindowsRouteSnapshotEntry>,
    virtual_route_snapshot: Vec<WindowsRouteSnapshotEntry>,
    config_path: Option<PathBuf>,
}

impl From<OwnedTunnelSession> for CleanupOwnedTunnelSession {
    fn from(owned: OwnedTunnelSession) -> Self {
        Self {
            process_handle: Some(owned.process_handle),
            route_snapshot: owned.route_snapshot,
            virtual_route_snapshot: owned.virtual_route_snapshot,
            config_path: Some(owned.config_path),
        }
    }
}

struct PreparedStart {
    plan: WindowsTunnelPlan,
    binary_path: PathBuf,
    cli_path: PathBuf,
    expected_version: String,
    expected_sha256: String,
    expected_cli_sha256: String,
    state_path: PathBuf,
    config_path: PathBuf,
    config_file_name: String,
    cli_file_name: String,
    config_toml: String,
    route_cidrs: Vec<String>,
    endpoint: IpAddr,
}

enum ExclusiveConfigWriteError {
    Create,
    Write,
}

fn endpoint_ip(endpoint: &str) -> DomainResult<IpAddr> {
    let host = if let Some(endpoint) = endpoint.strip_prefix('[') {
        endpoint
            .split_once("]:")
            .map(|(host, _)| host)
            .ok_or_else(|| endpoint_bypass_error("selected endpoint is invalid"))?
    } else {
        endpoint
            .rsplit_once(':')
            .map(|(host, _)| host)
            .ok_or_else(|| endpoint_bypass_error("selected endpoint is invalid"))?
    };
    IpAddr::from_str(host)
        .map_err(|_| endpoint_bypass_error("selected endpoint must be an IP address"))
}

fn canonical_state_path(path: &Path) -> Result<PathBuf, ()> {
    let file_name = safe_file_name_from_path(path).ok_or(())?;
    let directory = path
        .parent()
        .filter(|directory| directory.is_dir())
        .ok_or(())?;
    let directory = fs::canonicalize(directory).map_err(|_| ())?;
    Ok(directory.join(file_name))
}

fn canonical_file_under_directory(directory: &Path, file_name: &str) -> Option<PathBuf> {
    if !is_safe_tunnel_file_name(file_name) {
        return None;
    }
    let directory = fs::canonicalize(directory).ok()?;
    let candidate = directory.join(file_name);
    if !fs::symlink_metadata(&candidate).ok()?.file_type().is_file() {
        return None;
    }
    let file = fs::canonicalize(candidate).ok()?;
    (file.parent() == Some(directory.as_path())).then_some(file)
}

fn cleanup_config_path(directory: &Path, file_name: &str) -> Result<Option<PathBuf>, ()> {
    if !is_safe_tunnel_file_name(file_name) {
        return Err(());
    }
    let directory = fs::canonicalize(directory).map_err(|_| ())?;
    let candidate = directory.join(file_name);
    match fs::symlink_metadata(&candidate) {
        Ok(metadata) if metadata.file_type().is_file() => {
            canonical_file_under_directory(&directory, file_name)
                .map(Some)
                .ok_or(())
        }
        Ok(_) => Err(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(()),
    }
}

fn canonical_sibling_artifacts(binary: &Path, cli: &Path) -> Option<(PathBuf, PathBuf)> {
    let binary = fs::canonicalize(binary).ok()?;
    let cli = fs::canonicalize(cli).ok()?;
    if !binary.is_file() || !cli.is_file() || binary.parent() != cli.parent() {
        return None;
    }
    Some((binary, cli))
}

fn write_exclusive_config(path: &Path, contents: &str) -> Result<(), ExclusiveConfigWriteError> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| ExclusiveConfigWriteError::Create)?;
    file.write_all(contents.as_bytes())
        .map_err(|_| ExclusiveConfigWriteError::Write)
}

fn safe_file_name_from_path(path: &Path) -> Option<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| is_safe_tunnel_file_name(name))
        .map(str::to_string)
}

fn config_file_name_for_state(state_file_name: &str) -> Option<String> {
    let stem = Path::new(state_file_name).file_stem()?.to_str()?;
    if stem.trim().is_empty() {
        return None;
    }
    let config_file_name = format!("{stem}.easytier.toml");
    is_safe_tunnel_file_name(&config_file_name).then_some(config_file_name)
}

fn required_text(value: &str, field: &str) -> DomainResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(start_error(field));
    }
    Ok(value.to_string())
}

fn confirmation_error() -> DomainError {
    DomainError::new(
        WINDOWS_TUNNEL_CONFIRMATION_REQUIRED_CODE,
        "tunnel mutation requires explicit confirmation",
    )
}

fn secret_error() -> DomainError {
    DomainError::new(
        WINDOWS_TUNNEL_SECRET_FILE_INVALID_CODE,
        "network secret file is unavailable or empty",
    )
}

fn endpoint_bypass_error(message: &str) -> DomainError {
    DomainError::new(WINDOWS_TUNNEL_ENDPOINT_BYPASS_FAILED_CODE, message)
}

fn start_error(message: &str) -> DomainError {
    DomainError::new(WINDOWS_TUNNEL_START_FAILED_CODE, message)
}

fn peer_not_ready_error() -> DomainError {
    DomainError::new(
        WINDOWS_TUNNEL_PEER_NOT_READY_CODE,
        "EasyTier peer is not ready",
    )
}

fn route_not_ready_error() -> DomainError {
    DomainError::new(
        WINDOWS_TUNNEL_ROUTE_NOT_READY_CODE,
        "EasyTier destination routes are not ready",
    )
}

fn status_error(message: &str) -> DomainError {
    DomainError::new(WINDOWS_TUNNEL_STATUS_UNAVAILABLE_CODE, message)
}

fn stop_error(message: &str) -> DomainError {
    DomainError::new(WINDOWS_TUNNEL_STOP_FAILED_CODE, message)
}

fn rollback_error() -> DomainError {
    DomainError::new(
        WINDOWS_TUNNEL_ROLLBACK_FAILED_CODE,
        "tunnel cleanup could not be proven complete",
    )
}

fn ownership_error() -> DomainError {
    DomainError::new(
        WINDOWS_TUNNEL_OWNERSHIP_MISMATCH_CODE,
        "tunnel state is not owned by this session service",
    )
}

/// Production process port for an explicitly supplied EasyTier executable.
#[derive(Default)]
pub struct NativeEasyTierProcessRunner {
    #[cfg(windows)]
    proofs: BTreeMap<(u32, String), NativeEasyTierProcessProof>,
}

#[cfg(windows)]
#[derive(Clone)]
struct NativeEasyTierProcessProof {
    process: OwnedProcessHandle,
    binary_path: PathBuf,
    config_path: PathBuf,
    expected_sha256: String,
    creation_filetime: u64,
}

#[cfg(windows)]
const PROCESS_SYNCHRONIZE: u32 = 1_048_576;

#[cfg(windows)]
const NATIVE_PROCESS_STOP_WAIT_MILLIS: u32 = 10_000;

#[cfg(windows)]
struct NativeVerifiedProcessHandle {
    raw: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl NativeVerifiedProcessHandle {
    fn open(process_id: u32, expected_creation_filetime: u64) -> Option<Self> {
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
        };

        let raw = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE,
                0,
                process_id,
            )
        };
        if raw.is_null() {
            return None;
        }
        let handle = Self { raw };
        (native_process_creation_filetime(handle.raw) == Some(expected_creation_filetime))
            .then_some(handle)
    }

    fn terminate_and_wait(&self) -> DomainResult<()> {
        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};

        if unsafe { TerminateProcess(self.raw, 1) } == 0 {
            return Err(stop_error("owned EasyTier process could not be terminated"));
        }
        if unsafe { WaitForSingleObject(self.raw, NATIVE_PROCESS_STOP_WAIT_MILLIS) }
            != WAIT_OBJECT_0
        {
            return Err(stop_error("owned EasyTier process could not be terminated"));
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for NativeVerifiedProcessHandle {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;

        unsafe {
            let _ = CloseHandle(self.raw);
        }
    }
}

#[cfg(windows)]
#[derive(serde::Deserialize)]
struct NativeProcessInspection {
    #[serde(rename = "ProcessId")]
    process_id: u32,
    #[serde(rename = "CreationDate")]
    creation_marker: String,
    #[serde(rename = "CreationFileTime")]
    creation_filetime: u64,
    #[serde(rename = "ExecutablePath")]
    executable_path: String,
    #[serde(rename = "CommandLine")]
    command_line: String,
}

#[cfg(windows)]
fn native_easytier_process_command(
    binary_path: &Path,
    config_path: &Path,
) -> DomainResult<Command> {
    let working_directory = binary_path
        .parent()
        .ok_or_else(|| start_error("explicit EasyTier executable path is invalid"))?;
    let mut command = native_windows_hardened_command(binary_path)
        .map_err(|_| start_error("explicit EasyTier executable could not be started"))?;
    command
        .current_dir(working_directory)
        .arg("--config-file")
        .arg(config_path)
        .arg("--disable-env-parsing")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    Ok(command)
}

#[cfg(windows)]
impl EasyTierProcessRunner for NativeEasyTierProcessRunner {
    fn start(&mut self, spec: &EasyTierLaunchSpec) -> DomainResult<OwnedProcessHandle> {
        if spec.session_id.trim().is_empty() {
            return Err(start_error("EasyTier launch session identity is invalid"));
        }
        let binary_path = native_windows_validate_existing_easytier_artifact(&spec.binary_path)
            .map_err(|_| start_error("explicit EasyTier executable path is invalid"))?;
        let cli_path = native_windows_validate_existing_easytier_artifact(&spec.cli_path)
            .map_err(|_| start_error("explicit EasyTier CLI path is invalid"))?;
        if binary_path.parent() != cli_path.parent() {
            return Err(start_error(
                "EasyTier executable paths are not trusted siblings",
            ));
        }
        let config_file_name = safe_file_name_from_path(&spec.config_path)
            .ok_or_else(|| start_error("EasyTier session configuration path is invalid"))?;
        let config_directory = spec
            .config_path
            .parent()
            .ok_or_else(|| start_error("EasyTier session configuration path is invalid"))?;
        let config_path = canonical_file_under_directory(config_directory, &config_file_name)
            .ok_or_else(|| start_error("EasyTier session configuration path is invalid"))?;
        if verify_file_sha256(&binary_path, &spec.expected_sha256).is_err() {
            return Err(start_error(
                "explicit EasyTier executable does not match its pin",
            ));
        }
        if verify_file_sha256(&cli_path, &spec.expected_cli_sha256).is_err() {
            return Err(start_error("explicit EasyTier CLI does not match its pin"));
        }

        let child = native_easytier_process_command(&binary_path, &config_path)?
            .spawn()
            .map_err(|_| start_error("explicit EasyTier executable could not be started"))?;
        let process_id = child.id();
        let mut proof = None;
        for attempt in 0..5 {
            proof = native_start_proof(
                process_id,
                &spec.session_id,
                &binary_path,
                &config_path,
                &spec.expected_sha256,
            );
            if proof.is_some() {
                break;
            }
            if attempt < 4 {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
        let Some(proof) = proof else {
            return match native_terminate_child(child) {
                Ok(()) => Err(start_error(
                    "started EasyTier process ownership proof failed",
                )),
                Err(_) => Err(rollback_error()),
            };
        };

        let process = proof.process.clone();
        self.proofs.insert(native_process_key(&process), proof);
        Ok(process)
    }

    fn recover(&mut self, spec: &EasyTierRecoverySpec) -> DomainResult<RecoveredEasyTierProcess> {
        if !is_safe_tunnel_file_name(&spec.cli_file_name) {
            return Err(ownership_error());
        }
        let config_file_name =
            safe_file_name_from_path(&spec.config_path).ok_or_else(ownership_error)?;
        let config_directory = spec.config_path.parent().ok_or_else(ownership_error)?;
        let config_path = canonical_file_under_directory(config_directory, &config_file_name)
            .ok_or_else(ownership_error)?;
        let proof = native_process_proof(
            &spec.expected_process,
            None,
            &spec.expected_binary_sha256,
            &config_path,
        )
        .ok_or_else(ownership_error)?;
        let binary_directory = proof.binary_path.parent().ok_or_else(ownership_error)?;
        let trusted_binary_path =
            native_windows_validate_existing_easytier_artifact(&proof.binary_path)
                .map_err(|_| ownership_error())?;
        if trusted_binary_path != proof.binary_path {
            return Err(ownership_error());
        }
        let cli_path = canonical_file_under_directory(binary_directory, &spec.cli_file_name)
            .ok_or_else(ownership_error)?;
        let cli_path = native_windows_validate_existing_easytier_artifact(&cli_path)
            .map_err(|_| ownership_error())?;
        if verify_file_sha256(&cli_path, &spec.expected_cli_sha256).is_err() {
            return Err(ownership_error());
        }

        let recovered = RecoveredEasyTierProcess {
            process: proof.process.clone(),
            binary_path: proof.binary_path.clone(),
            cli_path,
        };
        self.proofs
            .insert(native_process_key(&proof.process), proof);
        Ok(recovered)
    }

    fn recover_for_cleanup(
        &mut self,
        spec: &EasyTierRecoverySpec,
    ) -> DomainResult<EasyTierCleanupRecovery> {
        if !is_safe_tunnel_file_name(&spec.cli_file_name) {
            return Err(ownership_error());
        }
        let config_file_name =
            safe_file_name_from_path(&spec.config_path).ok_or_else(ownership_error)?;
        let inspection = native_inspect_process_for_cleanup(spec.expected_process.process_id)?;
        let Some(inspection) = inspection else {
            return Ok(EasyTierCleanupRecovery::Absent);
        };
        let config_directory = spec.config_path.parent().ok_or_else(ownership_error)?;
        let config_path = canonical_file_under_directory(config_directory, &config_file_name)
            .ok_or_else(ownership_error)?;
        let proof = native_process_proof_from_inspection(
            inspection,
            &spec.expected_process,
            None,
            &spec.expected_binary_sha256,
            &config_path,
        )
        .ok_or_else(ownership_error)?;
        let _verified_handle =
            NativeVerifiedProcessHandle::open(proof.process.process_id, proof.creation_filetime)
                .ok_or_else(ownership_error)?;
        let binary_directory = proof.binary_path.parent().ok_or_else(ownership_error)?;
        let trusted_binary_path =
            native_windows_validate_existing_easytier_artifact(&proof.binary_path)
                .map_err(|_| ownership_error())?;
        if trusted_binary_path != proof.binary_path {
            return Err(ownership_error());
        }
        let cli_path = canonical_file_under_directory(binary_directory, &spec.cli_file_name)
            .ok_or_else(ownership_error)?;
        let cli_path = native_windows_validate_existing_easytier_artifact(&cli_path)
            .map_err(|_| ownership_error())?;
        let recovered = RecoveredEasyTierProcess {
            process: proof.process.clone(),
            binary_path: proof.binary_path.clone(),
            cli_path,
        };
        self.proofs
            .insert(native_process_key(&proof.process), proof);
        Ok(EasyTierCleanupRecovery::Present(recovered))
    }

    fn stop(&mut self, handle: &OwnedProcessHandle) -> DomainResult<()> {
        let key = native_process_key(handle);
        let proof = self.proofs.get(&key).cloned().ok_or_else(ownership_error)?;
        if proof.process != *handle {
            return Err(ownership_error());
        }
        let reproof = native_process_proof(
            handle,
            Some(&proof.binary_path),
            &proof.expected_sha256,
            &proof.config_path,
        )
        .ok_or_else(ownership_error)?;
        if reproof.creation_filetime != proof.creation_filetime {
            return Err(ownership_error());
        }
        let verified_handle =
            NativeVerifiedProcessHandle::open(handle.process_id, reproof.creation_filetime)
                .ok_or_else(ownership_error)?;
        verified_handle.terminate_and_wait()?;
        self.proofs.remove(&key);
        Ok(())
    }
}

#[cfg(windows)]
fn native_start_proof(
    process_id: u32,
    session_id: &str,
    expected_binary_path: &Path,
    expected_config_path: &Path,
    expected_sha256: &str,
) -> Option<NativeEasyTierProcessProof> {
    let inspection = native_inspect_process(process_id)?;
    if inspection.process_id != process_id
        || inspection.creation_marker.trim().is_empty()
        || inspection.creation_filetime == 0
    {
        return None;
    }
    let process = OwnedProcessHandle {
        session_id: session_id.to_string(),
        process_id,
        creation_marker: inspection.creation_marker.clone(),
    };
    let proof = native_process_proof_from_inspection(
        inspection,
        &process,
        Some(expected_binary_path),
        expected_sha256,
        expected_config_path,
    )?;
    NativeVerifiedProcessHandle::open(process_id, proof.creation_filetime)?;
    Some(proof)
}

#[cfg(windows)]
fn native_process_proof(
    expected_process: &OwnedProcessHandle,
    expected_binary_path: Option<&Path>,
    expected_sha256: &str,
    expected_config_path: &Path,
) -> Option<NativeEasyTierProcessProof> {
    let inspection = native_inspect_process(expected_process.process_id)?;
    let proof = native_process_proof_from_inspection(
        inspection,
        expected_process,
        expected_binary_path,
        expected_sha256,
        expected_config_path,
    )?;
    NativeVerifiedProcessHandle::open(expected_process.process_id, proof.creation_filetime)?;
    Some(proof)
}

#[cfg(windows)]
fn native_process_proof_from_inspection(
    inspection: NativeProcessInspection,
    expected_process: &OwnedProcessHandle,
    expected_binary_path: Option<&Path>,
    expected_sha256: &str,
    expected_config_path: &Path,
) -> Option<NativeEasyTierProcessProof> {
    if inspection.process_id != expected_process.process_id
        || inspection.creation_marker != expected_process.creation_marker
        || inspection.creation_filetime == 0
    {
        return None;
    }
    let binary_path = fs::canonicalize(&inspection.executable_path).ok()?;
    if !binary_path.is_file() {
        return None;
    }
    let trusted_binary_path =
        native_windows_validate_existing_easytier_artifact(&binary_path).ok()?;
    if trusted_binary_path != binary_path {
        return None;
    }
    match expected_binary_path {
        Some(expected_binary_path) if binary_path != expected_binary_path => return None,
        _ => {}
    }
    if verify_file_sha256(&binary_path, expected_sha256).is_err() {
        return None;
    }
    let config_path = fs::canonicalize(expected_config_path).ok()?;
    if !config_path.is_file() {
        return None;
    }
    if !native_command_matches(&inspection.command_line, &config_path) {
        return None;
    }
    Some(NativeEasyTierProcessProof {
        process: expected_process.clone(),
        binary_path,
        config_path,
        expected_sha256: expected_sha256.to_string(),
        creation_filetime: inspection.creation_filetime,
    })
}

#[cfg(windows)]
fn native_process_key(handle: &OwnedProcessHandle) -> (u32, String) {
    (handle.process_id, handle.creation_marker.clone())
}

#[cfg(windows)]
fn native_inspect_process(process_id: u32) -> Option<NativeProcessInspection> {
    let script = format!(
        "$process = Get-CimInstance Win32_Process -Filter \"ProcessId = {process_id}\" -ErrorAction SilentlyContinue; if ($null -eq $process) {{ exit 2 }}; [PSCustomObject]@{{ ProcessId = [uint32]$process.ProcessId; CreationDate = $process.CreationDate.ToUniversalTime().ToString('o'); CreationFileTime = [uint64]$process.CreationDate.ToUniversalTime().ToFileTimeUtc(); ExecutablePath = $process.ExecutablePath; CommandLine = $process.CommandLine }} | ConvertTo-Json -Compress"
    );
    let mut command = native_windows_system_command(NativeWindowsSystemTool::PowerShell).ok()?;
    let output = command
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    serde_json::from_slice(&output.stdout).ok()
}

#[cfg(windows)]
fn native_inspect_process_for_cleanup(
    process_id: u32,
) -> DomainResult<Option<NativeProcessInspection>> {
    if process_id == 0 {
        return Err(ownership_error());
    }
    let script = format!(
        "$ErrorActionPreference = 'Stop'\ntry {{\n$processes = @(Get-CimInstance Win32_Process -Filter \"ProcessId = {process_id}\" -ErrorAction Stop)\nif ($processes.Count -eq 0) {{ exit 3 }}\nif ($processes.Count -ne 1) {{ exit 2 }}\n$process = $processes[0]\n[PSCustomObject]@{{ ProcessId = [uint32]$process.ProcessId; CreationDate = $process.CreationDate.ToUniversalTime().ToString('o'); CreationFileTime = [uint64]$process.CreationDate.ToUniversalTime().ToFileTimeUtc(); ExecutablePath = $process.ExecutablePath; CommandLine = $process.CommandLine }} | ConvertTo-Json -Compress\n}}"
    ) + "\ncatch { exit 2 }";
    let mut command = native_windows_system_command(NativeWindowsSystemTool::PowerShell)
        .map_err(|_| ownership_error())?;
    let output = command
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| ownership_error())?;
    match output.status.code() {
        Some(0) => serde_json::from_slice(&output.stdout)
            .map(Some)
            .map_err(|_| ownership_error()),
        Some(3) => Ok(None),
        _ => Err(ownership_error()),
    }
}

#[cfg(windows)]
fn native_command_matches(command_line: &str, expected_config_path: &Path) -> bool {
    let Some(arguments) = native_command_line_arguments(command_line) else {
        return false;
    };
    let expected_config = expected_config_path.to_string_lossy();
    arguments.len() == 3
        && arguments[0] == "--config-file"
        && arguments[1] == expected_config.as_ref()
        && arguments[2] == "--disable-env-parsing"
}

#[cfg(windows)]
fn native_command_line_arguments(command_line: &str) -> Option<Vec<String>> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::UI::Shell::CommandLineToArgvW;

    let command_line = std::ffi::OsStr::new(command_line)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut argument_count = 0;
    let raw_arguments = unsafe { CommandLineToArgvW(command_line.as_ptr(), &mut argument_count) };
    if raw_arguments.is_null() {
        return None;
    }
    let arguments = if argument_count < 1 {
        None
    } else {
        unsafe {
            std::slice::from_raw_parts(raw_arguments, argument_count as usize)
                .iter()
                .map(|argument| native_wide_argument(*argument))
                .collect::<Option<Vec<_>>>()
        }
    };
    unsafe {
        let _ = LocalFree(raw_arguments as _);
    }
    arguments.map(|arguments| arguments.into_iter().skip(1).collect())
}

#[cfg(windows)]
fn native_wide_argument(argument: *const u16) -> Option<String> {
    if argument.is_null() {
        return None;
    }
    let mut length = 0;
    unsafe {
        while *argument.add(length) != 0 {
            length += 1;
        }
        String::from_utf16(std::slice::from_raw_parts(argument, length)).ok()
    }
}

#[cfg(windows)]
fn native_process_creation_filetime(handle: windows_sys::Win32::Foundation::HANDLE) -> Option<u64> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::GetProcessTimes;

    let mut creation = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut kernel = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut user = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let process_times =
        unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) };
    if process_times == 0 {
        return None;
    }
    Some((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

#[cfg(windows)]
fn native_terminate_child(mut child: std::process::Child) -> DomainResult<()> {
    match child
        .try_wait()
        .map_err(|_| stop_error("owned EasyTier process could not be terminated"))?
    {
        Some(_) => Ok(()),
        None => {
            child
                .kill()
                .map_err(|_| stop_error("owned EasyTier process could not be terminated"))?;
            child
                .wait()
                .map_err(|_| stop_error("owned EasyTier process could not be terminated"))?;
            Ok(())
        }
    }
}

#[cfg(not(windows))]
impl EasyTierProcessRunner for NativeEasyTierProcessRunner {
    fn start(&mut self, _spec: &EasyTierLaunchSpec) -> DomainResult<OwnedProcessHandle> {
        Err(start_error(
            "Windows EasyTier process execution is unavailable on this platform",
        ))
    }

    fn recover(&mut self, _spec: &EasyTierRecoverySpec) -> DomainResult<RecoveredEasyTierProcess> {
        Err(ownership_error())
    }

    fn stop(&mut self, _handle: &OwnedProcessHandle) -> DomainResult<()> {
        Err(stop_error(
            "Windows EasyTier process execution is unavailable on this platform",
        ))
    }
}

/// Production CLI port that runs only the explicitly supplied EasyTier CLI binary.
#[derive(Debug, Default)]
pub struct NativeEasyTierCliRunner;

#[cfg(windows)]
impl EasyTierCliRunner for NativeEasyTierCliRunner {
    fn version(&mut self, path: &Path, expected_sha256: &str) -> DomainResult<String> {
        native_cli_output(path, expected_sha256, &["--version"])
    }

    fn peer_ready(&mut self, path: &Path, expected_sha256: &str) -> DomainResult<bool> {
        let output = native_cli_output(path, expected_sha256, &["peer"])?;
        Ok(output.lines().skip(1).any(|line| !line.trim().is_empty()))
    }

    fn route_cidrs(&mut self, path: &Path, expected_sha256: &str) -> DomainResult<Vec<String>> {
        let output = native_cli_output(path, expected_sha256, &["route"])?;
        let mut cidrs = Vec::new();
        for token in output.split_whitespace() {
            let token = token.trim_matches(|character: char| {
                matches!(character, '|' | ',' | '[' | ']' | '(' | ')' | '"')
            });
            if token.contains('/') && !cidrs.iter().any(|cidr| cidr == token) {
                cidrs.push(token.to_string());
            }
        }
        Ok(cidrs)
    }
}

#[cfg(windows)]
fn native_cli_output(
    path: &Path,
    expected_sha256: &str,
    arguments: &[&str],
) -> DomainResult<String> {
    let path = native_windows_validate_existing_easytier_artifact(path)
        .map_err(|_| status_error("explicit EasyTier CLI could not be executed"))?;
    verify_file_sha256(&path, expected_sha256)
        .map_err(|_| status_error("explicit EasyTier CLI does not match its pin"))?;
    let working_directory = path
        .parent()
        .ok_or_else(|| status_error("explicit EasyTier CLI could not be executed"))?;
    let mut command = native_windows_hardened_command(&path)
        .map_err(|_| status_error("explicit EasyTier CLI could not be executed"))?;
    let output = command
        .current_dir(working_directory)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| status_error("explicit EasyTier CLI could not be executed"))?;
    if !output.status.success() {
        return Err(status_error("explicit EasyTier CLI command failed"));
    }
    String::from_utf8(output.stdout)
        .map(|output| output.trim().to_string())
        .map_err(|_| status_error("explicit EasyTier CLI returned non-text output"))
}

#[cfg(not(windows))]
impl EasyTierCliRunner for NativeEasyTierCliRunner {
    fn version(&mut self, _path: &Path, _expected_sha256: &str) -> DomainResult<String> {
        Err(status_error(
            "Windows EasyTier CLI execution is unavailable on this platform",
        ))
    }

    fn peer_ready(&mut self, _path: &Path, _expected_sha256: &str) -> DomainResult<bool> {
        Err(status_error(
            "Windows EasyTier CLI execution is unavailable on this platform",
        ))
    }

    fn route_cidrs(&mut self, _path: &Path, _expected_sha256: &str) -> DomainResult<Vec<String>> {
        Err(status_error(
            "Windows EasyTier CLI execution is unavailable on this platform",
        ))
    }
}

/// Production Windows route port for host-specific EasyTier underlay bypasses.
#[cfg(windows)]
#[derive(Debug, Default)]
pub struct NativeWindowsRoutePort {
    pending_snapshot: Option<Vec<WindowsRouteSnapshotEntry>>,
    owned_bypasses: BTreeMap<String, Vec<NativeBypassRoute>>,
    owned_destination_routes: BTreeMap<String, Vec<NativeDestinationRoute>>,
    cleanup_destination_keys: BTreeSet<String>,
}

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct NativeBypassRoute {
    endpoint: Ipv4Addr,
    gateway: Ipv4Addr,
    interface_index: u32,
    metric: u16,
}

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct NativeDestinationRoute {
    destination_cidr: String,
    gateway: String,
    interface_index: u32,
    metric: u32,
}

#[cfg(windows)]
impl WindowsRoutePort for NativeWindowsRoutePort {
    fn snapshot(&mut self, endpoints: &[IpAddr]) -> DomainResult<Vec<WindowsRouteSnapshotEntry>> {
        let snapshot = endpoints
            .iter()
            .map(native_route_snapshot)
            .collect::<DomainResult<Vec<_>>>()?;
        self.pending_snapshot = Some(snapshot.clone());
        Ok(snapshot)
    }

    fn add_endpoint_bypass(&mut self, endpoints: &[IpAddr]) -> DomainResult<()> {
        let snapshot = self.pending_snapshot.take().ok_or_else(|| {
            endpoint_bypass_error("underlay bypass was requested without a route snapshot")
        })?;
        let bypasses = native_bypass_routes_from_snapshot(&snapshot)?;
        let requested_endpoints = endpoints
            .iter()
            .map(|endpoint| match endpoint {
                IpAddr::V4(endpoint) => Ok(*endpoint),
                IpAddr::V6(_) => Err(endpoint_bypass_error(
                    "underlay bypass endpoints do not match the captured route snapshot",
                )),
            })
            .collect::<DomainResult<Vec<_>>>()?;
        if bypasses
            .iter()
            .map(|route| route.endpoint)
            .collect::<Vec<_>>()
            != requested_endpoints
        {
            return Err(endpoint_bypass_error(
                "underlay bypass endpoints do not match the captured route snapshot",
            ));
        }
        let key = native_bypass_key(&bypasses);
        if self.owned_bypasses.contains_key(&key) {
            return Err(endpoint_bypass_error(
                "underlay bypass is already owned by this session",
            ));
        }

        let mut added = Vec::with_capacity(bypasses.len());
        for bypass in &bypasses {
            if native_add_bypass(bypass).is_err() {
                for bypass in &added {
                    let _ = native_remove_bypass(bypass);
                }
                return Err(endpoint_bypass_error("underlay bypass command failed"));
            }
            added.push(bypass.clone());
        }

        self.owned_bypasses.insert(key, bypasses);
        Ok(())
    }

    fn recover_owned_bypass(&mut self, snapshot: &[WindowsRouteSnapshotEntry]) -> DomainResult<()> {
        let bypasses = native_bypass_routes_from_snapshot(snapshot)?;
        let key = native_bypass_key(&bypasses);
        for bypass in &bypasses {
            native_prove_bypass(bypass)?;
        }
        self.owned_bypasses.insert(key, bypasses);
        Ok(())
    }

    fn recover_cleanup_bypass(
        &mut self,
        snapshot: &[WindowsRouteSnapshotEntry],
    ) -> DomainResult<()> {
        let bypasses = native_bypass_routes_from_snapshot(snapshot)?;
        let key = native_bypass_key(&bypasses);
        let mut present = Vec::new();
        for bypass in &bypasses {
            if native_cleanup_bypass_presence(bypass)? {
                present.push(bypass.clone());
            }
        }
        self.owned_bypasses.remove(&key);
        if !present.is_empty() {
            self.owned_bypasses.insert(key, present);
        }
        Ok(())
    }

    fn restore(&mut self, snapshot: &[WindowsRouteSnapshotEntry]) -> DomainResult<()> {
        let bypasses = native_bypass_routes_from_snapshot(snapshot)?;
        let key = native_bypass_key(&bypasses);
        let Some(bypasses) = self.owned_bypasses.remove(&key) else {
            return Ok(());
        };
        let mut remaining = Vec::new();
        for bypass in bypasses {
            if native_remove_bypass(&bypass).is_err() {
                remaining.push(bypass);
            }
        }
        if !remaining.is_empty() {
            self.owned_bypasses.insert(key, remaining);
            return Err(endpoint_bypass_error(
                "one or more underlay bypass routes remain",
            ));
        }

        Ok(())
    }

    fn snapshot_destination_routes(
        &mut self,
        destination_cidrs: &[String],
    ) -> DomainResult<Vec<WindowsRouteSnapshotEntry>> {
        native_destination_route_snapshots(destination_cidrs)
    }

    fn capture_owned_destination_routes(
        &mut self,
        before: &[WindowsRouteSnapshotEntry],
        destination_cidrs: &[String],
    ) -> DomainResult<Vec<WindowsRouteSnapshotEntry>> {
        let destination_cidrs = native_normalize_destination_cidrs(destination_cidrs)?;
        let before = native_destination_routes_from_snapshot(before)?;
        if before
            .iter()
            .any(|route| !destination_cidrs.contains(&route.destination_cidr))
        {
            return Err(endpoint_bypass_error(
                "destination route snapshot contains an unrequested destination",
            ));
        }
        let before_keys = before
            .iter()
            .map(native_destination_route_tuple_key)
            .collect::<BTreeSet<_>>();
        let mut owned = Vec::with_capacity(destination_cidrs.len());
        for destination_cidr in destination_cidrs {
            let after = native_destination_route_snapshot(&destination_cidr)?;
            let after = native_destination_routes_from_snapshot(&after)?;
            let mut created = after
                .into_iter()
                .filter(|route| {
                    route.destination_cidr == destination_cidr
                        && !before_keys.contains(&native_destination_route_tuple_key(route))
                })
                .collect::<Vec<_>>();
            if created.len() != 1 {
                return Err(endpoint_bypass_error(
                    "destination route ownership could not be proven exactly",
                ));
            }
            let route = created
                .pop()
                .expect("one exact destination route was checked before extraction");
            native_prove_virtual_destination_route(&route)?;
            owned.push(route);
        }

        let key = native_destination_route_key(&owned);
        if self.owned_destination_routes.contains_key(&key) {
            return Err(endpoint_bypass_error(
                "destination route ownership is already held by this session",
            ));
        }
        let snapshot = native_destination_route_snapshot_entries(&owned);
        self.cleanup_destination_keys.remove(&key);
        self.owned_destination_routes.insert(key, owned);
        Ok(snapshot)
    }

    fn recover_owned_destination_routes(
        &mut self,
        owned: &[WindowsRouteSnapshotEntry],
    ) -> DomainResult<()> {
        let owned = native_destination_routes_from_snapshot(owned)?;
        let key = native_destination_route_key(&owned);
        for route in &owned {
            native_prove_virtual_destination_route(route)?;
        }
        self.cleanup_destination_keys.remove(&key);
        self.owned_destination_routes.insert(key, owned);
        Ok(())
    }

    fn recover_cleanup_destination_routes(
        &mut self,
        owned: &[WindowsRouteSnapshotEntry],
    ) -> DomainResult<()> {
        let owned = native_destination_routes_from_snapshot(owned)?;
        let key = native_destination_route_key(&owned);
        let cleanup_key = key.clone();
        let mut present = Vec::new();
        for route in &owned {
            if native_cleanup_destination_presence(route)? {
                present.push(route.clone());
            }
        }
        self.owned_destination_routes.remove(&key);
        if !present.is_empty() {
            self.owned_destination_routes.insert(key, present);
        }
        self.cleanup_destination_keys.insert(cleanup_key);
        Ok(())
    }

    fn remove_owned_destination_routes(
        &mut self,
        owned: &[WindowsRouteSnapshotEntry],
    ) -> DomainResult<()> {
        let owned = native_destination_routes_from_snapshot(owned)?;
        let key = native_destination_route_key(&owned);
        let cleanup_reconciled = self.cleanup_destination_keys.remove(&key);
        let Some(owned) = self.owned_destination_routes.remove(&key) else {
            if cleanup_reconciled {
                return Ok(());
            }
            return Err(endpoint_bypass_error(
                "destination route is not owned by this session",
            ));
        };
        let mut remaining = Vec::new();
        for route in owned {
            if native_remove_destination_route(&route).is_err() {
                remaining.push(route);
            }
        }
        if !remaining.is_empty() {
            self.owned_destination_routes.insert(key.clone(), remaining);
            if cleanup_reconciled {
                self.cleanup_destination_keys.insert(key);
            }
            return Err(endpoint_bypass_error(
                "one or more destination routes remain",
            ));
        }

        Ok(())
    }
}

#[cfg(all(test, windows))]
mod native_process_proof_tests {
    use super::*;
    use std::net::Ipv4Addr;

    const FIXTURE_BINARY_SHA256: &str =
        "d33d1d119b40c768c4d96c66236ba1c033e72a9c041e88aa9c84bd67a38d04a5";

    #[test]
    fn native_process_proof_requires_exact_arguments_and_records_creation_filetime() {
        let root = std::env::temp_dir().join(format!(
            "networkcore-windows-native-proof-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("native proof fixture directory exists");
        let binary_path = root.join("easytier-core.exe");
        let config_path = root.join("state.easytier.toml");
        fs::write(&binary_path, b"fixture-easytier-binary")
            .expect("native proof core fixture exists");
        fs::write(&config_path, "instance_name = 'fixture'")
            .expect("native proof config fixture exists");
        let binary_path = fs::canonicalize(&binary_path).expect("core fixture is canonical");
        let config_path = fs::canonicalize(&config_path).expect("config fixture is canonical");
        let process = OwnedProcessHandle {
            session_id: "fixture-session".to_string(),
            process_id: 41001,
            creation_marker: "2026-07-20T00:00:00Z".to_string(),
        };
        let creation_filetime = 133_713_371_337_u64;
        let exact_command_line = format!(
            "\"{}\" --config-file \"{}\" --disable-env-parsing",
            binary_path.display(),
            config_path.display()
        );
        let proof = native_process_proof_from_inspection(
            NativeProcessInspection {
                process_id: process.process_id,
                creation_marker: process.creation_marker.clone(),
                creation_filetime,
                executable_path: binary_path.to_string_lossy().into_owned(),
                command_line: exact_command_line,
            },
            &process,
            Some(&binary_path),
            FIXTURE_BINARY_SHA256,
            &config_path,
        )
        .expect("exact synthetic native inspection is accepted");
        assert_eq!(proof.creation_filetime, creation_filetime);

        let extra_argument_command_line = format!(
            "\"{}\" --config-file \"{}\" --disable-env-parsing --unexpected",
            binary_path.display(),
            config_path.display()
        );
        let extra_argument_proof = native_process_proof_from_inspection(
            NativeProcessInspection {
                process_id: process.process_id,
                creation_marker: process.creation_marker.clone(),
                creation_filetime,
                executable_path: binary_path.to_string_lossy().into_owned(),
                command_line: extra_argument_command_line,
            },
            &process,
            Some(&binary_path),
            FIXTURE_BINARY_SHA256,
            &config_path,
        );
        assert!(extra_argument_proof.is_none());
    }

    #[test]
    fn native_bypass_routes_require_one_normalized_ipv4_tuple_per_endpoint() {
        let snapshot = vec![WindowsRouteSnapshotEntry {
            destination_cidr: "198.51.100.10/32".to_string(),
            gateway: Some("192.0.2.1".to_string()),
            interface_index: Some(12),
            metric: Some(25),
        }];
        let routes = native_bypass_routes_from_snapshot(&snapshot)
            .expect("valid persisted endpoint bypass is normalized");
        assert_eq!(
            routes,
            vec![NativeBypassRoute {
                endpoint: Ipv4Addr::new(198, 51, 100, 10),
                gateway: Ipv4Addr::new(192, 0, 2, 1),
                interface_index: 12,
                metric: 25,
            }]
        );

        let rejected_snapshots = [
            Vec::new(),
            vec![WindowsRouteSnapshotEntry {
                destination_cidr: "198.51.100.10/24".to_string(),
                ..snapshot[0].clone()
            }],
            vec![WindowsRouteSnapshotEntry {
                destination_cidr: "2001:db8::10/32".to_string(),
                ..snapshot[0].clone()
            }],
            vec![WindowsRouteSnapshotEntry {
                gateway: Some("   ".to_string()),
                ..snapshot[0].clone()
            }],
            vec![WindowsRouteSnapshotEntry {
                gateway: Some("not-an-ip".to_string()),
                ..snapshot[0].clone()
            }],
            vec![WindowsRouteSnapshotEntry {
                interface_index: None,
                ..snapshot[0].clone()
            }],
            vec![WindowsRouteSnapshotEntry {
                interface_index: Some(0),
                ..snapshot[0].clone()
            }],
            vec![WindowsRouteSnapshotEntry {
                metric: None,
                ..snapshot[0].clone()
            }],
            vec![WindowsRouteSnapshotEntry {
                metric: Some(65_536),
                ..snapshot[0].clone()
            }],
            vec![snapshot[0].clone(), snapshot[0].clone()],
        ];
        for invalid_snapshot in rejected_snapshots {
            assert!(
                native_bypass_routes_from_snapshot(&invalid_snapshot).is_err(),
                "invalid persisted bypass snapshots are rejected"
            );
        }
    }

    #[test]
    fn native_exact_bypass_scripts_bind_every_route_tuple_field() {
        let snapshot = vec![WindowsRouteSnapshotEntry {
            destination_cidr: "198.51.100.10/32".to_string(),
            gateway: Some("192.0.2.1".to_string()),
            interface_index: Some(12),
            metric: Some(25),
        }];
        let route = native_bypass_routes_from_snapshot(&snapshot)
            .expect("valid persisted endpoint bypass is normalized")
            .pop()
            .expect("one normalized route is returned");
        let proof_script = native_exact_bypass_proof_script(&route);
        let removal_script = native_exact_bypass_removal_script(&route);
        let required_fragments = [
            "Get-NetRoute",
            "-PolicyStore ActiveStore",
            "-DestinationPrefix '198.51.100.10/32'",
            "-NextHop '192.0.2.1'",
            "-InterfaceIndex 12",
            "-RouteMetric 25",
            "$matches.Count -ne 1",
        ];
        for script in [&proof_script, &removal_script] {
            for fragment in required_fragments {
                assert!(
                    script.contains(fragment),
                    "exact bypass script contains {fragment}: {script}"
                );
            }
        }
        assert!(removal_script.contains(
            "Remove-NetRoute -InputObject $matches[0] -Confirm:$false -ErrorAction Stop"
        ));
        assert!(!removal_script.contains("route.exe"));
    }
}

#[cfg(windows)]
fn native_route_snapshot(endpoint: &IpAddr) -> DomainResult<WindowsRouteSnapshotEntry> {
    if !endpoint.is_ipv4() {
        return Err(endpoint_bypass_error(
            "Windows foreground tunnel supports only IPv4 underlay endpoints",
        ));
    }
    let script = format!(
        "$route = Find-NetRoute -RemoteIPAddress '{endpoint}' -ErrorAction Stop | Sort-Object RouteMetric | Select-Object -First 1; if ($null -eq $route) {{ exit 2 }}; $physical = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -Physical -ErrorAction SilentlyContinue | Where-Object {{ $_.Status -eq 'Up' }} | Select-Object -First 1; if ($null -eq $physical) {{ exit 2 }}; [PSCustomObject]@{{ NextHop = $route.NextHop; InterfaceIndex = $route.InterfaceIndex; RouteMetric = $route.RouteMetric }} | ConvertTo-Json -Compress"
    );
    let mut command = native_windows_system_command(NativeWindowsSystemTool::PowerShell)
        .map_err(|_| endpoint_bypass_error("physical route lookup could not be executed"))?;
    let output = command
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| endpoint_bypass_error("physical route lookup could not be executed"))?;
    if !output.status.success() {
        return Err(endpoint_bypass_error("physical route lookup failed"));
    }
    let route: NativeRouteLookup = serde_json::from_slice(&output.stdout)
        .map_err(|_| endpoint_bypass_error("physical route lookup returned invalid data"))?;
    if route.next_hop.trim().is_empty() || route.interface_index == 0 {
        return Err(endpoint_bypass_error("physical route lookup is incomplete"));
    }

    Ok(WindowsRouteSnapshotEntry {
        destination_cidr: format!("{endpoint}/32"),
        gateway: Some(route.next_hop),
        interface_index: Some(route.interface_index),
        metric: Some(route.route_metric),
    })
}

#[cfg(windows)]
#[derive(Debug, serde::Deserialize)]
struct NativeRouteLookup {
    #[serde(rename = "NextHop")]
    next_hop: String,
    #[serde(rename = "InterfaceIndex")]
    interface_index: u32,
    #[serde(rename = "RouteMetric")]
    route_metric: u32,
}

#[cfg(windows)]
fn native_bypass_routes_from_snapshot(
    snapshot: &[WindowsRouteSnapshotEntry],
) -> DomainResult<Vec<NativeBypassRoute>> {
    if snapshot.is_empty() {
        return Err(endpoint_bypass_error(
            "persisted endpoint bypass snapshot is empty",
        ));
    }

    let mut endpoints = BTreeSet::new();
    snapshot
        .iter()
        .map(|entry| {
            let (address, prefix) = entry.destination_cidr.split_once('/').ok_or_else(|| {
                endpoint_bypass_error("persisted endpoint bypass destination is invalid")
            })?;
            if prefix != "32" {
                return Err(endpoint_bypass_error(
                    "persisted endpoint bypass must use an IPv4 /32",
                ));
            }
            let endpoint = Ipv4Addr::from_str(address).map_err(|_| {
                endpoint_bypass_error("persisted endpoint bypass destination is not IPv4")
            })?;
            let gateway = entry
                .gateway
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    endpoint_bypass_error("persisted endpoint bypass gateway is unavailable")
                })?
                .parse::<Ipv4Addr>()
                .map_err(|_| {
                    endpoint_bypass_error("persisted endpoint bypass gateway is not IPv4")
                })?;
            let interface_index = entry
                .interface_index
                .filter(|value| *value != 0)
                .ok_or_else(|| {
                    endpoint_bypass_error("persisted endpoint bypass interface is invalid")
                })?;
            let metric = entry
                .metric
                .and_then(|value| u16::try_from(value).ok())
                .ok_or_else(|| {
                    endpoint_bypass_error("persisted endpoint bypass metric is invalid")
                })?;
            if !endpoints.insert(endpoint) {
                return Err(endpoint_bypass_error(
                    "persisted endpoint bypass contains a duplicate endpoint",
                ));
            }

            Ok(NativeBypassRoute {
                endpoint,
                gateway,
                interface_index,
                metric,
            })
        })
        .collect()
}

#[cfg(windows)]
fn native_silent_system_command(tool: NativeWindowsSystemTool) -> io::Result<Command> {
    let mut command = native_windows_system_command(tool)?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    Ok(command)
}

#[cfg(windows)]
fn native_add_bypass(route: &NativeBypassRoute) -> DomainResult<()> {
    let endpoint = route.endpoint.to_string();
    let gateway = route.gateway.to_string();
    let interface_index = route.interface_index.to_string();
    let metric = route.metric.to_string();
    let status = native_silent_system_command(NativeWindowsSystemTool::Route)
        .map_err(|_| endpoint_bypass_error("underlay bypass command could not run"))?
        .args([
            "ADD",
            &endpoint,
            "MASK",
            "255.255.255.255",
            &gateway,
            "METRIC",
            &metric,
            "IF",
            &interface_index,
        ])
        .status()
        .map_err(|_| endpoint_bypass_error("underlay bypass command could not run"))?;
    if !status.success() {
        return Err(endpoint_bypass_error("underlay bypass command failed"));
    }

    Ok(())
}

#[cfg(windows)]
fn native_exact_bypass_proof_script(route: &NativeBypassRoute) -> String {
    format!(
        "$matches = @(Get-NetRoute -PolicyStore ActiveStore -DestinationPrefix '{}/32' -NextHop '{}' -InterfaceIndex {} -RouteMetric {} -ErrorAction Stop)\nif ($matches.Count -ne 1) {{ exit 2 }}",
        route.endpoint, route.gateway, route.interface_index, route.metric
    )
}

#[cfg(windows)]
fn native_exact_bypass_removal_script(route: &NativeBypassRoute) -> String {
    format!(
        "{}\nRemove-NetRoute -InputObject $matches[0] -Confirm:$false -ErrorAction Stop",
        native_exact_bypass_proof_script(route)
    )
}

#[cfg(windows)]
fn native_cleanup_bypass_presence(route: &NativeBypassRoute) -> DomainResult<bool> {
    let script = format!(
        "$ErrorActionPreference = 'Stop'\ntry {{\n$matches = @(Get-NetRoute -PolicyStore ActiveStore -DestinationPrefix '{}/32' -NextHop '{}' -InterfaceIndex {} -RouteMetric {} -ErrorAction Stop)\nif ($matches.Count -eq 0) {{ exit 3 }}\nif ($matches.Count -ne 1) {{ exit 2 }}\n}}",
        route.endpoint, route.gateway, route.interface_index, route.metric
    ) + "\ncatch { exit 2 }";
    let status = native_silent_system_command(NativeWindowsSystemTool::PowerShell)
        .map_err(|_| endpoint_bypass_error("underlay bypass cleanup inspection could not run"))?
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .status()
        .map_err(|_| endpoint_bypass_error("underlay bypass cleanup inspection could not run"))?;
    match status.code() {
        Some(0) => Ok(true),
        Some(3) => Ok(false),
        _ => Err(endpoint_bypass_error(
            "underlay bypass cleanup inspection could not be proven",
        )),
    }
}

#[cfg(windows)]
fn native_prove_bypass(route: &NativeBypassRoute) -> DomainResult<()> {
    let script = native_exact_bypass_proof_script(route);
    let status = native_silent_system_command(NativeWindowsSystemTool::PowerShell)
        .map_err(|_| endpoint_bypass_error("underlay bypass proof could not run"))?
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .status()
        .map_err(|_| endpoint_bypass_error("underlay bypass proof could not run"))?;
    if !status.success() {
        return Err(endpoint_bypass_error("underlay bypass proof failed"));
    }

    Ok(())
}

#[cfg(windows)]
fn native_remove_bypass(route: &NativeBypassRoute) -> DomainResult<()> {
    let script = native_exact_bypass_removal_script(route);
    let status = native_silent_system_command(NativeWindowsSystemTool::PowerShell)
        .map_err(|_| endpoint_bypass_error("underlay bypass removal could not run"))?
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .status()
        .map_err(|_| endpoint_bypass_error("underlay bypass removal could not run"))?;
    if !status.success() {
        return Err(endpoint_bypass_error("underlay bypass removal failed"));
    }

    Ok(())
}

#[cfg(windows)]
fn native_bypass_key(routes: &[NativeBypassRoute]) -> String {
    let mut tuples = routes
        .iter()
        .map(|route| {
            format!(
                "{}|{}|{}|{}",
                route.endpoint, route.gateway, route.interface_index, route.metric,
            )
        })
        .collect::<Vec<_>>();
    tuples.sort();
    tuples.join("\n")
}

#[cfg(windows)]
#[derive(Debug, serde::Deserialize)]
struct NativeDestinationRouteSnapshotResponse {
    #[serde(rename = "Routes")]
    routes: Vec<NativeDestinationRouteLookup>,
}

#[cfg(windows)]
#[derive(Debug, serde::Deserialize)]
struct NativeDestinationRouteLookup {
    #[serde(rename = "DestinationPrefix")]
    destination_cidr: String,
    #[serde(rename = "NextHop")]
    gateway: String,
    #[serde(rename = "InterfaceIndex")]
    interface_index: u32,
    #[serde(rename = "RouteMetric")]
    metric: u32,
}

#[cfg(windows)]
fn native_destination_route_snapshot(
    destination_cidr: &str,
) -> DomainResult<Vec<WindowsRouteSnapshotEntry>> {
    let destination_cidr = native_normalize_destination_cidr(destination_cidr)?;
    let script = format!(
        "$routes = @(Get-NetRoute -PolicyStore ActiveStore -DestinationPrefix '{destination_cidr}' -ErrorAction Stop); $snapshots = @($routes | ForEach-Object {{ [PSCustomObject]@{{ DestinationPrefix = [string]$_.DestinationPrefix; NextHop = [string]$_.NextHop; InterfaceIndex = [uint32]$_.InterfaceIndex; RouteMetric = [uint32]$_.RouteMetric }} }}); [PSCustomObject]@{{ Routes = @($snapshots) }} | ConvertTo-Json -Compress"
    );
    let mut command = native_windows_system_command(NativeWindowsSystemTool::PowerShell)
        .map_err(|_| endpoint_bypass_error("destination route snapshot could not run"))?;
    let output = command
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| endpoint_bypass_error("destination route snapshot could not run"))?;
    if !output.status.success() {
        return Err(endpoint_bypass_error("destination route snapshot failed"));
    }
    let snapshot: NativeDestinationRouteSnapshotResponse = serde_json::from_slice(&output.stdout)
        .map_err(|_| {
        endpoint_bypass_error("destination route snapshot returned invalid data")
    })?;
    snapshot
        .routes
        .into_iter()
        .map(|route| {
            let destination_cidr = native_normalize_destination_cidr(&route.destination_cidr)?;
            if destination_cidr != route.destination_cidr
                || route.gateway.trim().is_empty()
                || route.interface_index == 0
            {
                return Err(endpoint_bypass_error(
                    "destination route snapshot is incomplete",
                ));
            }
            Ok(WindowsRouteSnapshotEntry {
                destination_cidr,
                gateway: Some(route.gateway.trim().to_string()),
                interface_index: Some(route.interface_index),
                metric: Some(route.metric),
            })
        })
        .collect()
}

#[cfg(windows)]
fn native_destination_route_snapshots(
    destination_cidrs: &[String],
) -> DomainResult<Vec<WindowsRouteSnapshotEntry>> {
    let destination_cidrs = native_normalize_destination_cidrs(destination_cidrs)?;
    let mut snapshot = Vec::new();
    for destination_cidr in destination_cidrs {
        snapshot.extend(native_destination_route_snapshot(&destination_cidr)?);
    }
    Ok(snapshot)
}

#[cfg(windows)]
fn native_normalize_destination_cidrs(destination_cidrs: &[String]) -> DomainResult<Vec<String>> {
    if destination_cidrs.is_empty() {
        return Err(endpoint_bypass_error(
            "destination route ownership requires at least one destination",
        ));
    }

    let mut seen = BTreeSet::new();
    let mut normalized = Vec::with_capacity(destination_cidrs.len());
    for destination_cidr in destination_cidrs {
        let destination_cidr = native_normalize_destination_cidr(destination_cidr)?;
        if !seen.insert(destination_cidr.clone()) {
            return Err(endpoint_bypass_error(
                "destination route ownership contains a duplicate destination",
            ));
        }
        normalized.push(destination_cidr);
    }
    Ok(normalized)
}

#[cfg(windows)]
fn native_normalize_destination_cidr(destination_cidr: &str) -> DomainResult<String> {
    crate::tunnel_config::canonical_destination_ipv4_cidr(destination_cidr)
        .map_err(|_| endpoint_bypass_error("destination route prefix is invalid"))
}

#[cfg(windows)]
fn native_destination_routes_from_snapshot(
    snapshot: &[WindowsRouteSnapshotEntry],
) -> DomainResult<Vec<NativeDestinationRoute>> {
    let mut tuples = BTreeSet::new();
    snapshot
        .iter()
        .map(|entry| {
            let destination_cidr = native_normalize_destination_cidr(&entry.destination_cidr)?;
            let gateway = entry
                .gateway
                .as_deref()
                .filter(|gateway| *gateway == gateway.trim() && !gateway.is_empty())
                .ok_or_else(|| endpoint_bypass_error("destination route gateway is unavailable"))?;
            let gateway = IpAddr::from_str(gateway)
                .map_err(|_| endpoint_bypass_error("destination route gateway is invalid"))?
                .to_string();
            let interface_index = entry
                .interface_index
                .filter(|index| *index != 0)
                .ok_or_else(|| endpoint_bypass_error("destination route interface is invalid"))?;
            let metric = entry
                .metric
                .ok_or_else(|| endpoint_bypass_error("destination route metric is invalid"))?;
            let route = NativeDestinationRoute {
                destination_cidr,
                gateway,
                interface_index,
                metric,
            };
            if !tuples.insert(native_destination_route_tuple_key(&route)) {
                return Err(endpoint_bypass_error(
                    "destination route snapshot contains a duplicate tuple",
                ));
            }
            Ok(route)
        })
        .collect()
}

#[cfg(windows)]
fn native_destination_route_snapshot_entries(
    routes: &[NativeDestinationRoute],
) -> Vec<WindowsRouteSnapshotEntry> {
    routes
        .iter()
        .map(|route| WindowsRouteSnapshotEntry {
            destination_cidr: route.destination_cidr.clone(),
            gateway: Some(route.gateway.clone()),
            interface_index: Some(route.interface_index),
            metric: Some(route.metric),
        })
        .collect()
}

#[cfg(windows)]
fn native_destination_route_tuple_key(route: &NativeDestinationRoute) -> String {
    format!(
        "{}|{}|{}|{}",
        route.destination_cidr, route.gateway, route.interface_index, route.metric
    )
}

#[cfg(windows)]
fn native_destination_route_key(routes: &[NativeDestinationRoute]) -> String {
    let mut tuples = routes
        .iter()
        .map(native_destination_route_tuple_key)
        .collect::<Vec<_>>();
    tuples.sort();
    tuples.join("\n")
}

#[cfg(windows)]
fn native_exact_destination_route_proof_script(route: &NativeDestinationRoute) -> String {
    format!(
        "$matches = @(Get-NetRoute -PolicyStore ActiveStore -DestinationPrefix '{}' -NextHop '{}' -InterfaceIndex {} -RouteMetric {} -ErrorAction Stop)\nif ($matches.Count -ne 1) {{ exit 2 }}\n$route = $matches[0]\n$physical = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -Physical -ErrorAction Stop\nif ($null -ne $physical) {{ exit 2 }}\n$adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction Stop\nif ($adapter.Status -ne 'Up') {{ exit 2 }}",
        route.destination_cidr, route.gateway, route.interface_index, route.metric
    )
}

#[cfg(windows)]
fn native_exact_destination_route_removal_script(route: &NativeDestinationRoute) -> String {
    format!(
        "{}\nRemove-NetRoute -InputObject $matches[0] -Confirm:$false -ErrorAction Stop",
        native_exact_destination_route_proof_script(route)
    )
}

#[cfg(windows)]
fn native_cleanup_destination_presence(route: &NativeDestinationRoute) -> DomainResult<bool> {
    let script = format!(
        "$ErrorActionPreference = 'Stop'\ntry {{\n$matches = @(Get-NetRoute -PolicyStore ActiveStore -DestinationPrefix '{}' -NextHop '{}' -InterfaceIndex {} -RouteMetric {} -ErrorAction Stop)\nif ($matches.Count -eq 0) {{ exit 3 }}\nif ($matches.Count -ne 1) {{ exit 2 }}\n$route = $matches[0]\n$physical = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -Physical -ErrorAction Stop\nif ($null -ne $physical) {{ exit 2 }}\n$adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction Stop\nif ($adapter.Status -ne 'Up') {{ exit 2 }}\n}}",
        route.destination_cidr, route.gateway, route.interface_index, route.metric
    ) + "\ncatch { exit 2 }";
    let status = native_silent_system_command(NativeWindowsSystemTool::PowerShell)
        .map_err(|_| endpoint_bypass_error("destination route cleanup inspection could not run"))?
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .status()
        .map_err(|_| endpoint_bypass_error("destination route cleanup inspection could not run"))?;
    match status.code() {
        Some(0) => Ok(true),
        Some(3) => Ok(false),
        _ => Err(endpoint_bypass_error(
            "destination route cleanup inspection could not be proven",
        )),
    }
}

#[cfg(windows)]
fn native_prove_virtual_destination_route(route: &NativeDestinationRoute) -> DomainResult<()> {
    let script = native_exact_destination_route_proof_script(route);
    let status = native_silent_system_command(NativeWindowsSystemTool::PowerShell)
        .map_err(|_| endpoint_bypass_error("destination route proof could not run"))?
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .status()
        .map_err(|_| endpoint_bypass_error("destination route proof could not run"))?;
    if !status.success() {
        return Err(endpoint_bypass_error("destination route proof failed"));
    }
    Ok(())
}

#[cfg(windows)]
fn native_remove_destination_route(route: &NativeDestinationRoute) -> DomainResult<()> {
    let script = native_exact_destination_route_removal_script(route);
    let status = native_silent_system_command(NativeWindowsSystemTool::PowerShell)
        .map_err(|_| endpoint_bypass_error("destination route removal could not run"))?
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .status()
        .map_err(|_| endpoint_bypass_error("destination route removal could not run"))?;
    if !status.success() {
        return Err(endpoint_bypass_error("destination route removal failed"));
    }
    Ok(())
}

#[cfg(not(windows))]
#[derive(Debug, Default)]
pub struct NativeWindowsRoutePort;

#[cfg(not(windows))]
impl WindowsRoutePort for NativeWindowsRoutePort {
    fn snapshot(&mut self, _endpoints: &[IpAddr]) -> DomainResult<Vec<WindowsRouteSnapshotEntry>> {
        Err(endpoint_bypass_error(
            "Windows route operations are unavailable on this platform",
        ))
    }

    fn add_endpoint_bypass(&mut self, _endpoints: &[IpAddr]) -> DomainResult<()> {
        Err(endpoint_bypass_error(
            "Windows route operations are unavailable on this platform",
        ))
    }

    fn recover_owned_bypass(
        &mut self,
        _snapshot: &[WindowsRouteSnapshotEntry],
    ) -> DomainResult<()> {
        Err(endpoint_bypass_error(
            "Windows route operations are unavailable on this platform",
        ))
    }

    fn restore(&mut self, _snapshot: &[WindowsRouteSnapshotEntry]) -> DomainResult<()> {
        Err(endpoint_bypass_error(
            "Windows route operations are unavailable on this platform",
        ))
    }

    fn snapshot_destination_routes(
        &mut self,
        _destination_cidrs: &[String],
    ) -> DomainResult<Vec<WindowsRouteSnapshotEntry>> {
        Err(endpoint_bypass_error(
            "Windows route operations are unavailable on this platform",
        ))
    }

    fn capture_owned_destination_routes(
        &mut self,
        _before: &[WindowsRouteSnapshotEntry],
        _destination_cidrs: &[String],
    ) -> DomainResult<Vec<WindowsRouteSnapshotEntry>> {
        Err(endpoint_bypass_error(
            "Windows route operations are unavailable on this platform",
        ))
    }

    fn recover_owned_destination_routes(
        &mut self,
        _owned: &[WindowsRouteSnapshotEntry],
    ) -> DomainResult<()> {
        Err(endpoint_bypass_error(
            "Windows route operations are unavailable on this platform",
        ))
    }

    fn remove_owned_destination_routes(
        &mut self,
        _owned: &[WindowsRouteSnapshotEntry],
    ) -> DomainResult<()> {
        Err(endpoint_bypass_error(
            "Windows route operations are unavailable on this platform",
        ))
    }
}
