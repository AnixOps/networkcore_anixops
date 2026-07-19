//! Foreground EasyTier session orchestration and route-safety ports.
//!
//! The generic service owns only processes and route bypasses that it starts in
//! the current instance. It never discovers, adopts, or terminates arbitrary
//! system processes.

use control_domain::{DomainError, DomainResult};
use std::collections::BTreeMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::tunnel_config::{
    read_tunnel_state, render_easytier_config, verify_file_sha256, write_tunnel_state,
    EasyTierConfigRequest, EasyTierLaunchSpec, OwnedProcessHandle, WindowsRouteSnapshotEntry,
    WindowsTunnelLifecycleState, WindowsTunnelState,
};
use crate::WindowsTunnelPlan;

pub const WINDOWS_TUNNEL_CONFIRMATION_REQUIRED_CODE: &str =
    "windows.tunnel.confirmation_required";
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
pub const WINDOWS_TUNNEL_OWNERSHIP_MISMATCH_CODE: &str =
    "windows.tunnel.ownership_mismatch";

/// Starts and stops only an EasyTier process created by the current session service.
pub trait EasyTierProcessRunner {
    fn start(&mut self, spec: &EasyTierLaunchSpec) -> DomainResult<OwnedProcessHandle>;
    fn stop(&mut self, handle: &OwnedProcessHandle) -> DomainResult<()>;
}

/// Queries one explicitly configured EasyTier CLI executable.
pub trait EasyTierCliRunner {
    fn version(&mut self, path: &Path) -> DomainResult<String>;
    fn peer_ready(&mut self, path: &Path) -> DomainResult<bool>;
    fn route_cidrs(&mut self, path: &Path) -> DomainResult<Vec<String>>;
}

/// Owns the physical underlay bypass route transaction for a foreground session.
pub trait WindowsRoutePort {
    fn snapshot(&mut self, endpoints: &[IpAddr]) -> DomainResult<Vec<WindowsRouteSnapshotEntry>>;
    fn add_endpoint_bypass(&mut self, endpoints: &[IpAddr]) -> DomainResult<()>;
    fn restore(&mut self, snapshot: &[WindowsRouteSnapshotEntry]) -> DomainResult<()>;
}

/// Explicit operator inputs for a foreground EasyTier session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsTunnelStartRequest {
    pub plan: WindowsTunnelPlan,
    pub easytier_binary: PathBuf,
    pub easytier_cli: PathBuf,
    pub easytier_version: String,
    pub easytier_sha256: String,
    pub network_name: String,
    pub network_secret_file: PathBuf,
    pub state_path: PathBuf,
    pub confirm: bool,
}

/// Session service composed from explicit process, CLI, and route ports.
pub struct WindowsTunnelSessionService<P, C, R> {
    process_runner: P,
    cli_runner: C,
    route_port: R,
    owned_sessions: BTreeMap<PathBuf, OwnedTunnelSession>,
}

impl<P, C, R> WindowsTunnelSessionService<P, C, R> {
    pub fn new(process_runner: P, cli_runner: C, route_port: R) -> Self {
        Self {
            process_runner,
            cli_runner,
            route_port,
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
        let prepared = self.prepare_start(request)?;

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

        if fs::write(&prepared.config_path, &prepared.config_toml).is_err() {
            return Err(self.rollback_routes_after_start_error(
                &route_snapshot,
                start_error("EasyTier session configuration could not be written"),
            ));
        }

        let spec = EasyTierLaunchSpec {
            binary_path: prepared.binary_path.clone(),
            cli_path: prepared.cli_path.clone(),
            config_path: prepared.config_path.clone(),
            expected_version: prepared.expected_version.clone(),
            expected_sha256: prepared.expected_sha256.clone(),
        };
        let process_handle = match self.process_runner.start(&spec) {
            Ok(handle) => handle,
            Err(_) => {
                return Err(self.rollback_failed_start(
                    &route_snapshot,
                    None,
                    &prepared.config_path,
                    start_error("EasyTier process could not be started"),
                ));
            }
        };

        let readiness = self.verify_readiness(&prepared.cli_path, &prepared.plan);
        if let Err(error) = readiness {
            return Err(self.rollback_failed_start(
                &route_snapshot,
                Some(&process_handle),
                &prepared.config_path,
                error,
            ));
        }

        let state = WindowsTunnelState {
            schema_version: crate::tunnel_config::WINDOWS_TUNNEL_STATE_SCHEMA_VERSION,
            session_id: prepared.plan.session_id.clone(),
            plan_digest: prepared.plan.plan_digest.clone(),
            selected_pop_id: prepared.plan.selected_pop_id.clone(),
            selected_endpoint: prepared.plan.selected_endpoint.clone(),
            state: WindowsTunnelLifecycleState::Running,
            config_path: redacted_config_path(&prepared.config_path),
            last_client_sequence: prepared.plan.client_sequence,
            last_pop_sequence: prepared.plan.pop_sequence,
            route_snapshot: route_snapshot.clone(),
            rollback_status: "clean".to_string(),
        };
        if let Err(error) = write_tunnel_state(&prepared.state_path, &state) {
            return Err(self.rollback_failed_start(
                &route_snapshot,
                Some(&process_handle),
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
                route_snapshot,
                route_cidrs: prepared
                    .plan
                    .route_intents
                    .iter()
                    .map(|route| route.destination_cidr.clone())
                    .collect(),
                config_path: prepared.config_path,
            },
        );

        Ok(state)
    }

    /// Queries readiness through the same explicit CLI path used at start time.
    pub fn status(&mut self, state_path: &Path) -> DomainResult<WindowsTunnelState> {
        let state = read_tunnel_state(state_path)?;
        if state.state != WindowsTunnelLifecycleState::Running {
            return Err(status_error("tunnel state is not running"));
        }
        let owned = self
            .owned_sessions
            .get(state_path)
            .ok_or_else(|| status_error("tunnel session is not owned by this service"))?;
        if owned.session_id != state.session_id {
            return Err(status_error("tunnel ownership token does not match persisted state"));
        }

        let peer_ready = self
            .cli_runner
            .peer_ready(&owned.cli_path)
            .map_err(|_| status_error("EasyTier peer readiness is unavailable"))?;
        let route_cidrs = self
            .cli_runner
            .route_cidrs(&owned.cli_path)
            .map_err(|_| status_error("EasyTier route readiness is unavailable"))?;
        if !peer_ready || !owned.route_cidrs.iter().all(|cidr| route_cidrs.contains(cidr)) {
            return Err(status_error("EasyTier session is not ready"));
        }

        Ok(state)
    }

    /// Removes session-owned route state and terminates only the owned process.
    pub fn stop(&mut self, state_path: &Path, confirm: bool) -> DomainResult<WindowsTunnelState> {
        if !confirm {
            return Err(confirmation_error());
        }

        let state = read_tunnel_state(state_path)?;
        if state.state != WindowsTunnelLifecycleState::Running {
            return Err(stop_error("tunnel state is not running"));
        }
        let session_matches = self
            .owned_sessions
            .get(state_path)
            .map(|owned| owned.session_id == state.session_id)
            .unwrap_or(false);
        if !session_matches {
            return Err(ownership_error());
        }
        let owned = self
            .owned_sessions
            .remove(state_path)
            .expect("owned tunnel session was checked before removal");

        let mut stopping = state.clone();
        stopping.state = WindowsTunnelLifecycleState::Stopping;
        stopping.rollback_status = "pending".to_string();
        if let Err(error) = write_tunnel_state(state_path, &stopping) {
            self.owned_sessions.insert(state_path.to_path_buf(), owned);
            return Err(error);
        }

        let route_result = self.route_port.restore(&owned.route_snapshot);
        let process_result = self.process_runner.stop(&owned.process_handle);
        let config_result = fs::remove_file(&owned.config_path);
        if route_result.is_err() || process_result.is_err() || config_result.is_err() {
            let mut failed = stopping;
            failed.state = WindowsTunnelLifecycleState::Failed;
            failed.rollback_status = "rollback_failed".to_string();
            let _ = write_tunnel_state(state_path, &failed);
            self.owned_sessions.insert(state_path.to_path_buf(), owned);
            return Err(rollback_error());
        }

        let mut stopped = stopping;
        stopped.state = WindowsTunnelLifecycleState::Stopped;
        stopped.rollback_status = "clean".to_string();
        write_tunnel_state(state_path, &stopped)?;
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
            return Err(start_error("tunnel plan is not safe for foreground execution"));
        }
        if self.owned_sessions.contains_key(&request.state_path) || request.state_path.exists() {
            return Err(start_error("state path is already owned or occupied"));
        }
        let state_directory = request
            .state_path
            .parent()
            .filter(|path| path.is_dir())
            .ok_or_else(|| start_error("state directory must already exist"))?;
        if !request.easytier_binary.is_file() || !request.easytier_cli.is_file() {
            return Err(start_error("configured EasyTier executable path is invalid"));
        }
        verify_file_sha256(&request.easytier_binary, &request.easytier_sha256)?;

        let configured_version = required_text(&request.easytier_version, "EasyTier version")?;
        let runtime_version = self
            .cli_runner
            .version(&request.easytier_cli)
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
        let config_path = state_directory.join(
            request
                .state_path
                .file_stem()
                .map(|stem| format!("{}.easytier.toml", stem.to_string_lossy()))
                .unwrap_or_else(|| "easytier-session.toml".to_string()),
        );
        if config_path.exists() {
            return Err(start_error("session configuration path is already occupied"));
        }
        let config = render_easytier_config(EasyTierConfigRequest {
            plan: &request.plan,
            network_name: &request.network_name,
            network_secret: &network_secret,
            virtual_ipv4: None,
        })?;

        Ok(PreparedStart {
            plan: request.plan,
            binary_path: request.easytier_binary,
            cli_path: request.easytier_cli,
            expected_version: configured_version,
            expected_sha256: request.easytier_sha256,
            state_path: request.state_path,
            config_path,
            config_toml: config.toml,
            endpoint,
        })
    }

    fn verify_readiness(&mut self, cli_path: &Path, plan: &WindowsTunnelPlan) -> DomainResult<()> {
        let peer_ready = self
            .cli_runner
            .peer_ready(cli_path)
            .map_err(|_| peer_not_ready_error())?;
        if !peer_ready {
            return Err(peer_not_ready_error());
        }

        let route_cidrs = self
            .cli_runner
            .route_cidrs(cli_path)
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
        process_handle: Option<&OwnedProcessHandle>,
        config_path: &Path,
        original: DomainError,
    ) -> DomainError {
        let routes_restored = self.route_port.restore(snapshot).is_ok();
        let process_stopped = process_handle
            .map(|handle| self.process_runner.stop(handle).is_ok())
            .unwrap_or(true);
        let config_removed = fs::remove_file(config_path).is_ok();
        if routes_restored && process_stopped && config_removed {
            original
        } else {
            rollback_error()
        }
    }
}

struct OwnedTunnelSession {
    session_id: String,
    process_handle: OwnedProcessHandle,
    cli_path: PathBuf,
    route_snapshot: Vec<WindowsRouteSnapshotEntry>,
    route_cidrs: Vec<String>,
    config_path: PathBuf,
}

struct PreparedStart {
    plan: WindowsTunnelPlan,
    binary_path: PathBuf,
    cli_path: PathBuf,
    expected_version: String,
    expected_sha256: String,
    state_path: PathBuf,
    config_path: PathBuf,
    config_toml: String,
    endpoint: IpAddr,
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

fn redacted_config_path(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "easytier-session.toml".to_string())
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
