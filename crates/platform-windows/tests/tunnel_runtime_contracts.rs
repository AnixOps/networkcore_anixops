use control_domain::{DomainError, DomainResult};
use platform_windows::tunnel_config::{
    read_tunnel_state, OwnedProcessHandle, WindowsRouteSnapshotEntry, WindowsTunnelLifecycleState,
    WindowsTunnelRuntimeOwnership, WindowsTunnelState, WINDOWS_TUNNEL_STATE_SCHEMA_VERSION,
};
use platform_windows::tunnel_runtime::{
    EasyTierCleanupRecovery, EasyTierCliRunner, EasyTierProcessRunner, EasyTierRecoverySpec,
    RecoveredEasyTierProcess, WindowsRoutePort, WindowsTunnelSessionService,
    WindowsTunnelStartRequest, WindowsTunnelStatePort,
    WINDOWS_TUNNEL_CONFIRMATION_REQUIRED_CODE, WINDOWS_TUNNEL_ENDPOINT_BYPASS_FAILED_CODE,
    WINDOWS_TUNNEL_OWNERSHIP_MISMATCH_CODE, WINDOWS_TUNNEL_PEER_NOT_READY_CODE,
    WINDOWS_TUNNEL_ROLLBACK_FAILED_CODE, WINDOWS_TUNNEL_START_FAILED_CODE,
};
use platform_windows::{WindowsTunnelPlan, WindowsTunnelRouteIntent};
use std::cell::RefCell;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::rc::Rc;

const FIXTURE_BINARY_SHA256: &str =
    "d33d1d119b40c768c4d96c66236ba1c033e72a9c041e88aa9c84bd67a38d04a5";

#[derive(Clone)]
struct SharedEvents(Rc<RefCell<Vec<String>>>);

impl SharedEvents {
    fn new() -> Self {
        Self(Rc::new(RefCell::new(Vec::new())))
    }

    fn push(&self, event: impl Into<String>) {
        self.0.borrow_mut().push(event.into());
    }

    fn snapshot(&self) -> Vec<String> {
        self.0.borrow().clone()
    }

    fn clear(&self) {
        self.0.borrow_mut().clear();
    }
}

struct FakeProcessRunner {
    events: SharedEvents,
    recovered_binary_path: Option<PathBuf>,
    recovered_cli_path: Option<PathBuf>,
    start_error: Option<DomainError>,
}

impl EasyTierProcessRunner for FakeProcessRunner {
    fn start(
        &mut self,
        _spec: &platform_windows::tunnel_config::EasyTierLaunchSpec,
    ) -> DomainResult<OwnedProcessHandle> {
        self.events.push("process.start");
        if let Some(error) = &self.start_error {
            return Err(error.clone());
        }
        Ok(OwnedProcessHandle {
            session_id: "fixture-session".to_string(),
            process_id: 41001,
            creation_marker: "fixture-creation-marker".to_string(),
        })
    }

    fn recover(&mut self, spec: &EasyTierRecoverySpec) -> DomainResult<RecoveredEasyTierProcess> {
        self.events.push("process.recover");
        let binary_path = self.recovered_binary_path.clone().ok_or_else(|| {
            DomainError::new(
                "fixture.recovery_proof_failed",
                "fixture recovery proof is unavailable",
            )
        })?;
        let cli_path = self.recovered_cli_path.clone().ok_or_else(|| {
            DomainError::new(
                "fixture.recovery_proof_failed",
                "fixture recovery proof is unavailable",
            )
        })?;
        Ok(RecoveredEasyTierProcess {
            process: spec.expected_process.clone(),
            binary_path,
            cli_path,
        })
    }

    fn stop(&mut self, handle: &OwnedProcessHandle) -> DomainResult<()> {
        self.events.push(format!(
            "process.stop:{}:{}:{}",
            handle.session_id, handle.process_id, handle.creation_marker
        ));
        Ok(())
    }
}

struct FakeCliRunner {
    events: SharedEvents,
    peer_ready: bool,
    routes: Vec<String>,
}

impl EasyTierCliRunner for FakeCliRunner {
    fn version(&mut self, path: &Path) -> DomainResult<String> {
        self.events.push(format!("cli.version:{}", path.display()));
        Ok("2.6.1".to_string())
    }

    fn peer_ready(&mut self, path: &Path) -> DomainResult<bool> {
        self.events
            .push(format!("cli.peer_ready:{}", path.display()));
        Ok(self.peer_ready)
    }

    fn route_cidrs(&mut self, path: &Path) -> DomainResult<Vec<String>> {
        self.events
            .push(format!("cli.route_cidrs:{}", path.display()));
        Ok(self.routes.clone())
    }
}

struct FakeRoutePort {
    events: SharedEvents,
    recovery_error: Option<DomainError>,
    restore_error: Option<DomainError>,
    destination_capture_error: Option<DomainError>,
    destination_remove_error: Option<DomainError>,
}

impl FakeRoutePort {
    fn ready(events: SharedEvents) -> Self {
        Self {
            events,
            recovery_error: None,
            restore_error: None,
            destination_capture_error: None,
            destination_remove_error: None,
        }
    }

    fn failing_recovery(events: SharedEvents) -> Self {
        Self {
            events,
            recovery_error: Some(DomainError::new(
                WINDOWS_TUNNEL_ENDPOINT_BYPASS_FAILED_CODE,
                "fixture route recovery proof failed",
            )),
            restore_error: None,
            destination_capture_error: None,
            destination_remove_error: None,
        }
    }

    fn recovery_is_configured_to_fail(&self) -> bool {
        self.recovery_error.is_some()
    }

    fn destination_capture_fails(events: SharedEvents) -> Self {
        Self {
            events,
            recovery_error: None,
            restore_error: None,
            destination_capture_error: Some(DomainError::new(
                WINDOWS_TUNNEL_ENDPOINT_BYPASS_FAILED_CODE,
                "fixture destination capture failed",
            )),
            destination_remove_error: None,
        }
    }

    fn destination_capture_cleanup_fails(events: SharedEvents) -> Self {
        Self {
            events,
            recovery_error: None,
            restore_error: Some(DomainError::new(
                WINDOWS_TUNNEL_ENDPOINT_BYPASS_FAILED_CODE,
                "fixture endpoint bypass restoration failed",
            )),
            destination_capture_error: Some(DomainError::new(
                WINDOWS_TUNNEL_ENDPOINT_BYPASS_FAILED_CODE,
                "fixture destination capture failed",
            )),
            destination_remove_error: None,
        }
    }

    fn bypass_restore_fails(events: SharedEvents) -> Self {
        Self {
            events,
            recovery_error: None,
            restore_error: Some(DomainError::new(
                WINDOWS_TUNNEL_ENDPOINT_BYPASS_FAILED_CODE,
                "fixture endpoint bypass restoration failed",
            )),
            destination_capture_error: None,
            destination_remove_error: None,
        }
    }

    fn destination_removal_fails(events: SharedEvents) -> Self {
        Self {
            events,
            recovery_error: None,
            restore_error: None,
            destination_capture_error: None,
            destination_remove_error: Some(DomainError::new(
                WINDOWS_TUNNEL_ENDPOINT_BYPASS_FAILED_CODE,
                "fixture destination removal failed",
            )),
        }
    }
}

impl WindowsRoutePort for FakeRoutePort {
    fn snapshot_destination_routes(
        &mut self,
        destination_cidrs: &[String],
    ) -> DomainResult<Vec<WindowsRouteSnapshotEntry>> {
        self.events.push(format!(
            "route.destination_snapshot:{}",
            destination_cidrs.len()
        ));
        Ok(destination_cidrs
            .iter()
            .map(|destination_cidr| WindowsRouteSnapshotEntry {
                destination_cidr: destination_cidr.clone(),
                gateway: Some("10.10.0.254".to_string()),
                interface_index: Some(7),
                metric: Some(25),
            })
            .collect())
    }

    fn capture_owned_destination_routes(
        &mut self,
        _before: &[WindowsRouteSnapshotEntry],
        destination_cidrs: &[String],
    ) -> DomainResult<Vec<WindowsRouteSnapshotEntry>> {
        self.events.push(format!(
            "route.destination_capture:{}",
            destination_cidrs.len()
        ));
        if let Some(error) = &self.destination_capture_error {
            return Err(error.clone());
        }
        Ok(destination_cidrs
            .iter()
            .map(|destination_cidr| WindowsRouteSnapshotEntry {
                destination_cidr: destination_cidr.clone(),
                gateway: Some("10.10.0.1".to_string()),
                interface_index: Some(42),
                metric: Some(7),
            })
            .collect())
    }

    fn recover_owned_destination_routes(
        &mut self,
        snapshot: &[WindowsRouteSnapshotEntry],
    ) -> DomainResult<()> {
        self.events.push(format!(
            "route.destination_recover:{}",
            route_snapshot_key(snapshot)
        ));
        Ok(())
    }

    fn remove_owned_destination_routes(
        &mut self,
        snapshot: &[WindowsRouteSnapshotEntry],
    ) -> DomainResult<()> {
        self.events.push(format!(
            "route.destination_remove:{}",
            route_snapshot_key(snapshot)
        ));
        match &self.destination_remove_error {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }

    fn snapshot(&mut self, endpoints: &[IpAddr]) -> DomainResult<Vec<WindowsRouteSnapshotEntry>> {
        self.events
            .push(format!("route.snapshot:{}", endpoints.len()));
        Ok(endpoints
            .iter()
            .map(|endpoint| WindowsRouteSnapshotEntry {
                destination_cidr: format!("{endpoint}/32"),
                gateway: None,
                interface_index: Some(12),
                metric: Some(25),
            })
            .collect())
    }

    fn add_endpoint_bypass(&mut self, endpoints: &[IpAddr]) -> DomainResult<()> {
        self.events
            .push(format!("route.bypass:{}", endpoints.len()));
        Ok(())
    }

    fn recover_owned_bypass(&mut self, snapshot: &[WindowsRouteSnapshotEntry]) -> DomainResult<()> {
        self.events
            .push(format!("route.recover:{}", route_snapshot_key(snapshot)));
        match &self.recovery_error {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }

    fn restore(&mut self, snapshot: &[WindowsRouteSnapshotEntry]) -> DomainResult<()> {
        self.events
            .push(format!("route.restore:{}", route_snapshot_key(snapshot)));
        match &self.restore_error {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }
}

#[derive(Clone)]
struct FakeStatePort {
    data: Rc<RefCell<FakeStatePortData>>,
    events: SharedEvents,
}

struct FakeStatePortData {
    state: WindowsTunnelState,
    failed_writes: Vec<WindowsTunnelLifecycleState>,
}

impl FakeStatePort {
    fn seeded(state: WindowsTunnelState, events: SharedEvents) -> Self {
        Self {
            data: Rc::new(RefCell::new(FakeStatePortData {
                state,
                failed_writes: Vec::new(),
            })),
            events,
        }
    }

    fn fail_next_write_for(&self, lifecycle: WindowsTunnelLifecycleState) {
        self.data.borrow_mut().failed_writes.push(lifecycle);
    }

    fn current(&self) -> WindowsTunnelState {
        self.data.borrow().state.clone()
    }
}

impl WindowsTunnelStatePort for FakeStatePort {
    fn read(&mut self, _path: &Path) -> DomainResult<WindowsTunnelState> {
        self.events.push("state.read");
        Ok(self.current())
    }

    fn write(&mut self, _path: &Path, state: &WindowsTunnelState) -> DomainResult<()> {
        self.events.push(format!("state.write:{:?}", state.state));
        let mut data = self.data.borrow_mut();
        if let Some(position) = data
            .failed_writes
            .iter()
            .position(|lifecycle| *lifecycle == state.state)
        {
            data.failed_writes.remove(position);
            self.events
                .push(format!("state.write_failed:{:?}", state.state));
            return Err(DomainError::new(
                "fixture.state_write_failed",
                "fixture state transition could not be persisted",
            ));
        }
        data.state = state.clone();
        Ok(())
    }
}

struct CleanupFakeProcessRunner {
    events: SharedEvents,
    recovered_binary_path: Option<PathBuf>,
    recovered_cli_path: Option<PathBuf>,
    cleanup_absent: bool,
    stop_error: Option<DomainError>,
}

impl CleanupFakeProcessRunner {
    fn present(
        events: SharedEvents,
        binary_path: PathBuf,
        cli_path: PathBuf,
        stop_error: Option<DomainError>,
    ) -> Self {
        Self {
            events,
            recovered_binary_path: Some(binary_path),
            recovered_cli_path: Some(cli_path),
            cleanup_absent: false,
            stop_error,
        }
    }

    fn absent(events: SharedEvents) -> Self {
        Self {
            events,
            recovered_binary_path: None,
            recovered_cli_path: None,
            cleanup_absent: true,
            stop_error: None,
        }
    }
}

impl EasyTierProcessRunner for CleanupFakeProcessRunner {
    fn start(
        &mut self,
        _spec: &platform_windows::tunnel_config::EasyTierLaunchSpec,
    ) -> DomainResult<OwnedProcessHandle> {
        Err(DomainError::new(
            "fixture.start_not_expected",
            "cleanup lifecycle tests do not start a process",
        ))
    }

    fn recover(&mut self, spec: &EasyTierRecoverySpec) -> DomainResult<RecoveredEasyTierProcess> {
        self.events.push("process.recover");
        let binary_path = self.recovered_binary_path.clone().ok_or_else(|| {
            DomainError::new(
                "fixture.recovery_proof_failed",
                "fixture process recovery proof is unavailable",
            )
        })?;
        let cli_path = self.recovered_cli_path.clone().ok_or_else(|| {
            DomainError::new(
                "fixture.recovery_proof_failed",
                "fixture process recovery proof is unavailable",
            )
        })?;
        Ok(RecoveredEasyTierProcess {
            process: spec.expected_process.clone(),
            binary_path,
            cli_path,
        })
    }

    fn recover_for_cleanup(
        &mut self,
        spec: &EasyTierRecoverySpec,
    ) -> DomainResult<EasyTierCleanupRecovery> {
        self.events.push("process.cleanup_recover");
        if self.cleanup_absent {
            Ok(EasyTierCleanupRecovery::Absent)
        } else {
            self.recover(spec).map(EasyTierCleanupRecovery::Present)
        }
    }

    fn stop(&mut self, handle: &OwnedProcessHandle) -> DomainResult<()> {
        self.events.push(format!(
            "process.stop:{}:{}:{}",
            handle.session_id, handle.process_id, handle.creation_marker
        ));
        match &self.stop_error {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }
}

#[derive(Clone)]
enum CleanupRouteProof {
    Exact(Vec<bool>),
    Ambiguous,
}

struct CleanupFakeRoutePort {
    events: SharedEvents,
    destination_proof: CleanupRouteProof,
    bypass_proof: CleanupRouteProof,
    destination_remove_error: Option<DomainError>,
    restore_error: Option<DomainError>,
    destination_remaining: Option<usize>,
    bypass_remaining: Option<usize>,
}

impl CleanupFakeRoutePort {
    fn complete(events: SharedEvents) -> Self {
        Self {
            events,
            destination_proof: CleanupRouteProof::Exact(vec![true, true]),
            bypass_proof: CleanupRouteProof::Exact(vec![true]),
            destination_remove_error: None,
            restore_error: None,
            destination_remaining: None,
            bypass_remaining: None,
        }
    }

    fn partial_destination_removal_fails(events: SharedEvents) -> Self {
        Self {
            destination_remove_error: Some(DomainError::new(
                WINDOWS_TUNNEL_ROLLBACK_FAILED_CODE,
                "fixture destination removal was interrupted after one exact tuple",
            )),
            ..Self::complete(events)
        }
    }

    fn reconciled(
        events: SharedEvents,
        destination_proof: CleanupRouteProof,
        bypass_proof: CleanupRouteProof,
    ) -> Self {
        Self {
            events,
            destination_proof,
            bypass_proof,
            destination_remove_error: None,
            restore_error: None,
            destination_remaining: None,
            bypass_remaining: None,
        }
    }

    fn strict_proof(proof: &CleanupRouteProof, expected: usize) -> DomainResult<()> {
        match proof {
            CleanupRouteProof::Exact(matches)
                if matches.len() == expected && matches.iter().all(|match_| *match_) =>
            {
                Ok(())
            }
            CleanupRouteProof::Exact(_) | CleanupRouteProof::Ambiguous => Err(DomainError::new(
                WINDOWS_TUNNEL_ROLLBACK_FAILED_CODE,
                "fixture strict route recovery could not prove every tuple",
            )),
        }
    }

    fn cleanup_proof(proof: &CleanupRouteProof, expected: usize) -> DomainResult<usize> {
        match proof {
            CleanupRouteProof::Exact(matches) if matches.len() == expected => {
                Ok(matches.iter().filter(|match_| **match_).count())
            }
            CleanupRouteProof::Exact(_) | CleanupRouteProof::Ambiguous => Err(DomainError::new(
                WINDOWS_TUNNEL_ROLLBACK_FAILED_CODE,
                "fixture cleanup route recovery found an ambiguous tuple",
            )),
        }
    }
}

impl WindowsRoutePort for CleanupFakeRoutePort {
    fn snapshot(&mut self, _endpoints: &[IpAddr]) -> DomainResult<Vec<WindowsRouteSnapshotEntry>> {
        Err(DomainError::new(
            "fixture.snapshot_not_expected",
            "cleanup lifecycle tests do not capture routes",
        ))
    }

    fn add_endpoint_bypass(&mut self, _endpoints: &[IpAddr]) -> DomainResult<()> {
        Err(DomainError::new(
            "fixture.bypass_not_expected",
            "cleanup lifecycle tests do not add bypasses",
        ))
    }

    fn recover_owned_bypass(&mut self, snapshot: &[WindowsRouteSnapshotEntry]) -> DomainResult<()> {
        self.events.push("route.bypass_recover_strict");
        Self::strict_proof(&self.bypass_proof, snapshot.len())
    }

    fn recover_cleanup_bypass(
        &mut self,
        snapshot: &[WindowsRouteSnapshotEntry],
    ) -> DomainResult<()> {
        self.events.push("route.bypass_recover_cleanup");
        self.bypass_remaining = Some(Self::cleanup_proof(&self.bypass_proof, snapshot.len())?);
        Ok(())
    }

    fn restore(&mut self, snapshot: &[WindowsRouteSnapshotEntry]) -> DomainResult<()> {
        let remaining = self.bypass_remaining.unwrap_or(snapshot.len());
        if remaining == 0 {
            self.events.push("route.bypass_skip_absent");
            return Ok(());
        }
        self.events.push("route.restore");
        match &self.restore_error {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }

    fn snapshot_destination_routes(
        &mut self,
        _destination_cidrs: &[String],
    ) -> DomainResult<Vec<WindowsRouteSnapshotEntry>> {
        Err(DomainError::new(
            "fixture.destination_snapshot_not_expected",
            "cleanup lifecycle tests do not capture destination routes",
        ))
    }

    fn capture_owned_destination_routes(
        &mut self,
        _before: &[WindowsRouteSnapshotEntry],
        _destination_cidrs: &[String],
    ) -> DomainResult<Vec<WindowsRouteSnapshotEntry>> {
        Err(DomainError::new(
            "fixture.destination_capture_not_expected",
            "cleanup lifecycle tests do not capture destination routes",
        ))
    }

    fn recover_owned_destination_routes(
        &mut self,
        snapshot: &[WindowsRouteSnapshotEntry],
    ) -> DomainResult<()> {
        self.events.push("route.destination_recover_strict");
        Self::strict_proof(&self.destination_proof, snapshot.len())
    }

    fn recover_cleanup_destination_routes(
        &mut self,
        snapshot: &[WindowsRouteSnapshotEntry],
    ) -> DomainResult<()> {
        self.events.push("route.destination_recover_cleanup");
        self.destination_remaining = Some(Self::cleanup_proof(
            &self.destination_proof,
            snapshot.len(),
        )?);
        Ok(())
    }

    fn remove_owned_destination_routes(
        &mut self,
        snapshot: &[WindowsRouteSnapshotEntry],
    ) -> DomainResult<()> {
        let remaining = self.destination_remaining.unwrap_or(snapshot.len());
        if remaining == 0 {
            self.events.push("route.destination_skip_absent");
            return Ok(());
        }
        if let Some(error) = &self.destination_remove_error {
            self.events.push("route.destination_remove_partial");
            return Err(error.clone());
        }
        self.events.push("route.destination_remove");
        Ok(())
    }
}

fn fake_process_runner(
    events: SharedEvents,
    recovered_binary_path: Option<PathBuf>,
    recovered_cli_path: Option<PathBuf>,
) -> FakeProcessRunner {
    FakeProcessRunner {
        events,
        recovered_binary_path,
        recovered_cli_path,
        start_error: None,
    }
}

fn failing_start_process_runner(events: SharedEvents, error: DomainError) -> FakeProcessRunner {
    FakeProcessRunner {
        events,
        recovered_binary_path: None,
        recovered_cli_path: None,
        start_error: Some(error),
    }
}

fn route_snapshot_key(snapshot: &[WindowsRouteSnapshotEntry]) -> String {
    snapshot
        .iter()
        .map(|route| route.destination_cidr.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

fn fixture_plan() -> WindowsTunnelPlan {
    WindowsTunnelPlan {
        session_id: "fixture-session".to_string(),
        tenant_id: "fixture-tenant-1".to_string(),
        client_bundle_id: "fixture-client-bundle".to_string(),
        pop_bundle_id: "fixture-pop-bundle".to_string(),
        client_sequence: 3,
        pop_sequence: 4,
        selected_pop_id: "pop-a".to_string(),
        selected_endpoint: "198.51.100.10:11010".to_string(),
        route_intents: vec![WindowsTunnelRouteIntent {
            route_id: "fixture-route".to_string(),
            destination_cidr: "203.0.113.0/24".to_string(),
            service_chain_id: "pop-a-chain".to_string(),
            direct_fallback: false,
        }],
        endpoint_bypass_required: true,
        plan_digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
    }
}

fn fixture_paths(name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "networkcore-windows-tunnel-{name}-{}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("fixture state directory");
    let binary = root.join("easytier-core.exe");
    let cli = root.join("easytier-cli.exe");
    let secret = root.join("network-secret.txt");
    fs::write(&binary, b"fixture-easytier-binary").expect("fixture EasyTier binary");
    fs::write(&cli, b"fixture-easytier-cli").expect("fixture EasyTier CLI");
    fs::write(&secret, b"fixture-network-secret").expect("fixture network secret");
    (binary, cli, secret)
}

fn cleanup_fixture(
    name: &str,
    lifecycle: WindowsTunnelLifecycleState,
) -> (PathBuf, PathBuf, PathBuf, PathBuf, WindowsTunnelState) {
    let (binary, cli, _secret) = fixture_paths(name);
    let state_path = binary.parent().expect("fixture parent").join("state.json");
    let config_path = state_path
        .parent()
        .expect("fixture state path has a parent")
        .join("state.easytier.toml");
    fs::write(&config_path, "fixture cleanup configuration")
        .expect("fixture cleanup configuration exists");
    let rollback_status = match lifecycle {
        WindowsTunnelLifecycleState::Running => "clean",
        WindowsTunnelLifecycleState::Stopping => "pending",
        WindowsTunnelLifecycleState::Failed => "rollback_failed",
        WindowsTunnelLifecycleState::Starting | WindowsTunnelLifecycleState::Stopped => "clean",
    };
    let destination_routes = vec![
        WindowsRouteSnapshotEntry {
            destination_cidr: "203.0.113.0/24".to_string(),
            gateway: Some("10.10.0.1".to_string()),
            interface_index: Some(42),
            metric: Some(7),
        },
        WindowsRouteSnapshotEntry {
            destination_cidr: "203.0.114.0/24".to_string(),
            gateway: Some("10.10.0.1".to_string()),
            interface_index: Some(42),
            metric: Some(7),
        },
    ];
    let state = WindowsTunnelState {
        schema_version: WINDOWS_TUNNEL_STATE_SCHEMA_VERSION,
        session_id: "fixture-session".to_string(),
        plan_digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .to_string(),
        selected_pop_id: "pop-a".to_string(),
        selected_endpoint: "198.51.100.10:11010".to_string(),
        state: lifecycle,
        config_path: "state.easytier.toml".to_string(),
        last_client_sequence: 3,
        last_pop_sequence: 4,
        client_bundle_id: "fixture-client-bundle".to_string(),
        client_sequence: 3,
        pop_bundle_id: "fixture-pop-bundle".to_string(),
        pop_sequence: 4,
        easytier_version: "2.6.1".to_string(),
        route_snapshot: vec![WindowsRouteSnapshotEntry {
            destination_cidr: "198.51.100.10/32".to_string(),
            gateway: Some("192.0.2.1".to_string()),
            interface_index: Some(12),
            metric: Some(25),
        }],
        rollback_status: rollback_status.to_string(),
        runtime_ownership: WindowsTunnelRuntimeOwnership {
            process: OwnedProcessHandle {
                session_id: "fixture-session".to_string(),
                process_id: 41001,
                creation_marker: "fixture-creation-marker".to_string(),
            },
            binary_sha256: FIXTURE_BINARY_SHA256.to_string(),
            cli_file_name: "easytier-cli.exe".to_string(),
            route_cidrs: vec!["203.0.113.0/24".to_string(), "203.0.114.0/24".to_string()],
            virtual_route_snapshot: destination_routes,
        },
    };
    (binary, cli, state_path, config_path, state)
}

fn start_request(
    binary: PathBuf,
    cli: PathBuf,
    secret: PathBuf,
    state_path: PathBuf,
) -> WindowsTunnelStartRequest {
    WindowsTunnelStartRequest {
        plan: fixture_plan(),
        easytier_binary: binary,
        easytier_cli: cli,
        easytier_version: "2.6.1".to_string(),
        easytier_sha256: FIXTURE_BINARY_SHA256.to_string(),
        network_name: "fixture-network".to_string(),
        network_secret_file: secret,
        state_path,
        confirm: true,
    }
}

fn event_index(events: &[String], prefix: &str) -> usize {
    events
        .iter()
        .position(|event| event.starts_with(prefix))
        .unwrap_or_else(|| panic!("missing event {prefix}: {events:?}"))
}

fn fixture_cli_outside_binary_directory(cli: &Path) -> PathBuf {
    let directory = cli
        .parent()
        .expect("fixture CLI has a parent directory")
        .join("recovery-proof");
    fs::create_dir_all(&directory).expect("recovered CLI directory exists");
    let recovered_cli = directory.join(cli.file_name().expect("fixture CLI has a file name"));
    fs::write(&recovered_cli, b"fixture-recovered-easytier-cli")
        .expect("recovered EasyTier CLI fixture exists");
    recovered_cli
}

#[test]
fn start_rejects_cli_outside_hash_verified_core_directory_before_version_call() {
    let events = SharedEvents::new();
    let (binary, cli, secret) = fixture_paths("start-cli-outside-core-directory");
    let state_path = binary.parent().expect("fixture parent").join("state.json");
    let outside_cli = fixture_cli_outside_binary_directory(&cli);
    let mut service = WindowsTunnelSessionService::new(
        fake_process_runner(events.clone(), None, None),
        FakeCliRunner {
            events: events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        FakeRoutePort::ready(events.clone()),
    );

    let error = service
        .start(start_request(binary, outside_cli, secret, state_path))
        .expect_err("CLI outside the hash-verified core directory is rejected");
    assert_eq!(error.code, WINDOWS_TUNNEL_START_FAILED_CODE);
    assert!(events.snapshot().is_empty());
}

#[test]
fn start_redacts_process_runner_paths_from_the_service_diagnostic() {
    let events = SharedEvents::new();
    let (binary, cli, secret) = fixture_paths("start-redacts-process-runner-paths");
    let state_path = binary.parent().expect("fixture parent").join("state.json");
    let raw_binary_path = binary.display().to_string();
    let raw_state_path = state_path.display().to_string();
    let raw_error = DomainError::new(
        "fixture.process_start_failed",
        format!(
            "fixture process runner failed for binary {raw_binary_path} and state {raw_state_path}"
        ),
    );
    let mut service = WindowsTunnelSessionService::new(
        failing_start_process_runner(events.clone(), raw_error),
        FakeCliRunner {
            events: events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        FakeRoutePort::ready(events),
    );

    let error = service
        .start(start_request(binary, cli, secret, state_path))
        .expect_err("process-runner start failures are redacted by the service");
    assert_eq!(error.code, WINDOWS_TUNNEL_START_FAILED_CODE);
    assert_eq!(error.message, "EasyTier process could not be started");
    assert!(!error.message.contains(&raw_binary_path));
    assert!(!error.message.contains(&raw_state_path));
    assert!(!error.message.contains("fixture process runner failed"));
}

#[test]
fn start_rejects_noncanonical_destination_policies_before_route_mutation() {
    let cases: &[(&str, &[&str])] = &[
        ("default-ipv4", &["0.0.0.0/0"]),
        ("default-ipv6", &["::/0"]),
        ("ipv6", &["2001:db8::/32"]),
        ("host-bits", &["203.0.113.1/24"]),
        ("whitespace", &[" 203.0.113.0/24"]),
        ("malformed", &["not-a-destination-prefix"]),
        ("duplicate", &["203.0.113.0/24", "203.0.113.0/24"]),
    ];

    for (name, destination_cidrs) in cases {
        let events = SharedEvents::new();
        let (binary, cli, secret) = fixture_paths(&format!("start-invalid-policy-{name}"));
        let state_path = binary.parent().expect("fixture parent").join("state.json");
        let mut request = start_request(binary, cli, secret, state_path);
        request.plan.route_intents = destination_cidrs
            .iter()
            .enumerate()
            .map(|(index, destination_cidr)| WindowsTunnelRouteIntent {
                route_id: format!("fixture-route-{index}"),
                destination_cidr: (*destination_cidr).to_string(),
                service_chain_id: "pop-a-chain".to_string(),
                direct_fallback: false,
            })
            .collect();
        let mut service = WindowsTunnelSessionService::new(
            fake_process_runner(events.clone(), None, None),
            FakeCliRunner {
                events: events.clone(),
                peer_ready: true,
                routes: vec!["203.0.113.0/24".to_string()],
            },
            FakeRoutePort::ready(events.clone()),
        );

        let error = service
            .start(request)
            .expect_err("invalid destination policy must fail preflight");
        assert_eq!(error.code, WINDOWS_TUNNEL_START_FAILED_CODE);
        assert!(
            !events
                .snapshot()
                .iter()
                .any(|event| event.starts_with("route.")),
            "{name} must be rejected before any route operation"
        );
    }
}

#[test]
fn start_orders_destination_snapshot_bypass_process_readiness_capture_and_state() {
    let events = SharedEvents::new();
    let (binary, cli, secret) = fixture_paths("start-order");
    let state_path = binary.parent().expect("fixture parent").join("state.json");
    let mut service = WindowsTunnelSessionService::new(
        fake_process_runner(events.clone(), None, None),
        FakeCliRunner {
            events: events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        FakeRoutePort::ready(events.clone()),
    );

    let state = service
        .start(start_request(binary, cli, secret, state_path.clone()))
        .expect("fake EasyTier session starts");
    assert_eq!(state.state, WindowsTunnelLifecycleState::Running);
    assert_eq!(
        read_tunnel_state(&state_path).expect("state is persisted"),
        state
    );

    let events = events.snapshot();
    assert!(event_index(&events, "cli.version") < event_index(&events, "route.snapshot"));
    assert!(
        event_index(&events, "route.destination_snapshot") < event_index(&events, "route.snapshot")
    );
    assert!(event_index(&events, "route.snapshot") < event_index(&events, "route.bypass"));
    assert!(event_index(&events, "route.bypass") < event_index(&events, "process.start"));
    assert!(event_index(&events, "process.start") < event_index(&events, "cli.peer_ready"));
    assert!(event_index(&events, "cli.peer_ready") < event_index(&events, "cli.route_cidrs"));
    assert!(
        event_index(&events, "cli.route_cidrs") < event_index(&events, "route.destination_capture")
    );
}

#[test]
fn destination_capture_failure_returns_rollback_without_unproven_removal() {
    let events = SharedEvents::new();
    let (binary, cli, secret) = fixture_paths("destination-capture-failure");
    let state_path = binary.parent().expect("fixture parent").join("state.json");
    let mut service = WindowsTunnelSessionService::new(
        fake_process_runner(events.clone(), None, None),
        FakeCliRunner {
            events: events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        FakeRoutePort::destination_capture_fails(events.clone()),
    );

    let error = service
        .start(start_request(binary, cli, secret, state_path))
        .expect_err("destination ownership capture failure must abort cleanup");
    assert_eq!(error.code, WINDOWS_TUNNEL_ROLLBACK_FAILED_CODE);
    let events = events.snapshot();
    assert!(
        event_index(&events, "route.destination_capture") < event_index(&events, "route.restore")
    );
    assert!(event_index(&events, "route.restore") < event_index(&events, "process.stop"));
    assert!(!events
        .iter()
        .any(|event| event.starts_with("route.destination_remove")));
}

#[test]
fn unproven_destination_capture_retains_config_when_cleanup_fails() {
    let events = SharedEvents::new();
    let (binary, cli, secret) = fixture_paths("destination-capture-cleanup-failure");
    let state_path = binary.parent().expect("fixture parent").join("state.json");
    let config_path = state_path
        .parent()
        .expect("fixture state path has a parent")
        .join("state.easytier.toml");
    let mut service = WindowsTunnelSessionService::new(
        fake_process_runner(events.clone(), None, None),
        FakeCliRunner {
            events: events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        FakeRoutePort::destination_capture_cleanup_fails(events.clone()),
    );

    let error = service
        .start(start_request(binary, cli, secret, state_path))
        .expect_err("unproven destination capture must fail closed");
    assert_eq!(error.code, WINDOWS_TUNNEL_ROLLBACK_FAILED_CODE);
    assert!(
        config_path.is_file(),
        "manual recovery configuration remains when rollback cannot be proven"
    );
    assert!(!events
        .snapshot()
        .iter()
        .any(|event| event.starts_with("route.destination_remove")));
}

#[test]
fn destination_removal_failure_retains_owned_state_and_skips_later_cleanup() {
    let owner_events = SharedEvents::new();
    let (binary, cli, secret) = fixture_paths("destination-removal-failure");
    let state_path = binary.parent().expect("fixture parent").join("state.json");
    let mut owner = WindowsTunnelSessionService::new(
        fake_process_runner(owner_events.clone(), None, None),
        FakeCliRunner {
            events: owner_events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        FakeRoutePort::ready(owner_events.clone()),
    );
    owner
        .start(start_request(
            binary.clone(),
            cli.clone(),
            secret,
            state_path.clone(),
        ))
        .expect("owner starts a session");

    let events = SharedEvents::new();
    let mut recovered = WindowsTunnelSessionService::new(
        fake_process_runner(events.clone(), Some(binary), Some(cli)),
        FakeCliRunner {
            events: events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        FakeRoutePort::destination_removal_fails(events.clone()),
    );
    let error = recovered
        .stop(&state_path, true)
        .expect_err("destination removal failure must stop cleanup");
    assert_eq!(error.code, WINDOWS_TUNNEL_ROLLBACK_FAILED_CODE);
    let events = events.snapshot();
    let destination_remove = event_index(&events, "route.destination_remove");
    assert!(!events
        .iter()
        .any(|event| event.starts_with("route.restore")));
    assert!(!events.iter().any(|event| event.starts_with("process.stop")));
    assert!(destination_remove > event_index(&events, "route.destination_recover"));
    assert_eq!(
        read_tunnel_state(&state_path)
            .expect("failed cleanup state remains persisted")
            .state,
        WindowsTunnelLifecycleState::Failed
    );
    recovered
        .stop(&state_path, true)
        .expect_err("owned failed session must remain available for a later retry");
}

#[test]
fn readiness_failure_restores_routes_and_stops_owned_process() {
    let events = SharedEvents::new();
    let (binary, cli, secret) = fixture_paths("readiness-failure");
    let state_path = binary.parent().expect("fixture parent").join("state.json");
    let mut service = WindowsTunnelSessionService::new(
        fake_process_runner(events.clone(), None, None),
        FakeCliRunner {
            events: events.clone(),
            peer_ready: false,
            routes: Vec::new(),
        },
        FakeRoutePort::ready(events.clone()),
    );

    let error = service
        .start(start_request(binary, cli, secret, state_path))
        .expect_err("peer readiness failure must abort the session");
    assert_eq!(error.code, WINDOWS_TUNNEL_PEER_NOT_READY_CODE);

    let events = events.snapshot();
    assert!(event_index(&events, "process.start") < event_index(&events, "route.restore"));
    assert!(event_index(&events, "route.restore") < event_index(&events, "process.stop"));
}

#[test]
fn unproven_native_start_failure_retains_config_without_clean_rollback_state() {
    let events = SharedEvents::new();
    let (binary, cli, secret) = fixture_paths("unproven-native-start-failure");
    let state_path = binary.parent().expect("fixture parent").join("state.json");
    let config_path = state_path
        .parent()
        .expect("fixture state path has a parent")
        .join("state.easytier.toml");
    let mut service = WindowsTunnelSessionService::new(
        failing_start_process_runner(
            events.clone(),
            DomainError::new(
                WINDOWS_TUNNEL_ROLLBACK_FAILED_CODE,
                "fixture native child termination could not be proven",
            ),
        ),
        FakeCliRunner {
            events: events.clone(),
            peer_ready: true,
            routes: Vec::new(),
        },
        FakeRoutePort::ready(events.clone()),
    );

    let error = service
        .start(start_request(binary, cli, secret, state_path.clone()))
        .expect_err("unproven native process cleanup must fail closed");
    assert_eq!(error.code, WINDOWS_TUNNEL_ROLLBACK_FAILED_CODE);
    assert!(
        config_path.is_file(),
        "manual recovery configuration remains when native process cleanup is unproven"
    );
    assert!(
        !state_path.exists(),
        "failed start must not persist a state claiming clean rollback"
    );

    let events = events.snapshot();
    assert!(events.contains(&"process.start".to_string()));
    assert!(!events.iter().any(|event| event.starts_with("process.stop")));
}

#[test]
fn readiness_and_bypass_restore_failure_retain_config_without_clean_rollback_state() {
    let events = SharedEvents::new();
    let (binary, cli, secret) = fixture_paths("readiness-bypass-restore-failure");
    let state_path = binary.parent().expect("fixture parent").join("state.json");
    let config_path = state_path
        .parent()
        .expect("fixture state path has a parent")
        .join("state.easytier.toml");
    let mut service = WindowsTunnelSessionService::new(
        fake_process_runner(events.clone(), None, None),
        FakeCliRunner {
            events: events.clone(),
            peer_ready: false,
            routes: Vec::new(),
        },
        FakeRoutePort::bypass_restore_fails(events.clone()),
    );

    let error = service
        .start(start_request(binary, cli, secret, state_path.clone()))
        .expect_err("failed bypass restoration must retain the recovery configuration");
    assert_eq!(error.code, WINDOWS_TUNNEL_ROLLBACK_FAILED_CODE);
    assert!(
        config_path.is_file(),
        "manual recovery configuration remains when bypass restoration fails"
    );
    assert!(
        !state_path.exists(),
        "failed start must not persist a state claiming clean rollback"
    );

    let events = events.snapshot();
    assert!(events.contains(&"process.start".to_string()));
    assert!(event_index(&events, "process.start") < event_index(&events, "route.restore"));
    assert!(event_index(&events, "route.restore") < event_index(&events, "process.stop"));
}

#[test]
fn stop_rejects_missing_confirmation() {
    let events = SharedEvents::new();
    let (_binary, _cli, _secret) = fixture_paths("stop-confirmation");
    let state_path = std::env::temp_dir().join(format!(
        "networkcore-windows-tunnel-stop-confirmation-{}.json",
        std::process::id()
    ));
    let mut service = WindowsTunnelSessionService::new(
        fake_process_runner(events.clone(), None, None),
        FakeCliRunner {
            events: events.clone(),
            peer_ready: true,
            routes: Vec::new(),
        },
        FakeRoutePort::ready(events.clone()),
    );

    let error = service
        .stop(&state_path, false)
        .expect_err("stop must require explicit confirmation");
    assert_eq!(error.code, WINDOWS_TUNNEL_CONFIRMATION_REQUIRED_CODE);
    assert!(events.snapshot().is_empty());
}

#[test]
fn status_queries_explicit_easytier_cli() {
    let events = SharedEvents::new();
    let (binary, cli, secret) = fixture_paths("status-cli");
    let state_path = binary.parent().expect("fixture parent").join("state.json");
    let cli_path = fs::canonicalize(&cli).expect("fixture CLI path is canonical");
    let mut service = WindowsTunnelSessionService::new(
        fake_process_runner(events.clone(), None, None),
        FakeCliRunner {
            events: events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        FakeRoutePort::ready(events.clone()),
    );
    service
        .start(start_request(binary, cli, secret, state_path.clone()))
        .expect("fake EasyTier session starts");
    events.clear();

    service.status(&state_path).expect("status is available");
    let events = events.snapshot();
    assert!(events.contains(&format!("cli.peer_ready:{}", cli_path.display())));
    assert!(events.contains(&format!("cli.route_cidrs:{}", cli_path.display())));
}

#[test]
fn stale_state_cannot_stop_another_session() {
    let owner_events = SharedEvents::new();
    let (binary, cli, secret) = fixture_paths("stale-owner");
    let state_path = binary.parent().expect("fixture parent").join("state.json");
    let mut owner = WindowsTunnelSessionService::new(
        fake_process_runner(owner_events.clone(), None, None),
        FakeCliRunner {
            events: owner_events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        FakeRoutePort::ready(owner_events.clone()),
    );
    owner
        .start(start_request(binary, cli, secret, state_path.clone()))
        .expect("owner starts session");

    let stale_events = SharedEvents::new();
    let mut stale = WindowsTunnelSessionService::new(
        fake_process_runner(stale_events.clone(), None, None),
        FakeCliRunner {
            events: stale_events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        FakeRoutePort::ready(stale_events.clone()),
    );

    let error = stale
        .stop(&state_path, true)
        .expect_err("a service without the ownership token cannot stop the session");
    assert_eq!(error.code, WINDOWS_TUNNEL_OWNERSHIP_MISMATCH_CODE);
    assert_eq!(stale_events.snapshot(), vec!["process.recover"]);
}

#[test]
fn fresh_service_status_requires_recovery_proof() {
    let owner_events = SharedEvents::new();
    let (binary, cli, secret) = fixture_paths("fresh-status");
    let state_path = binary.parent().expect("fixture parent").join("state.json");
    let recovered_binary = binary.clone();
    let recovered_cli = fs::canonicalize(&cli).expect("fixture CLI path is canonical");
    let mut owner = WindowsTunnelSessionService::new(
        fake_process_runner(owner_events.clone(), None, None),
        FakeCliRunner {
            events: owner_events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        FakeRoutePort::ready(owner_events),
    );
    owner
        .start(start_request(binary, cli, secret, state_path.clone()))
        .expect("owner starts a persisted session");

    let failed_events = SharedEvents::new();
    let mut unproven = WindowsTunnelSessionService::new(
        fake_process_runner(failed_events.clone(), None, None),
        FakeCliRunner {
            events: failed_events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        FakeRoutePort::ready(failed_events.clone()),
    );
    unproven
        .status(&state_path)
        .expect_err("fresh status requires an ownership recovery proof");
    assert_eq!(failed_events.snapshot(), vec!["process.recover"]);

    let recovered_events = SharedEvents::new();
    let mut recovered = WindowsTunnelSessionService::new(
        fake_process_runner(
            recovered_events.clone(),
            Some(recovered_binary),
            Some(recovered_cli.clone()),
        ),
        FakeCliRunner {
            events: recovered_events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        FakeRoutePort::ready(recovered_events.clone()),
    );
    recovered
        .status(&state_path)
        .expect("proven fresh status is available");

    let events = recovered_events.snapshot();
    assert!(event_index(&events, "process.recover") < event_index(&events, "cli.peer_ready"));
    assert!(events.contains(&format!("cli.peer_ready:{}", recovered_cli.display())));
    assert!(events.contains(&format!("cli.route_cidrs:{}", recovered_cli.display())));
}

#[test]
fn fresh_service_rejects_recovered_cli_outside_proven_binary_directory() {
    let owner_events = SharedEvents::new();
    let (binary, cli, secret) = fixture_paths("fresh-rejected-cli-directory");
    let state_path = binary.parent().expect("fixture parent").join("state.json");
    let recovered_binary = binary.clone();
    let recovered_cli = fixture_cli_outside_binary_directory(&cli);
    let mut owner = WindowsTunnelSessionService::new(
        fake_process_runner(owner_events.clone(), None, None),
        FakeCliRunner {
            events: owner_events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        FakeRoutePort::ready(owner_events),
    );
    owner
        .start(start_request(binary, cli, secret, state_path.clone()))
        .expect("owner starts a persisted session");

    let recovered_events = SharedEvents::new();
    let mut recovered = WindowsTunnelSessionService::new(
        fake_process_runner(
            recovered_events.clone(),
            Some(recovered_binary),
            Some(recovered_cli),
        ),
        FakeCliRunner {
            events: recovered_events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        FakeRoutePort::ready(recovered_events.clone()),
    );

    let error = recovered
        .status(&state_path)
        .expect_err("recovered CLI outside the proven binary directory is rejected");
    assert_eq!(error.code, WINDOWS_TUNNEL_OWNERSHIP_MISMATCH_CODE);
    assert_eq!(recovered_events.snapshot(), vec!["process.recover"]);
}

#[cfg(unix)]
#[test]
fn fresh_service_rejects_recovered_config_symlink_outside_state_directory_before_process_recovery()
{
    use std::os::unix::fs::symlink;

    let owner_events = SharedEvents::new();
    let (binary, cli, secret) = fixture_paths("fresh-config-symlink-outside-state-directory");
    let state_path = binary.parent().expect("fixture parent").join("state.json");
    let recovered_binary = binary.clone();
    let recovered_cli = cli.clone();
    let mut owner = WindowsTunnelSessionService::new(
        fake_process_runner(owner_events.clone(), None, None),
        FakeCliRunner {
            events: owner_events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        FakeRoutePort::ready(owner_events),
    );
    let persisted = owner
        .start(start_request(binary, cli, secret, state_path.clone()))
        .expect("owner starts a persisted session");
    let config_path = state_path
        .parent()
        .expect("state path has a parent")
        .join(&persisted.config_path);
    let outside_config = std::env::temp_dir().join(format!(
        "networkcore-windows-tunnel-outside-config-{}.toml",
        std::process::id()
    ));
    fs::write(&outside_config, "fixture outside configuration")
        .expect("outside configuration fixture exists");
    fs::remove_file(&config_path).expect("owned configuration is removed before link swap");
    symlink(&outside_config, &config_path).expect("config path becomes an outside symlink");

    let recovered_events = SharedEvents::new();
    let mut recovered = WindowsTunnelSessionService::new(
        fake_process_runner(
            recovered_events.clone(),
            Some(recovered_binary),
            Some(recovered_cli),
        ),
        FakeCliRunner {
            events: recovered_events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        FakeRoutePort::ready(recovered_events.clone()),
    );

    let error = recovered
        .status(&state_path)
        .expect_err("fresh recovery rejects a configuration symlink outside the state directory");
    assert_eq!(error.code, WINDOWS_TUNNEL_OWNERSHIP_MISMATCH_CODE);
    assert!(recovered_events.snapshot().is_empty());
}

#[cfg(unix)]
#[test]
fn fresh_service_rejects_recovered_cli_symlink_outside_core_directory_before_readiness() {
    use std::os::unix::fs::symlink;

    let owner_events = SharedEvents::new();
    let (binary, cli, secret) = fixture_paths("fresh-cli-symlink-outside-core-directory");
    let state_path = binary.parent().expect("fixture parent").join("state.json");
    let recovered_binary = binary.clone();
    let mut owner = WindowsTunnelSessionService::new(
        fake_process_runner(owner_events.clone(), None, None),
        FakeCliRunner {
            events: owner_events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        FakeRoutePort::ready(owner_events),
    );
    owner
        .start(start_request(
            binary,
            cli.clone(),
            secret,
            state_path.clone(),
        ))
        .expect("owner starts a persisted session");
    let outside_cli = std::env::temp_dir().join(format!(
        "networkcore-windows-tunnel-outside-cli-{}",
        std::process::id()
    ));
    fs::write(&outside_cli, b"fixture outside EasyTier CLI")
        .expect("outside EasyTier CLI fixture exists");
    fs::remove_file(&cli).expect("owned CLI fixture is removed before link swap");
    symlink(&outside_cli, &cli).expect("CLI path becomes an outside symlink");

    let recovered_events = SharedEvents::new();
    let mut recovered = WindowsTunnelSessionService::new(
        fake_process_runner(recovered_events.clone(), Some(recovered_binary), Some(cli)),
        FakeCliRunner {
            events: recovered_events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        FakeRoutePort::ready(recovered_events.clone()),
    );

    let error = recovered
        .status(&state_path)
        .expect_err("fresh recovery rejects a same-name CLI symlink outside the core directory");
    assert_eq!(error.code, WINDOWS_TUNNEL_OWNERSHIP_MISMATCH_CODE);
    assert_eq!(recovered_events.snapshot(), vec!["process.recover"]);
}

#[test]
fn fresh_stop_requires_route_recovery_after_process_proof() {
    let owner_events = SharedEvents::new();
    let (binary, cli, secret) = fixture_paths("fresh-stop-route-recovery");
    let state_path = binary.parent().expect("fixture parent").join("state.json");
    let recovered_binary = binary.clone();
    let recovered_cli = cli.clone();
    let mut owner = WindowsTunnelSessionService::new(
        fake_process_runner(owner_events.clone(), None, None),
        FakeCliRunner {
            events: owner_events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        FakeRoutePort::ready(owner_events),
    );
    let persisted = owner
        .start(start_request(binary, cli, secret, state_path.clone()))
        .expect("owner starts a persisted session");
    let config_path = state_path
        .parent()
        .expect("state path has a parent")
        .join(&persisted.config_path);
    assert!(config_path.is_file());

    let recovered_events = SharedEvents::new();
    let route_port = FakeRoutePort::failing_recovery(recovered_events.clone());
    assert!(route_port.recovery_is_configured_to_fail());
    let mut recovered = WindowsTunnelSessionService::new(
        fake_process_runner(
            recovered_events.clone(),
            Some(recovered_binary),
            Some(recovered_cli),
        ),
        FakeCliRunner {
            events: recovered_events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        route_port,
    );
    let recovered_route_event = format!(
        "route.recover:{}",
        route_snapshot_key(&persisted.route_snapshot)
    );

    let error = recovered
        .stop(&state_path, true)
        .expect_err("fresh stop requires a recovered endpoint-bypass proof");
    assert_eq!(error.code, WINDOWS_TUNNEL_ENDPOINT_BYPASS_FAILED_CODE);
    assert_eq!(
        recovered_events.snapshot(),
        vec!["process.recover".to_string(), recovered_route_event]
    );
    assert_eq!(
        read_tunnel_state(&state_path)
            .expect("route recovery failure preserves state")
            .state,
        WindowsTunnelLifecycleState::Running
    );
    assert!(config_path.is_file());
}

#[test]
fn fresh_service_stop_requires_recovery_proof_before_cleanup() {
    let owner_events = SharedEvents::new();
    let (binary, cli, secret) = fixture_paths("fresh-stop");
    let state_path = binary.parent().expect("fixture parent").join("state.json");
    let recovered_binary = binary.clone();
    let recovered_cli = cli.clone();
    let mut owner = WindowsTunnelSessionService::new(
        fake_process_runner(owner_events.clone(), None, None),
        FakeCliRunner {
            events: owner_events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        FakeRoutePort::ready(owner_events),
    );
    let persisted = owner
        .start(start_request(binary, cli, secret, state_path.clone()))
        .expect("owner starts a persisted session");

    let failed_events = SharedEvents::new();
    let mut unproven = WindowsTunnelSessionService::new(
        fake_process_runner(failed_events.clone(), None, None),
        FakeCliRunner {
            events: failed_events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        FakeRoutePort::ready(failed_events.clone()),
    );
    unproven
        .stop(&state_path, true)
        .expect_err("fresh stop requires an ownership recovery proof");
    assert_eq!(failed_events.snapshot(), vec!["process.recover"]);

    let recovered_events = SharedEvents::new();
    let mut recovered = WindowsTunnelSessionService::new(
        fake_process_runner(
            recovered_events.clone(),
            Some(recovered_binary),
            Some(recovered_cli),
        ),
        FakeCliRunner {
            events: recovered_events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        FakeRoutePort::ready(recovered_events.clone()),
    );
    recovered
        .stop(&state_path, true)
        .expect("proven fresh stop completes cleanup");

    let events = recovered_events.snapshot();
    let process_recovered = event_index(&events, "process.recover");
    let route_recovered = event_index(&events, "route.recover");
    let destination_recovered = event_index(&events, "route.destination_recover");
    let destination_removed = event_index(&events, "route.destination_remove");
    let route_restored = event_index(&events, "route.restore");
    let process_stopped = event_index(&events, "process.stop");
    assert!(process_recovered < route_recovered);
    assert!(route_recovered < destination_recovered);
    assert!(destination_recovered < destination_removed);
    assert!(destination_removed < route_restored);
    assert!(route_restored < process_stopped);
    assert!(events.contains(&format!(
        "route.recover:{}",
        route_snapshot_key(&persisted.route_snapshot)
    )));
    assert!(events.contains(&format!(
        "route.restore:{}",
        route_snapshot_key(&persisted.route_snapshot)
    )));
    assert!(
        events.contains(&"process.stop:fixture-session:41001:fixture-creation-marker".to_string())
    );
}

#[test]
fn running_cleanup_persists_stopping_before_partial_destination_failure_and_resumes() {
    let events = SharedEvents::new();
    let (binary, cli, state_path, config_path, state) =
        cleanup_fixture("cleanup-partial-destination", WindowsTunnelLifecycleState::Running);
    let state_port = FakeStatePort::seeded(state, events.clone());
    state_port.fail_next_write_for(WindowsTunnelLifecycleState::Failed);
    let mut first = WindowsTunnelSessionService::new_with_state_port(
        CleanupFakeProcessRunner::present(events.clone(), binary.clone(), cli.clone(), None),
        FakeCliRunner {
            events: events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string(), "203.0.114.0/24".to_string()],
        },
        CleanupFakeRoutePort::partial_destination_removal_fails(events.clone()),
        state_port.clone(),
    );

    let error = first
        .stop(&state_path, true)
        .expect_err("partial destination removal requires retryable cleanup intent");
    assert_eq!(error.code, WINDOWS_TUNNEL_ROLLBACK_FAILED_CODE);
    assert_eq!(
        state_port.current().state,
        WindowsTunnelLifecycleState::Stopping,
        "a failed Failed write preserves the durable Stopping record"
    );
    let first_events = events.snapshot();
    assert!(
        event_index(&first_events, "state.write:Stopping")
            < event_index(&first_events, "route.destination_remove_partial")
    );
    assert!(config_path.is_file());

    events.clear();
    let mut retry = WindowsTunnelSessionService::new_with_state_port(
        CleanupFakeProcessRunner::present(events.clone(), binary, cli, None),
        FakeCliRunner {
            events: events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string(), "203.0.114.0/24".to_string()],
        },
        CleanupFakeRoutePort::reconciled(
            events.clone(),
            CleanupRouteProof::Exact(vec![false, true]),
            CleanupRouteProof::Exact(vec![true]),
        ),
        state_port.clone(),
    );
    let stopped = retry
        .stop(&state_path, true)
        .expect("fresh Stopping service reconciles the remaining exact resources");
    assert_eq!(stopped.state, WindowsTunnelLifecycleState::Stopped);
    assert_eq!(state_port.current().state, WindowsTunnelLifecycleState::Stopped);
    assert!(!config_path.exists());
}

#[test]
fn running_cleanup_persists_failed_after_process_stop_failure_and_resumes() {
    let events = SharedEvents::new();
    let (binary, cli, state_path, config_path, state) =
        cleanup_fixture("cleanup-process-stop-failure", WindowsTunnelLifecycleState::Running);
    let state_port = FakeStatePort::seeded(state, events.clone());
    let mut first = WindowsTunnelSessionService::new_with_state_port(
        CleanupFakeProcessRunner::present(
            events.clone(),
            binary.clone(),
            cli.clone(),
            Some(DomainError::new(
                WINDOWS_TUNNEL_ROLLBACK_FAILED_CODE,
                "fixture process stop failed",
            )),
        ),
        FakeCliRunner {
            events: events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string(), "203.0.114.0/24".to_string()],
        },
        CleanupFakeRoutePort::complete(events.clone()),
        state_port.clone(),
    );

    let error = first
        .stop(&state_path, true)
        .expect_err("process stop failure must retain a retryable failed cleanup state");
    assert_eq!(error.code, WINDOWS_TUNNEL_ROLLBACK_FAILED_CODE);
    assert_eq!(state_port.current().state, WindowsTunnelLifecycleState::Failed);
    let first_events = events.snapshot();
    assert!(
        event_index(&first_events, "route.restore")
            < event_index(&first_events, "process.stop")
    );
    assert!(config_path.is_file());

    events.clear();
    let mut retry = WindowsTunnelSessionService::new_with_state_port(
        CleanupFakeProcessRunner::present(events.clone(), binary, cli, None),
        FakeCliRunner {
            events: events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string(), "203.0.114.0/24".to_string()],
        },
        CleanupFakeRoutePort::reconciled(
            events.clone(),
            CleanupRouteProof::Exact(vec![false, false]),
            CleanupRouteProof::Exact(vec![false]),
        ),
        state_port.clone(),
    );
    let stopped = retry
        .stop(&state_path, true)
        .expect("fresh Failed service reconciles absent routes and stops the exact process");
    assert_eq!(stopped.state, WindowsTunnelLifecycleState::Stopped);
    assert_eq!(state_port.current().state, WindowsTunnelLifecycleState::Stopped);
    assert!(!config_path.exists());
    let retry_events = events.snapshot();
    assert!(!retry_events
        .iter()
        .any(|event| event.starts_with("route.destination_remove")));
    assert!(!retry_events.iter().any(|event| event == "route.restore"));
    assert!(retry_events.iter().any(|event| event.starts_with("process.stop")));
}

#[test]
fn stopped_write_failure_releases_session_for_absent_resource_reconciliation() {
    let events = SharedEvents::new();
    let (binary, cli, state_path, config_path, state) =
        cleanup_fixture("cleanup-stopped-write-failure", WindowsTunnelLifecycleState::Running);
    let state_port = FakeStatePort::seeded(state, events.clone());
    state_port.fail_next_write_for(WindowsTunnelLifecycleState::Stopped);
    let mut first = WindowsTunnelSessionService::new_with_state_port(
        CleanupFakeProcessRunner::present(events.clone(), binary, cli, None),
        FakeCliRunner {
            events: events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string(), "203.0.114.0/24".to_string()],
        },
        CleanupFakeRoutePort::complete(events.clone()),
        state_port.clone(),
    );

    first
        .stop(&state_path, true)
        .expect_err("a failed Stopped write leaves durable cleanup intent for retry");
    assert_eq!(state_port.current().state, WindowsTunnelLifecycleState::Stopping);
    assert!(!config_path.exists());

    events.clear();
    let mut retry = WindowsTunnelSessionService::new_with_state_port(
        CleanupFakeProcessRunner::absent(events.clone()),
        FakeCliRunner {
            events: events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string(), "203.0.114.0/24".to_string()],
        },
        CleanupFakeRoutePort::reconciled(
            events.clone(),
            CleanupRouteProof::Exact(vec![false, false]),
            CleanupRouteProof::Exact(vec![false]),
        ),
        state_port.clone(),
    );
    let stopped = retry
        .stop(&state_path, true)
        .expect("fresh Stopping service writes Stopped without deleting absent resources");
    assert_eq!(stopped.state, WindowsTunnelLifecycleState::Stopped);
    assert_eq!(state_port.current().state, WindowsTunnelLifecycleState::Stopped);
    let retry_events = events.snapshot();
    assert!(!retry_events
        .iter()
        .any(|event| event.starts_with("route.destination_remove")));
    assert!(!retry_events.iter().any(|event| event == "route.restore"));
    assert!(!retry_events.iter().any(|event| event.starts_with("process.stop")));
}

#[test]
fn running_recovery_rejects_missing_route_tuple_before_stopping_write() {
    let events = SharedEvents::new();
    let (binary, cli, state_path, _config_path, state) =
        cleanup_fixture("cleanup-running-strict-missing", WindowsTunnelLifecycleState::Running);
    let state_port = FakeStatePort::seeded(state, events.clone());
    let mut service = WindowsTunnelSessionService::new_with_state_port(
        CleanupFakeProcessRunner::present(events.clone(), binary, cli, None),
        FakeCliRunner {
            events: events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string(), "203.0.114.0/24".to_string()],
        },
        CleanupFakeRoutePort::reconciled(
            events.clone(),
            CleanupRouteProof::Exact(vec![false, false]),
            CleanupRouteProof::Exact(vec![true]),
        ),
        state_port.clone(),
    );

    let error = service
        .stop(&state_path, true)
        .expect_err("Running state rejects a missing exact destination tuple");
    assert_eq!(error.code, WINDOWS_TUNNEL_ROLLBACK_FAILED_CODE);
    assert_eq!(state_port.current().state, WindowsTunnelLifecycleState::Running);
    assert!(!events
        .snapshot()
        .iter()
        .any(|event| event == "state.write:Stopping"));
}

#[test]
fn cleanup_recovery_rejects_ambiguous_tuple_before_deletion() {
    let events = SharedEvents::new();
    let (_binary, _cli, state_path, _config_path, state) = cleanup_fixture(
        "cleanup-stopping-ambiguous-route",
        WindowsTunnelLifecycleState::Stopping,
    );
    let state_port = FakeStatePort::seeded(state, events.clone());
    let mut service = WindowsTunnelSessionService::new_with_state_port(
        CleanupFakeProcessRunner::absent(events.clone()),
        FakeCliRunner {
            events: events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string(), "203.0.114.0/24".to_string()],
        },
        CleanupFakeRoutePort::reconciled(
            events.clone(),
            CleanupRouteProof::Ambiguous,
            CleanupRouteProof::Exact(vec![true]),
        ),
        state_port.clone(),
    );

    let error = service
        .stop(&state_path, true)
        .expect_err("Stopping state accepts only zero-or-one exact result for each tuple");
    assert_eq!(error.code, WINDOWS_TUNNEL_ROLLBACK_FAILED_CODE);
    assert_eq!(state_port.current().state, WindowsTunnelLifecycleState::Failed);
    let events = events.snapshot();
    assert!(!events
        .iter()
        .any(|event| event.starts_with("route.destination_remove")));
    assert!(!events.iter().any(|event| event == "route.restore"));
}

#[test]
fn stop_persists_durable_stopping_before_first_destination_mutation() {
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

    let stopping_state = stop
        .find("self.state_port.write(&state_path, &stopping)?;")
        .expect("stop durably writes Stopping through the state port");
    let destination_remove = stop
        .find(".remove_owned_destination_routes(&owned.virtual_route_snapshot)")
        .expect("stop removes exact owned destination routes");
    assert!(
        stopping_state < destination_remove,
        "durable Stopping intent must precede the first destination deletion"
    );
}

#[test]
fn lifecycle_cleanup_uses_injected_state_port_and_leaves_retryable_intent() {
    let source = include_str!("../src/tunnel_runtime.rs").replace("\r\n", "\n");
    assert!(source.contains("pub trait WindowsTunnelStatePort"));
    assert!(source.contains("pub enum EasyTierCleanupRecovery"));
    assert!(source.contains("fn recover_for_cleanup("));
    assert!(source.contains("fn recover_cleanup_bypass("));
    assert!(source.contains("fn recover_cleanup_destination_routes("));
    let stop_marker =
        "    pub fn stop(&mut self, state_path: &Path, confirm: bool) -> DomainResult<WindowsTunnelState> {";
    let stop_start = source
        .find(stop_marker)
        .expect("stop implementation exists");
    let stop_end = source[stop_start..]
        .find("\n    fn prepare_start(")
        .expect("stop implementation ends before start preparation");
    let stop = &source[stop_start..stop_start + stop_end];

    assert!(stop.contains("self.state_port.read(&state_path)?;"));
    assert!(
        stop.contains("self.state_port.write(&state_path, &failed)"),
        "cleanup failures attempt durable Failed persistence through the injected port"
    );
    assert!(
        stop.contains("self.state_port.write(&state_path, &stopped)?;"),
        "a final Stopped transition is also written through the injected port"
    );
    let stopped_write = stop
        .find("self.state_port.write(&state_path, &stopped)?;")
        .expect("final Stopped transition exists");
    let released_session = stop[..stopped_write]
        .rfind("self.owned_sessions.remove(&state_path)")
        .expect("session is released before a failed Stopped write can return");
    assert!(
        released_session < stopped_write,
        "failed Stopped persistence must leave the next stop to reconcile fresh state"
    );
}

#[test]
fn failed_start_config_removal_requires_proven_destination_bypass_and_process_cleanup() {
    let source = include_str!("../src/tunnel_runtime.rs").replace("\r\n", "\n");
    let rollback_marker = "    fn rollback_failed_start(";
    let rollback_start = source
        .find(rollback_marker)
        .expect("failed-start rollback implementation exists");
    let rollback_end = source[rollback_start..]
        .find("\n\n    fn rollback_unproven_destination_capture(")
        .expect("failed-start rollback ends before unproven destination cleanup");
    let rollback = &source[rollback_start..rollback_start + rollback_end];

    assert!(
        source.contains(
            "enum StartProcessCleanup<'a> {\n    NotStarted,\n    Owned(&'a OwnedProcessHandle),\n    Unproven,\n}"
        ),
        "failed start distinguishes absent, owned, and unproven process cleanup"
    );
    assert!(
        rollback.contains("process: StartProcessCleanup<'_>"),
        "failed-start rollback receives an explicit process cleanup proof"
    );
    assert!(
        rollback.contains("StartProcessCleanup::Unproven => false"),
        "unproven process cleanup cannot be treated as stopped"
    );

    let all_cleanup_failure_guard = rollback
        .find("if !(destination_routes_removed && routes_restored && process_stopped) {")
        .expect("config removal has a destination, bypass, and process cleanup failure guard");
    let guard_rollback = all_cleanup_failure_guard
        + rollback[all_cleanup_failure_guard..]
            .find("return rollback_error();")
            .expect("failed cleanup returns rollback failure before config removal");
    let config_removal = rollback
        .find("if fs::remove_file(config_path).is_ok() {")
        .expect("failed-start rollback removes its direct-child config only after proof");
    assert!(all_cleanup_failure_guard < guard_rollback);
    assert!(guard_rollback < config_removal);
    assert!(
        rollback[config_removal..].contains(
            "if fs::remove_file(config_path).is_ok() {\n            original\n        } else {\n            rollback_error()\n        }"
        ),
        "config removal returns the original error only after the all-cleanup failure guard"
    );

    let unproven_capture_start = source
        .find("    fn rollback_unproven_destination_capture(")
        .expect("unproven destination cleanup implementation exists");
    let unproven_capture_end = source[unproven_capture_start..]
        .find("\n}\n\nstruct OwnedTunnelSession")
        .expect("unproven destination cleanup ends before session ownership");
    let unproven_capture =
        &source[unproven_capture_start..unproven_capture_start + unproven_capture_end];
    assert!(
        !unproven_capture.contains("fs::remove_file(config_path)"),
        "unproven destination cleanup retains the config because route cleanup is not proven"
    );
}

#[test]
fn native_windows_elevation_probe_is_explicit_and_fail_closed() {
    let source = include_str!("../src/tunnel_runtime.rs").replace("\r\n", "\n");
    let windows_marker = "#[cfg(windows)]\npub fn native_windows_is_elevated() -> bool {";
    let windows_start = source
        .find(windows_marker)
        .expect("Windows elevation probe exists");
    let non_windows_marker = "#[cfg(not(windows))]\npub fn native_windows_is_elevated() -> bool {";
    let non_windows_start = source
        .find(non_windows_marker)
        .expect("non-Windows elevation probe exists");
    let windows_probe = &source[windows_start..non_windows_start];

    assert!(
        windows_probe.contains("use windows_sys::Win32::UI::Shell::IsUserAnAdmin;"),
        "Windows elevation probe imports IsUserAnAdmin"
    );
    assert!(
        windows_probe.contains("unsafe { IsUserAnAdmin() != 0 }"),
        "Windows elevation probe returns IsUserAnAdmin as a Boolean"
    );
    assert!(
        source.contains(
            "#[cfg(not(windows))]\npub fn native_windows_is_elevated() -> bool {\n    false\n}"
        ),
        "non-Windows elevation probe returns literal false"
    );
}

#[test]
fn native_windows_process_start_discards_child_standard_streams() {
    let source = include_str!("../src/tunnel_runtime.rs").replace("\r\n", "\n");
    let command_builder_marker = "#[cfg(windows)]\nfn native_easytier_process_command(";
    let command_builder_start = source
        .find(command_builder_marker)
        .expect("Windows EasyTier command builder exists");
    let native_runner_marker =
        "#[cfg(windows)]\nimpl EasyTierProcessRunner for NativeEasyTierProcessRunner";
    let command_builder_end = source[command_builder_start..]
        .find(native_runner_marker)
        .expect("Windows command builder ends before native process start");
    let command_builder =
        &source[command_builder_start..command_builder_start + command_builder_end];

    let config_flag = command_builder
        .find(".arg(\"--config-file\")")
        .expect("command builder preserves the config-file flag");
    let config_path = command_builder
        .find(".arg(config_path)")
        .expect("command builder preserves the canonical config path");
    let disable_environment_parsing = command_builder
        .find(".arg(\"--disable-env-parsing\")")
        .expect("command builder preserves disabled environment parsing");
    assert!(
        config_flag < config_path && config_path < disable_environment_parsing,
        "command builder preserves the canonical EasyTier argument order"
    );

    let stdin = command_builder
        .find(".stdin(Stdio::null())")
        .expect("command builder discards child stdin");
    let stdout = command_builder
        .find(".stdout(Stdio::null())")
        .expect("command builder discards child stdout");
    let stderr = command_builder
        .find(".stderr(Stdio::null())")
        .expect("command builder discards child stderr");
    assert!(
        stdin < stdout && stdout < stderr,
        "command builder configures every child standard stream explicitly"
    );

    let native_runner = &source[command_builder_start + command_builder_end..];
    let start_offset = native_runner
        .find("fn start(&mut self, spec: &EasyTierLaunchSpec)")
        .expect("native process runner start exists");
    let start = &native_runner[start_offset..];
    let start_end = start
        .find("\n    fn recover(")
        .expect("native process runner start ends before recovery");
    let start = &start[..start_end];
    let command_builder_call = start
        .find("native_easytier_process_command(&binary_path, &config_path)")
        .expect("native process start uses the command builder");
    let spawn = start
        .find(".spawn()")
        .expect("native process start spawns the configured command");
    assert!(
        command_builder_call < spawn,
        "native process start configures the command before spawning it"
    );
}

#[test]
fn native_windows_recovery_and_removal_require_exact_bypass_proof() {
    let source = include_str!("../src/tunnel_runtime.rs").replace("\r\n", "\n");
    let route_port_marker = "#[cfg(windows)]\nimpl WindowsRoutePort for NativeWindowsRoutePort {";
    let route_port_start = source
        .find(route_port_marker)
        .expect("Windows route port implementation exists");
    let route_port_end = source[route_port_start..]
        .find("\n#[cfg(all(test, windows))]\nmod native_process_proof_tests")
        .expect("Windows route port implementation ends before native unit tests");
    let route_port = &source[route_port_start..route_port_start + route_port_end];
    let recovery_start = route_port
        .find("    fn recover_owned_bypass(")
        .expect("native bypass recovery exists");
    let recovery_end = route_port[recovery_start..]
        .find("\n\n    fn restore(")
        .expect("native bypass recovery ends before restore");
    let recovery = &route_port[recovery_start..recovery_start + recovery_end];

    let parse = recovery
        .find("native_bypass_routes_from_snapshot(snapshot)")
        .expect("recovery normalizes the persisted bypass snapshot");
    let key = recovery
        .find("native_bypass_key(&bypasses)")
        .expect("recovery constructs a normalized bypass ownership key");
    let proof_loop = recovery
        .find("for bypass in &bypasses")
        .expect("recovery proves each normalized bypass route");
    let proof = recovery
        .find("native_prove_bypass(bypass)")
        .expect("recovery invokes exact native bypass proof");
    let insertion = recovery
        .find("self.owned_bypasses.insert(key, bypasses)")
        .expect("recovery records only proven bypass ownership");
    assert!(
        parse < key && key < proof_loop && proof_loop < proof && proof < insertion,
        "recovery must normalize, key, prove every tuple, then insert ownership"
    );

    let removal_marker =
        "#[cfg(windows)]\nfn native_remove_bypass(route: &NativeBypassRoute) -> DomainResult<()> {";
    let removal_start = source
        .find(removal_marker)
        .expect("native bypass removal helper exists");
    let removal_end = source[removal_start + removal_marker.len()..]
        .find("\n#[cfg(windows)]\nfn native_bypass_key(")
        .expect("native bypass removal helper ends before key normalization");
    let removal = &source[removal_start..removal_start + removal_marker.len() + removal_end];
    assert!(
        removal.contains("native_exact_bypass_removal_script(route)"),
        "removal uses the exact bounded PowerShell removal script"
    );
    assert!(
        removal.contains("powershell.exe"),
        "removal executes the bounded PowerShell script"
    );
    assert!(!removal.contains("route.exe"));
    assert!(!removal.contains("DELETE"));
}

#[test]
fn native_windows_route_snapshot_requires_up_physical_adapter_proof() {
    let source = include_str!("../src/tunnel_runtime.rs").replace("\r\n", "\n");
    let snapshot_start = source
        .find("fn native_route_snapshot(")
        .expect("native endpoint route snapshot exists");
    let snapshot = &source[snapshot_start..];
    assert!(
        snapshot.contains("Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -Physical"),
        "selected underlay interface must be proven physical"
    );
    assert!(snapshot.contains("Status -eq 'Up'"));
    assert!(snapshot.contains("if ($null -eq $physical)"));
}

#[test]
fn native_windows_destination_routes_use_bounded_active_store_exact_tuple_proof() {
    let source = include_str!("../src/tunnel_runtime.rs").replace("\r\n", "\n");
    let destination_start = source
        .find("fn native_destination_route_snapshot(")
        .expect("native destination route snapshot exists");
    let destination_end = source[destination_start..]
        .find("\n#[cfg(not(windows))]")
        .expect("native destination route helpers are bounded");
    let destination = &source[destination_start..destination_start + destination_end];
    for fragment in [
        "Get-NetRoute -PolicyStore ActiveStore",
        "-DestinationPrefix",
        "-NextHop",
        "-InterfaceIndex",
        "-RouteMetric",
        "$matches.Count -ne 1",
        "Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -Physical",
        "Remove-NetRoute -InputObject $matches[0]",
    ] {
        assert!(
            destination.contains(fragment),
            "destination proof contains {fragment}"
        );
    }
    assert!(!destination.contains("route.exe DELETE"));
    assert!(!destination.contains("-DestinationPrefix '*"));
}

#[test]
fn native_windows_destination_normalization_uses_canonical_ipv4_policy() {
    let source = include_str!("../src/tunnel_runtime.rs").replace("\r\n", "\n");
    let normalization_marker =
        "#[cfg(windows)]\nfn native_normalize_destination_cidr(destination_cidr: &str)";
    let normalization_start = source
        .find(normalization_marker)
        .expect("native destination normalization exists");
    let normalization_end = source[normalization_start..]
        .find("\n#[cfg(windows)]\nfn native_destination_routes_from_snapshot(")
        .expect("native destination normalization ends before snapshot parsing");
    let normalization = &source[normalization_start..normalization_start + normalization_end];

    assert!(normalization.contains("canonical_destination_ipv4_cidr(destination_cidr)"));
    assert!(!normalization.contains("IpAddr::from_str(address)"));
}

#[test]
fn native_windows_bypass_commands_discard_child_standard_streams() {
    let source = include_str!("../src/tunnel_runtime.rs").replace("\r\n", "\n");
    let command_marker =
        "#[cfg(windows)]\nfn native_silent_route_command(program: &str) -> Command {";
    let command_start = source
        .find(command_marker)
        .expect("native silent route command helper exists");
    let command_end = source[command_start..]
        .find("\n#[cfg(windows)]\nfn native_add_bypass(")
        .expect("native silent route command helper ends before route addition");
    let command = &source[command_start..command_start + command_end];
    let stdin = command
        .find(".stdin(Stdio::null())")
        .expect("native route commands discard child stdin");
    let stdout = command
        .find(".stdout(Stdio::null())")
        .expect("native route commands discard child stdout");
    let stderr = command
        .find(".stderr(Stdio::null())")
        .expect("native route commands discard child stderr");
    assert!(
        stdin < stdout && stdout < stderr,
        "native route command helper configures every child standard stream"
    );

    for (name, marker, end_marker) in [
        (
            "add",
            "#[cfg(windows)]\nfn native_add_bypass(",
            "\n#[cfg(windows)]\nfn native_exact_bypass_proof_script(",
        ),
        (
            "proof",
            "#[cfg(windows)]\nfn native_prove_bypass(",
            "\n#[cfg(windows)]\nfn native_remove_bypass(",
        ),
        (
            "removal",
            "#[cfg(windows)]\nfn native_remove_bypass(",
            "\n#[cfg(windows)]\nfn native_bypass_key(",
        ),
    ] {
        let start = source.find(marker).expect("native bypass helper exists");
        let end = source[start..]
            .find(end_marker)
            .expect("native bypass helper has a bounded source slice");
        let helper = &source[start..start + end];
        let silent_command = helper
            .find("native_silent_route_command(")
            .expect("native bypass helper uses the silent route command helper");
        let status = helper
            .find(".status()")
            .expect("native bypass helper executes its configured command");
        assert!(
            silent_command < status,
            "native {name} bypass helper configures silent streams before status"
        );
    }
}
