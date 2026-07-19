use control_domain::DomainResult;
use platform_windows::tunnel_config::{
    read_tunnel_state, OwnedProcessHandle, WindowsRouteSnapshotEntry, WindowsTunnelLifecycleState,
};
use platform_windows::tunnel_runtime::{
    EasyTierCliRunner, EasyTierProcessRunner, WindowsRoutePort, WindowsTunnelSessionService,
    WindowsTunnelStartRequest, WINDOWS_TUNNEL_CONFIRMATION_REQUIRED_CODE,
    WINDOWS_TUNNEL_OWNERSHIP_MISMATCH_CODE, WINDOWS_TUNNEL_PEER_NOT_READY_CODE,
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
}

impl EasyTierProcessRunner for FakeProcessRunner {
    fn start(
        &mut self,
        _spec: &platform_windows::tunnel_config::EasyTierLaunchSpec,
    ) -> DomainResult<OwnedProcessHandle> {
        self.events.push("process.start");
        Ok(OwnedProcessHandle {
            session_id: "fixture-session".to_string(),
            process_id: 41001,
        })
    }

    fn stop(&mut self, _handle: &OwnedProcessHandle) -> DomainResult<()> {
        self.events.push("process.stop");
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
}

impl WindowsRoutePort for FakeRoutePort {
    fn snapshot(
        &mut self,
        endpoints: &[IpAddr],
    ) -> DomainResult<Vec<WindowsRouteSnapshotEntry>> {
        self.events.push(format!("route.snapshot:{}", endpoints.len()));
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

    fn add_endpoint_bypass(
        &mut self,
        endpoints: &[IpAddr],
    ) -> DomainResult<()> {
        self.events
            .push(format!("route.bypass:{}", endpoints.len()));
        Ok(())
    }

    fn restore(&mut self, _snapshot: &[WindowsRouteSnapshotEntry]) -> DomainResult<()> {
        self.events.push("route.restore");
        Ok(())
    }
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
        plan_digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .to_string(),
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

#[test]
fn start_orders_snapshot_bypass_process_and_readiness() {
    let events = SharedEvents::new();
    let (binary, cli, secret) = fixture_paths("start-order");
    let state_path = binary.parent().expect("fixture parent").join("state.json");
    let mut service = WindowsTunnelSessionService::new(
        FakeProcessRunner {
            events: events.clone(),
        },
        FakeCliRunner {
            events: events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        FakeRoutePort {
            events: events.clone(),
        },
    );

    let state = service
        .start(start_request(binary, cli, secret, state_path.clone()))
        .expect("fake EasyTier session starts");
    assert_eq!(state.state, WindowsTunnelLifecycleState::Running);
    assert_eq!(read_tunnel_state(&state_path).expect("state is persisted"), state);

    let events = events.snapshot();
    assert!(event_index(&events, "cli.version") < event_index(&events, "route.snapshot"));
    assert!(event_index(&events, "route.snapshot") < event_index(&events, "route.bypass"));
    assert!(event_index(&events, "route.bypass") < event_index(&events, "process.start"));
    assert!(event_index(&events, "process.start") < event_index(&events, "cli.peer_ready"));
    assert!(event_index(&events, "cli.peer_ready") < event_index(&events, "cli.route_cidrs"));
}

#[test]
fn readiness_failure_restores_routes_and_stops_owned_process() {
    let events = SharedEvents::new();
    let (binary, cli, secret) = fixture_paths("readiness-failure");
    let state_path = binary.parent().expect("fixture parent").join("state.json");
    let mut service = WindowsTunnelSessionService::new(
        FakeProcessRunner {
            events: events.clone(),
        },
        FakeCliRunner {
            events: events.clone(),
            peer_ready: false,
            routes: Vec::new(),
        },
        FakeRoutePort {
            events: events.clone(),
        },
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
fn stop_rejects_missing_confirmation() {
    let events = SharedEvents::new();
    let (_binary, _cli, _secret) = fixture_paths("stop-confirmation");
    let state_path = std::env::temp_dir().join(format!(
        "networkcore-windows-tunnel-stop-confirmation-{}.json",
        std::process::id()
    ));
    let mut service = WindowsTunnelSessionService::new(
        FakeProcessRunner {
            events: events.clone(),
        },
        FakeCliRunner {
            events: events.clone(),
            peer_ready: true,
            routes: Vec::new(),
        },
        FakeRoutePort {
            events: events.clone(),
        },
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
    let cli_path = cli.clone();
    let mut service = WindowsTunnelSessionService::new(
        FakeProcessRunner {
            events: events.clone(),
        },
        FakeCliRunner {
            events: events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        FakeRoutePort {
            events: events.clone(),
        },
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
        FakeProcessRunner {
            events: owner_events.clone(),
        },
        FakeCliRunner {
            events: owner_events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        FakeRoutePort {
            events: owner_events.clone(),
        },
    );
    owner
        .start(start_request(binary, cli, secret, state_path.clone()))
        .expect("owner starts session");

    let stale_events = SharedEvents::new();
    let mut stale = WindowsTunnelSessionService::new(
        FakeProcessRunner {
            events: stale_events.clone(),
        },
        FakeCliRunner {
            events: stale_events.clone(),
            peer_ready: true,
            routes: vec!["203.0.113.0/24".to_string()],
        },
        FakeRoutePort {
            events: stale_events.clone(),
        },
    );

    let error = stale
        .stop(&state_path, true)
        .expect_err("a service without the ownership token cannot stop the session");
    assert_eq!(error.code, WINDOWS_TUNNEL_OWNERSHIP_MISMATCH_CODE);
    assert!(stale_events.snapshot().is_empty());
}
