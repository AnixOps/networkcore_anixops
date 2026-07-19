# Windows EasyTier Foreground Tunnel Implementation Plan

> For agentic workers: use superpowers:executing-plans to implement this plan task-by-task with review checkpoints. Each behavior slice is CI-gated before the next slice begins.

**Goal:** Add a manually testable Windows foreground tunnel that verifies signed NetworkCore delivery, launches an explicitly installed EasyTier runtime, exposes one selected Linux POP route, and cleans up deterministically.

**Architecture:** config-core owns EasyTier transport admission and a pure WindowsTunnelPlan. platform-windows owns EasyTier TOML generation, executable pinning, process/CLI/route ports, session state, and rollback. apps/windows-cli exposes tunnel start/status/stop and never embeds EasyTier internals. The first package uses an operator-supplied EasyTier installation and does not redistribute drivers or binaries.

**Tech Stack:** Rust 2021 workspace, existing config-core Ed25519 verifier, serde/serde_json, TOML config generation, std::process::Command platform adapters, GitHub Actions Windows/Ubuntu/macOS CI, and manually recorded Windows 11 plus Linux POP acceptance.

## Global Constraints

- Local validation is limited to static inspection and Git operations; all Rust format, lint, test, build, audit, package, and release checks run in GitHub Actions.
- Every state-changing tunnel command requires explicit --confirm and an explicit state directory.
- The client never downloads EasyTier, delivery bundles, routes, or secrets.
- Network secrets never appear in process arguments, environment variables, diagnostics, JSON, logs, or GitHub Actions output.
- Only transport=easytier, one selected entry POP, IPv4 destination CIDR routes, and foreground sessions are active in this slice.
- Service auto-start, GUI, installer, bundled Wintun/EasyTier, full-tunnel kill switch, IPv6, DNS mutation, system proxy/trust-store mutation, and client-side multi-hop execution remain blocked.
- A behavior slice may have a test-only red checkpoint commit for TDD; its subsequent feat commit is the feature deliverable. Never start the next slice until that feature commit's exact SHA has a successful GitHub Actions run.
- The operator's existing EasyTier cluster is used only after the artifact is built and the manual acceptance record is ready; no cluster credentials are committed.

## CI Checkpoint Procedure

Run this from /root/code/.worktrees/networkcore-windows-tunnel after each feature commit; do not run cargo locally.

    git push origin feat/windows-easytier-tunnel
    HEAD_SHA="$(git rev-parse HEAD)"
    gh workflow run ci.yml --repo AnixOps/networkcore_anixops --ref feat/windows-easytier-tunnel
    RUN_ID="$(gh run list --repo AnixOps/networkcore_anixops --workflow CI --branch feat/windows-easytier-tunnel --limit 10 --json databaseId,headSha,status --jq "map(select(.headSha == \"${HEAD_SHA}\" and .status == \"in_progress\")) | .[0].databaseId")"
    test -n "${RUN_ID}"
    gh run watch "${RUN_ID}" --repo AnixOps/networkcore_anixops --exit-status --interval 15
    gh run view "${RUN_ID}" --repo AnixOps/networkcore_anixops --json headSha,status,conclusion,jobs

Expected feature result: headSha equals HEAD_SHA, status is completed, conclusion is success, Windows/Ubuntu/macOS Rust jobs are successful, and CI summary is successful. A test-only red checkpoint should fail only at the newly added assertion.

## Task 1: Admit EasyTier Delivery Transport

Files:

- Modify: crates/config-core/src/sdwan_delivery.rs
- Test: crates/config-core/tests/sdwan_delivery_contracts.rs
- Test: the unit-test module in crates/config-core/src/sdwan_delivery.rs

Interfaces:

- Add SDWAN_DELIVERY_TRANSPORT_EASYTIER: &str = "easytier".
- Keep legacy transport=ikev2 acceptance unchanged.
- validate_client_profile accepts exactly ikev2 or easytier; all other values return sdwan.delivery.parse_failed.

- [ ] Write the failing unit test named accepts_easytier_client_transport. Construct ClientDeliveryProfileWire with transport easytier, one valid POP reference, and a principal equal to the target. Assert that the returned profile transport is easytier.
- [ ] Commit only this test as test: define easytier delivery transport contract, push it, dispatch CI, and confirm the new assertion fails because the parser still requires ikev2.
- [ ] Add the transport constant and replace the single equality check with an exact two-value match. Do not normalize arbitrary values or add a fallback transport.
- [ ] Add an integration assertion for a newly signed synthetic EasyTier client fixture and a rejection assertion for transport=wireguard. Store only the public key and signed fixture; discard the private key.
- [ ] Commit the behavior as feat: accept easytier delivery transport and run the CI Checkpoint Procedure. Do not continue until the exact SHA is green.

## Task 2: Build the Pure Windows Tunnel Plan

Files:

- Create: crates/config-core/src/windows_tunnel.rs
- Modify: crates/config-core/src/lib.rs
- Test: crates/config-core/tests/windows_tunnel_contracts.rs
- Add: testdata/sdwan-delivery-contract/v1/easytier-client-envelope.json
- Add: testdata/sdwan-delivery-contract/v1/easytier-pop-envelope.json
- Modify: testdata/sdwan-delivery-contract/v1/manifest.json and README.md

Interfaces:

    pub struct WindowsTunnelPlanRequest<'a> {
        pub client: &'a VerifiedDeliveryEnvelope,
        pub pop: &'a VerifiedDeliveryEnvelope,
        pub device_id: &'a str,
        pub selected_pop_id: &'a str,
        pub last_client_sequence: Option<u64>,
        pub last_pop_sequence: Option<u64>,
        pub now: OffsetDateTime,
    }

    pub struct WindowsTunnelRouteIntent {
        pub route_id: String,
        pub destination_cidr: String,
        pub service_chain_id: String,
        pub direct_fallback: bool,
    }

    pub struct WindowsTunnelPlan {
        pub session_id: String,
        pub tenant_id: String,
        pub client_bundle_id: String,
        pub pop_bundle_id: String,
        pub client_sequence: u64,
        pub pop_sequence: u64,
        pub selected_pop_id: String,
        pub selected_endpoint: String,
        pub route_intents: Vec<WindowsTunnelRouteIntent>,
        pub endpoint_bypass_required: bool,
        pub plan_digest: String,
    }

    pub fn plan_windows_tunnel(request: WindowsTunnelPlanRequest<'_>) -> DomainResult<WindowsTunnelPlan>;

- [ ] Add tests named plans_one_selected_easytier_pop_and_destination_routes, rejects_client_target_mismatch, rejects_selected_pop_missing_from_client_delivery, rejects_independent_sequence_replay_for_client_or_pop, rejects_route_selector_that_cannot_be_applied_by_windows_system_routes, and plan_digest_is_stable_and_contains_no_secret.
- [ ] Generate a synthetic Ed25519 pair offline, sign EasyTier client and POP payloads, and check in only the public key, envelopes, hashes, and expected signing-input digests. Use target fixture-device-1, POP pop-a, transport easytier, and destination route 203.0.113.0/24. State in the fixture README that the private key is discarded.
- [ ] Commit tests and fixtures as test: define windows easytier tunnel planner, push, dispatch CI, and confirm the planner assertions fail because the module and function do not exist.
- [ ] Implement checks in this order: bundle kinds, expiry at now, independent sequence floors, tenant equality, client target equality, EasyTier transport, selected POP reference, POP target equality, supported route selector shape, and non-empty service-chain metadata. Accept only routes with a destination CIDR and no source CIDR, domain suffix, traffic class, protocol, or port selector. Preserve chain ID and direct_fallback as metadata; do not execute the chain on Windows.
- [ ] Create session_id and plan_digest from stable secret-free fields using SHA-256. Never include payload bytes or secret values in errors.
- [ ] Commit as feat: add windows tunnel delivery planner and run the CI Checkpoint Procedure. Do not continue until the exact SHA is green.

## Task 3: Render EasyTier Config and Persist Redacted Session State

Files:

- Modify: crates/platform-windows/Cargo.toml and Cargo.lock
- Create: crates/platform-windows/src/tunnel_config.rs
- Modify: crates/platform-windows/src/lib.rs
- Test: crates/platform-windows/tests/tunnel_config_contracts.rs

Interfaces:

    pub struct EasyTierConfigRequest<'a> {
        pub plan: &'a WindowsTunnelPlan,
        pub network_name: &'a str,
        pub network_secret: &'a str,
        pub virtual_ipv4: Option<&'a str>,
    }

    pub struct EasyTierConfigArtifact {
        pub toml: String,
        pub redacted_toml: String,
        pub proxy_cidrs: Vec<String>,
    }

    pub fn render_easytier_config(request: EasyTierConfigRequest<'_>) -> DomainResult<EasyTierConfigArtifact>;
    pub fn verify_file_sha256(path: &Path, expected_lower_hex: &str) -> DomainResult<()>;

    pub enum WindowsTunnelLifecycleState { Starting, Running, Stopping, Stopped, Failed }

    pub struct WindowsRouteSnapshotEntry {
        pub destination_cidr: String,
        pub gateway: Option<String>,
        pub interface_index: Option<u32>,
        pub metric: Option<u32>,
    }

    pub struct EasyTierLaunchSpec {
        pub binary_path: PathBuf,
        pub cli_path: PathBuf,
        pub config_path: PathBuf,
        pub expected_version: String,
        pub expected_sha256: String,
    }

    pub struct OwnedProcessHandle { pub session_id: String, pub process_id: u32 }

    pub struct WindowsTunnelState {
        pub schema_version: u32,
        pub session_id: String,
        pub plan_digest: String,
        pub selected_pop_id: String,
        pub selected_endpoint: String,
        pub state: WindowsTunnelLifecycleState,
        pub config_path: String,
        pub last_client_sequence: u64,
        pub last_pop_sequence: u64,
        pub route_snapshot: Vec<WindowsRouteSnapshotEntry>,
        pub rollback_status: String,
    }

- [ ] Add tests named renders_network_identity_peer_and_proxy_cidr_without_secret_in_redacted_output, rejects_invalid_binary_hash, writes_stable_state_json, and refuses_unknown_state_schema. Assert EasyTier network_identity, peer, proxy_network, and optional ipv4 fields; assert redacted_toml never contains the secret.
- [ ] Commit tests as test: define easytier config and state contracts, push, dispatch CI, and confirm the new tests fail because the module and functions do not exist.
- [ ] Add direct dependencies on existing locked packages config-core, control-domain, ring, serde, serde_json, time, and toml. Update only the platform-windows dependency list in Cargo.lock; do not introduce a new third-party package.
- [ ] Render a minimal EasyTier TOML containing the selected peer, network identity, optional virtual IPv4, and destination proxy CIDRs. The runtime passes the generated file with --config-file and --disable-env-parsing. The secret never appears in an argument, environment variable, diagnostic, or display string.
- [ ] Implement lower-case SHA-256 verification with ring, reject non-64-hex expected values and mismatches, serialize state with serde_json, retain only redacted paths and metadata, and delete config after successful stop.
- [ ] Commit as feat: add easytier config and tunnel state and run the CI Checkpoint Procedure. Do not continue until the exact SHA is green.

## Task 4: Add Process, CLI, and Route-Safety Session Ports

Files:

- Create: crates/platform-windows/src/tunnel_runtime.rs
- Modify: crates/platform-windows/src/lib.rs
- Test: crates/platform-windows/tests/tunnel_runtime_contracts.rs

Interfaces:

    pub trait EasyTierProcessRunner {
        fn start(&mut self, spec: &EasyTierLaunchSpec) -> DomainResult<OwnedProcessHandle>;
        fn stop(&mut self, handle: &OwnedProcessHandle) -> DomainResult<()>;
    }

    pub trait EasyTierCliRunner {
        fn version(&mut self, path: &Path) -> DomainResult<String>;
        fn peer_ready(&mut self, path: &Path) -> DomainResult<bool>;
        fn route_cidrs(&mut self, path: &Path) -> DomainResult<Vec<String>>;
    }

    pub trait WindowsRoutePort {
        fn snapshot(&mut self, endpoints: &[IpAddr]) -> DomainResult<Vec<WindowsRouteSnapshotEntry>>;
        fn add_endpoint_bypass(&mut self, endpoints: &[IpAddr]) -> DomainResult<()>;
        fn restore(&mut self, snapshot: &[WindowsRouteSnapshotEntry]) -> DomainResult<()>;
    }

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

    pub struct WindowsTunnelSessionService<P, C, R>;
    impl<P, C, R> WindowsTunnelSessionService<P, C, R> {
        pub fn start(&mut self, request: WindowsTunnelStartRequest) -> DomainResult<WindowsTunnelState>;
        pub fn status(&mut self, state_path: &Path) -> DomainResult<WindowsTunnelState>;
        pub fn stop(&mut self, state_path: &Path, confirm: bool) -> DomainResult<WindowsTunnelState>;
    }

- [ ] Add fake-port tests named start_orders_snapshot_bypass_process_and_readiness, readiness_failure_restores_routes_and_stops_owned_process, stop_rejects_missing_confirmation, status_queries_explicit_easytier_cli, and stale_state_cannot_stop_another_session. Assert starting->running, starting->failed, and running->stopping->stopped transitions and route restoration on every failed readiness path.
- [ ] Commit tests as test: define windows tunnel lifecycle contracts, push, dispatch CI, and confirm the new tests fail because the service and ports do not exist.
- [ ] Implement ownership tokens, preflight of paths/hashes/secret/admin/plan/confirmation, route snapshot, endpoint bypass, config write, EasyTier process start, peer/route readiness, state persistence, and deterministic rollback. Report windows.tunnel.rollback_failed if either cleanup call fails. Never scan or kill arbitrary processes.
- [ ] Add cfg(windows) production ports using std::process::Command and explicit EasyTier paths plus route.exe/PowerShell route commands. Add non-Windows ports returning windows.tunnel.start_failed with a platform-unsupported diagnostic so other CI targets compile without host mutation.
- [ ] Commit as feat: add windows tunnel lifecycle adapter and run the CI Checkpoint Procedure. Do not continue until the exact SHA is green.

## Task 5: Expose tunnel start/status/stop in the Windows CLI

Files:

- Modify: apps/windows-cli/Cargo.toml, apps/windows-cli/src/lib.rs, apps/windows-cli/src/main.rs
- Modify: apps/windows-cli/tests/windows_cli_contracts.rs
- Modify: crates/platform-windows/src/lib.rs and platform capability tests

Interfaces:

    pub enum WindowsCliCommand {
        Help { format: OutputFormat },
        Version { format: OutputFormat },
        Capabilities { format: OutputFormat },
        Status { format: OutputFormat },
        Diagnostics { format: OutputFormat },
        TunnelStart(WindowsTunnelStartArgs),
        TunnelStatus(WindowsTunnelStatusArgs),
        TunnelStop(WindowsTunnelStopArgs),
    }

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
        pub network_name: String,
        pub network_secret_file: PathBuf,
        pub state_path: PathBuf,
        pub confirm: bool,
    }

    pub struct WindowsTunnelStatusArgs { pub state_path: PathBuf }
    pub struct WindowsTunnelStopArgs { pub state_path: PathBuf, pub confirm: bool }

- [ ] Add tests named parses_tunnel_start_with_all_explicit_paths, rejects_tunnel_start_without_confirm, rejects_tunnel_start_without_secret_file, renders_redacted_tunnel_status_json, and tunnel_stop_requires_confirm. Use fake session ports and assert delegation without launching a process.
- [ ] Commit tests as test: define windows tunnel cli commands, push, dispatch CI, and confirm parser/response tests fail because the variants do not exist.
- [ ] Extend the argument scanner with the exact spec options, keep --format text|json order-independent, and wire main.rs to production Windows ports or the non-Windows unsupported adapter. Render session, POP, digest, readiness, state, rollback, and redacted diagnostics; never render command lines, secrets, payloads, or private config.
- [ ] Add foreground_tunnel as active only for the explicitly confirmed external-EasyTier path. Keep windows-service, windows-driver, and windows-installer blocked until manual acceptance and a later packaging slice. Update help text to require a preinstalled EasyTier and elevated execution.
- [ ] Commit as feat: expose windows easytier tunnel cli and run the CI Checkpoint Procedure. Do not continue until the exact SHA is green.

## Task 6: Document External EasyTier Manual E2E and Package Boundary

Files:

- Create: docs/architecture/windows-easytier-tunnel-source-contract.md
- Modify: docs/alpha-windows-smoke-test.md, docs/manual-intervention.md, docs/release-strategy.md
- Modify: README.md, ROADMAP.md, TODO.md, CHANGELOG.md
- Modify: .github/workflows/ci.yml and .github/workflows/release.yml

- [ ] Add governance tests for the source contract, command names, blocked service/installer/redistribution markers, external EasyTier path, and manual acceptance marker names. Add release assertions that the archive contains NetworkCore plus runtime instructions, not EasyTier or Wintun.
- [ ] Commit assertions as test: define windows easytier release governance, push, dispatch CI, and confirm the new anchors fail because the contract and markers do not exist.
- [ ] Add the source contract and manual marker block with non-secret fields: easytier version, binary SHA-256, pending status, one-client/one-POP/one-IPv4-CIDR scope, peer-route-ping-curl-stop-rollback requirements, external-runtime requirement, and explicit-confirm-only mutation.
- [ ] Add EASYTIER-RUNTIME.md to Windows release staging with pinned-runtime, config-file, administrator, checksum, uninstall, and rollback instructions. Do not add EasyTier, Wintun, or a driver. Keep foreground external runtime active and service/driver/installer blocked.
- [ ] Commit as docs: define windows easytier manual e2e boundary and run CI. Dispatch release on this exact feature SHA with version v0.1.2-alpha.5; verify Windows package, manifest, checksum, and attestation jobs pass while publish remains skipped for workflow_dispatch.

## Task 7: Manual Cluster Acceptance

Files:

- Modify: docs/manual-intervention.md only after non-secret results exist

- [ ] On the Windows host, install the pinned EasyTier release, record binary and CLI SHA-256 values, create a local secret file with restrictive ACLs, and obtain signed client/POP envelopes. Keep secrets outside Git and CI.
- [ ] Record the pre-start Windows route table, selected EasyTier process entries, and Linux POP test-CIDR reachability.
- [ ] Run the released CLI as administrator with the spec tunnel start command. Capture redacted JSON, easytier-cli peer, and easytier-cli route output; confirm the selected POP and destination CIDR.
- [ ] Run ping to the EasyTier virtual address, ping and curl to a host in the POP CIDR, and a negative test to an unadvertised CIDR. Record route and POP identity for each result.
- [ ] Run tunnel status, then tunnel stop --confirm. Capture post-stop route/process state and require it to match pre-start. Set windows_tunnel_manual_test_status=confirmed only when peer, route, traffic, negative route, stop, and rollback evidence pass.
- [ ] Commit the redacted evidence as docs: record windows easytier tunnel smoke, push, and run the CI Checkpoint Procedure again.

## Completion Criteria

1. Tasks 1-6 feature commits each have a successful exact-SHA GitHub Actions run.
2. The Windows release artifact contains the CLI and external EasyTier instructions, with no driver or EasyTier binary.
3. Task 7 records successful Windows-to-Linux-POP ping and curl traffic, negative routing, stop, and rollback evidence.
4. windows-service, windows-driver, and windows-installer remain blocked; only foreground external-EasyTier tunneling is active.
5. All worktrees are clean and the final feature branch points at the last CI-verified commit.
