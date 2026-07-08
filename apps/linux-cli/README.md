# networkcore-linux

`networkcore-linux` is the Linux CLI entrypoint for NetworkCore.

The crate currently provides:

- Command parsing for the first Linux command surface.
- A config reader boundary that can be tested without local file-system verification.
- Response and diagnostic mapping for help, capabilities, prepare-config, start, stop, status, diagnostics, mitm status/diagnostics/certificate-plan/browser-plan/browser-capture, install-sing-box, run-url, and version commands.
- A foreground lifecycle host source contract for `start` handoff, with default unavailable, current-process, injectable interruption source, Unix OS signal source, and interruption cleanup implementations.
- JSON response rendering for automation-facing output contracts.
- A minimal binary that wires `capabilities`, `status`, `diagnostics`, `mitm status/diagnostics/certificate-plan/browser-plan`, and `mitm browser-capture plan/launch-plan/session-plan/launch/apply/rollback/verify/traffic-proof` to `HostLinuxReadOnlyProbe`, wires `mitm browser-capture launch --confirm` to an injected `BrowserCaptureProcessRunner`, wires `mitm browser-capture verify --confirm` to an injected `BrowserCaptureEndpointProbe`, wires `mitm browser-capture traffic-proof --confirm` to an injected `BrowserCaptureTrafficProofProbe`, wires `prepare-config` to the pure `config-core` service, wires `start` to `engine-native::NativeProxyEngineService` through `RuntimeOrchestrator`, wires `install-sing-box` to the `engine-singbox` latest release installer, and wires `run-url` to the `config-core` URL parser plus `sing-box` config renderer and foreground process runner.

Release/source split: the latest published Linux artifact is `v0.1.0-alpha.8`.
This README describes current `main` source. The `v0.1.0-alpha.8` artifact
includes `mitm browser-capture verify --confirm`,
`mitm browser-capture verify --confirm --target-url <url>`,
`mitm browser-capture session-plan`, browser capture target route verify, and the browser capture `--target-url`
option. Source-only increments after this tag require a later tag release before
they are present in a downloadable GitHub Release asset.
Current `main` adds `mitm browser-capture traffic-proof --confirm --proof-token <token> --proof-log <path>`.
That source-only command verifies that an operator-provided proof log contains a
browser proof token and emits `traffic_proof_report`; it is not included in
`v0.1.0-alpha.8` and needs a later tag release before users can download it.

P4 current stage source of truth: this crate is now in P4 Client And Platform
Integration. P3 Runtime Capability Baseline is completed history, not the
current repository stage. The active P4 backlog buckets are subscription/client
compatibility, MITM data plane plus certificate lifecycle, and browser capture
user flow completion. Any P3 wording in completed changelog or roadmap entries
is historical context only and must not be used as the current CLI release or
iteration stage.

`install-sing-box` downloads the latest official `sing-box` release asset into an operator-visible cache and reports the cached executable path; it does not bundle `sing-box` into NetworkCore release artifacts. `run-url <ss://url>` parses a Shadowsocks URL through the subscription model, renders a local `mixed` inbound config for `sing-box`, writes it under the engine cache, and starts `sing-box run -c <config>` in the foreground. The default local proxy is `127.0.0.1:7890`.

`networkcore-linux mitm status`, `networkcore-linux mitm diagnostics`, `networkcore-linux mitm certificate-plan`, `networkcore-linux mitm browser-plan`, and `networkcore-linux mitm browser-capture plan/launch-plan/session-plan/launch/apply/rollback/verify/traffic-proof` implement the first partial `MITM_CLI_COMMAND_GATE` surface. They load the built-in `networkcore.adblock` policy through `mitm-policy`, emit `mitm_status` JSON fields, and report `mitm-cli-command-gate-status=partial-active`. `certificate-plan` exposes `mitm_status.certificate_plan` with current certificate state, plan steps, blocked operations, and `mutation_ready=false`; `browser-plan` exposes `mitm_status.browser_plan` with the planned explicit proxy `127.0.0.1:7890`, required steps, blocked operations, and `mutation_ready=false`. `browser-capture` emits a `browser_capture` report: `plan` is read-only, `launch-plan` returns manual dedicated-profile browser command templates bound to the loaded `networkcore.adblock` plugin and planned proxy URL without writing host state, `session-plan <ss://url>` returns a redacted subscription-to-local-proxy/browser/verify command plan plus selected node and plugin metadata without starting processes, `session-plan` and `launch --confirm` both accept `--target-url <url>` so the dedicated browser profile can open a specific page through the planned proxy, `launch --confirm` starts a dedicated browser profile through `BrowserCaptureProcessRunner` with explicit `--proxy-server` and `--user-data-dir` arguments and records `launch_report`, pid, profile, proxy, target URL, command args, and plugin metadata, `verify --confirm` uses `BrowserCaptureEndpointProbe` to check whether the planned local proxy endpoint is reachable and records `verify_report`, proxy URL, probe type, and plugin metadata, `verify --confirm --target-url <url>` additionally sends an HTTP CONNECT probe for the target host:port through the planned proxy and records `target_url`, `probe=http-connect-target`, and `target_reachable`, `traffic-proof --confirm --proof-token <token> --proof-log <path>` uses `BrowserCaptureTrafficProofProbe` to inspect an operator-provided proof log for the token and records `traffic_proof_report`, `proof-log-token`, proxy URL, proof token, proof log path, and plugin metadata, `apply --confirm` records authorization and remains blocked, and `rollback --snapshot <path>` preserves the snapshot path and remains blocked. The browser hijack path remains `deferred`; CA mutation, browser/system proxy mutation, full live browser capture automation, and HTTP/TLS data-plane gates stay blocked.

The browser capture mutation path is governed by
`docs/architecture/linux-mitm-browser-capture-source-contract.md`. It requires
`BrowserCaptureProcessRunner`, `LinuxBrowserCaptureLaunchRequest`,
`LinuxBrowserCaptureLaunchReport`, `BrowserCaptureAuthorization`,
`BrowserCaptureEndpointProbe`, `LinuxBrowserCaptureSessionPlanRequest`,
`LinuxBrowserCaptureSessionPlanReport`, `BrowserCaptureTrafficProofProbe`,
`LinuxBrowserCaptureTrafficProofRequest`,
`LinuxBrowserCaptureTrafficProofReport`, `BrowserCaptureRollbackSnapshot`, explicit session-plan/launch/apply/rollback/verify/traffic-proof commands,
and rollback-safe snapshots before any browser/system proxy state can be written.
The current command surface can plan a redacted subscription-to-browser capture
session, launch a dedicated browser process, optionally open a `--target-url`
inside that dedicated profile, and verify the planned local proxy endpoint or
target URL proxy route after
`--confirm`, but it does not mutate
system proxy, browser policy, PAC, TUN, DNS, firewall, CA, or HTTP/TLS
data-plane state.

This crate does not modify TUN, DNS, routing, firewall, certificates, service managers, or daemon state. `start` is foreground-only, maps Unix `SIGINT`/`SIGTERM` and injected lifecycle interruption to `cli.linux.start.lifecycle_interrupted` with exit code 130, then stops the current in-process runtime and aggregates native release diagnostics such as `engine.native.runtime.accept_loop_stopped` and `engine.native.runtime.released`. `run-url` is also foreground-only and does not imply daemon, control socket, cross-process `stop`, background `status`, managed logs, packaging, or service installation support. All validation runs in GitHub Actions according to `docs/ci-cd-policy.md`.
