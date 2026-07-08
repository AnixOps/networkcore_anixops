# networkcore-linux

`networkcore-linux` is the Linux CLI entrypoint for NetworkCore.

The crate currently provides:

- Command parsing for the first Linux command surface.
- A config reader boundary that can be tested without local file-system verification.
- Response and diagnostic mapping for help, capabilities, prepare-config, start, stop, status, diagnostics, mitm status/diagnostics/certificate-plan/browser-plan/browser-capture, install-sing-box, run-url, and version commands.
- A foreground lifecycle host source contract for `start` handoff, with default unavailable, current-process, injectable interruption source, Unix OS signal source, and interruption cleanup implementations.
- JSON response rendering for automation-facing output contracts.
- A minimal binary that wires `capabilities`, `status`, `diagnostics`, `mitm status/diagnostics/certificate-plan/browser-plan`, and `mitm browser-capture plan/apply/rollback/verify` to `HostLinuxReadOnlyProbe`, wires `prepare-config` to the pure `config-core` service, wires `start` to `engine-native::NativeProxyEngineService` through `RuntimeOrchestrator`, wires `install-sing-box` to the `engine-singbox` latest release installer, and wires `run-url` to the `config-core` URL parser plus `sing-box` config renderer and foreground process runner.

`install-sing-box` downloads the latest official `sing-box` release asset into an operator-visible cache and reports the cached executable path; it does not bundle `sing-box` into NetworkCore release artifacts. `run-url <ss://url>` parses a Shadowsocks URL through the subscription model, renders a local `mixed` inbound config for `sing-box`, writes it under the engine cache, and starts `sing-box run -c <config>` in the foreground. The default local proxy is `127.0.0.1:7890`.

`networkcore-linux mitm status`, `networkcore-linux mitm diagnostics`, `networkcore-linux mitm certificate-plan`, `networkcore-linux mitm browser-plan`, and `networkcore-linux mitm browser-capture plan/apply/rollback/verify` implement the first partial `MITM_CLI_COMMAND_GATE` surface. They load the built-in `networkcore.adblock` policy through `mitm-policy`, emit `mitm_status` JSON fields, and report `mitm-cli-command-gate-status=partial-active`. `certificate-plan` exposes `mitm_status.certificate_plan` with current certificate state, plan steps, blocked operations, and `mutation_ready=false`; `browser-plan` exposes `mitm_status.browser_plan` with the planned explicit proxy `127.0.0.1:7890`, required steps, blocked operations, and `mutation_ready=false`. `browser-capture` emits a `browser_capture` report: `plan` is read-only, `apply --confirm` records authorization and remains blocked, `rollback --snapshot <path>` preserves the snapshot path and remains blocked, and `verify` reports live capture probing as blocked. The browser hijack path remains `deferred`; CA mutation, browser capture mutation, and HTTP/TLS data-plane gates stay blocked.

The browser capture mutation path is governed by
`docs/architecture/linux-mitm-browser-capture-source-contract.md`. It requires
`BrowserCaptureAuthorization`, `BrowserCaptureRollbackSnapshot`, explicit
apply/rollback/verify commands, and rollback-safe snapshots before any
browser/system proxy state can be written. The current command surface only
returns blocked reports and does not mutate host or browser state.

This crate does not modify TUN, DNS, routing, firewall, certificates, service managers, or daemon state. `start` is foreground-only, maps Unix `SIGINT`/`SIGTERM` and injected lifecycle interruption to `cli.linux.start.lifecycle_interrupted` with exit code 130, then stops the current in-process runtime and aggregates native release diagnostics such as `engine.native.runtime.accept_loop_stopped` and `engine.native.runtime.released`. `run-url` is also foreground-only and does not imply daemon, control socket, cross-process `stop`, background `status`, managed logs, packaging, or service installation support. All validation runs in GitHub Actions according to `docs/ci-cd-policy.md`.
