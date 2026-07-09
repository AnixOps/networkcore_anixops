# networkcore-linux

`networkcore-linux` is the Linux CLI entrypoint for NetworkCore.

The crate currently provides:

- Command parsing for the first Linux command surface.
- A config reader boundary that can be tested without local file-system verification.
- Response and diagnostic mapping for help, capabilities, prepare-config, start, stop, status, diagnostics, mitm status/diagnostics/certificate-plan/certificate apply/rollback/browser-plan/browser-capture/http-rewrite, install-sing-box, run-url, and version commands.
- A foreground lifecycle host source contract for `start` handoff, with default unavailable, current-process, injectable interruption source, Unix OS signal source, and interruption cleanup implementations.
- JSON response rendering for automation-facing output contracts.
- A minimal binary that wires `capabilities`, `status`, `diagnostics`, `mitm status/diagnostics/certificate-plan/browser-plan`, `mitm certificate apply/rollback`, `mitm http-rewrite plan/preview`, and `mitm browser-capture plan/launch-plan/session-plan/launch/apply/rollback/verify/traffic-proof` to `HostLinuxReadOnlyProbe`, wires `mitm certificate apply/rollback` to `CommandMitmCertificateArtifactStore`, wires `mitm browser-capture launch --confirm` to an injected `BrowserCaptureProcessRunner`, wires `mitm browser-capture verify --confirm` to an injected `BrowserCaptureEndpointProbe`, wires `mitm browser-capture traffic-proof --confirm` to an injected `BrowserCaptureTrafficProofProbe`, wires `prepare-config` to the pure `config-core` service, wires `start` to `engine-native::NativeProxyEngineService` through `RuntimeOrchestrator` with the built-in `networkcore.adblock` MITM plugin hook, wires `install-sing-box` to the `engine-singbox` latest release installer, and wires `run-url` to the `config-core` URL parser plus `sing-box` config renderer and foreground process runner.

Release/source split: the latest published Linux artifact is `v0.1.0-alpha.13`.
This README describes current `main` source. The `v0.1.0-alpha.13` artifact
includes `mitm certificate apply --confirm --cert-file <path> --key-file
<path> [--profile-trust-file <path>] --snapshot <path>` / `rollback --snapshot <path>` certificate artifact
lifecycle and dedicated profile CA trust artifact foundation, `mitm http-rewrite plan` / `mitm http-rewrite preview --confirm --url <url>`
caller-provided plain HTTP rewrite foundation, `http_rewrite` report, `mitm browser-capture verify --confirm`,
`mitm browser-capture verify --confirm --target-url <url>`,
`mitm browser-capture session-plan`, browser capture target route verify, the browser capture `--target-url`
option, `mitm browser-capture traffic-proof --confirm [--target-url <url>] [--proof-token <token>] [--proof-log <path>]`,
`session-plan`/`launch --confirm` proof URL binding through `proof_target_url`,
`networkcore_proof_token`, and `traffic_proof_command`, and
`mitm browser-capture apply --confirm --pac-file <path> [--policy-file <path>] [--profile-prefs-file <path>] --snapshot <path>`
/ `rollback --snapshot <path>` PAC/browser policy/profile prefs artifact apply/rollback, plus
`networkcore-linux start` built-in `networkcore.adblock` MITM hook injection for
native SOCKS5 CONNECT-level `Reject` blocking. Browser capture `session-plan`,
`launch`, `apply`, `verify`, and `traffic-proof` also accept
`--proxy-scheme http|socks5`; `socks5` emits
`socks5://127.0.0.1:7890` browser/PAC/probe plans so an explicitly launched
dedicated browser can target the native SOCKS5 CONNECT hook. The traffic-proof
command verifies that an operator-provided proof log contains a browser proof
token and emits `traffic_proof_report`; when proof token/log are omitted, it
uses the same default proof binding as session-plan/launch, derived from the
target CONNECT endpoint plus proxy URL so it can match native SOCKS5 CONNECT
diagnostics. Session-plan/launch proof binding appends
the token to the target URL passed to the dedicated browser and emits the
matching traffic-proof command; the artifact path writes only the
operator-provided NetworkCore PAC file, optional Chromium/Chrome managed proxy
policy artifact, optional Firefox dedicated profile prefs, and rollback
snapshot, reports `profile_prefs_file_path` and `profile_prefs_content`, and
never installs system PAC or browser policy; the native MITM hook only writes SOCKS5 CONNECT
failure for plugin `Reject`, emits
`engine.native.runtime.http_mitm_connect_browser_proof_observed` with the same
default proof token, and does not decrypt HTTPS. The HTTP rewrite preview applies
plugin outcomes only to caller-provided plain HTTP input and does not intercept
live browser/system traffic or execute TLS decryption. The dedicated profile trust artifact increment is not included in
older artifacts before `v0.1.0-alpha.13`; the plain HTTP rewrite foundation is not included before `v0.1.0-alpha.12`.
The per-alpha feature and boundary index is
`docs/alpha-release-feature-matrix.md`.

P4 current stage source of truth: this crate is now in P4 Client And Platform
Integration. P3 Runtime Capability Baseline is completed history, not the
current repository stage. The active P4 backlog buckets are subscription/client
compatibility, MITM data plane plus certificate lifecycle, and browser capture
user flow completion. Any P3 wording in completed changelog or roadmap entries
is historical context only and must not be used as the current CLI release or
iteration stage.

`install-sing-box` downloads the latest official `sing-box` release asset into an operator-visible cache and reports the cached executable path; it does not bundle `sing-box` into NetworkCore release artifacts. `run-url <ss://url>` parses a Shadowsocks URL through the subscription model, renders a local `mixed` inbound config for `sing-box`, writes it under the engine cache, and starts `sing-box run -c <config>` in the foreground. The default local proxy is `127.0.0.1:7890`.

`networkcore-linux mitm status`, `networkcore-linux mitm diagnostics`, `networkcore-linux mitm certificate-plan`, `networkcore-linux mitm certificate apply/rollback`, `networkcore-linux mitm browser-plan`, `networkcore-linux mitm http-rewrite plan/preview`, and `networkcore-linux mitm browser-capture plan/launch-plan/session-plan/launch/apply/rollback/verify/traffic-proof` implement the first partial `MITM_CLI_COMMAND_GATE` surface. They load the built-in `networkcore.adblock` policy through `mitm-policy`, emit `mitm_status` JSON fields, and report `mitm-cli-command-gate-status=partial-active`. `networkcore-linux start` also loads the built-in plugin into `engine-native`; matching plugin `Reject` outcomes are applied at the explicit SOCKS5 CONNECT layer as a SOCKS5 general failure response before outbound selection, and CONNECT hook diagnostics emit the default browser proof token when the target endpoint matches the same proxy URL. `certificate-plan` exposes `mitm_status.certificate_plan` with current certificate state, artifact lifecycle steps, dedicated profile trust artifact step, trust blocked operations, and `mutation_ready=false`; `mitm certificate apply --confirm --cert-file <path> --key-file <path> [--profile-trust-file <path>] --snapshot <path>` writes operator-provided NetworkCore certificate/private-key artifacts, an optional dedicated profile CA trust artifact, and a rollback snapshot through `CommandMitmCertificateArtifactStore`, records `certificate_lifecycle`, `LinuxMitmCertificateArtifactRequest`, `profile_trust_file_path`, `profile_trust_content`, `profile_trust_fingerprint`, `LinuxMitmCertificateApplyReport`, and `trust_plan`; `mitm certificate rollback --snapshot <path>` removes NetworkCore-managed certificate artifacts when the snapshot fingerprint still matches. The certificate lifecycle boundary is fixed by `docs/architecture/linux-mitm-certificate-lifecycle-source-contract.md` and keeps system trust-store, browser trust-store, and profile trust state mutation blocked. `http-rewrite plan` exposes `MITM_HTTP_TLS_DATA_PLANE_GATE=plain-http-live-data-plane-active/tls-decryption-blocked`; `http-rewrite preview --confirm --url <url>` builds a `NativePlainHttpMessage`, invokes the built-in plugin, and applies reject/redirect/header/body mutation outcomes to caller-provided plain HTTP input. The native `ListenerKind::Http` explicit proxy path also parses real `http://` HTTP/1.x request/response traffic through `NativeExplicitHttpProxyRequest` and applies reject, redirect, and header/body rewrite before or after SOCKS outbound forwarding. The HTTP rewrite boundary is fixed by `docs/architecture/linux-mitm-http-rewrite-source-contract.md` and keeps TLS decryption, HTTPS CONNECT termination, CA trust, browser/system proxy mutation, and script execution blocked. `browser-plan` exposes `mitm_status.browser_plan` with the planned explicit proxy `127.0.0.1:7890`, required steps, blocked operations, and `mutation_ready=false`. `browser-capture` emits a `browser_capture` report: `plan` is read-only, `launch-plan` returns manual dedicated-profile browser command templates bound to the loaded `networkcore.adblock` plugin and planned proxy URL without writing host state, `session-plan <ss://url>` returns a redacted subscription-to-local-proxy/browser/verify/traffic-proof command plan plus selected node and plugin metadata without starting processes, `session-plan` and `launch --confirm` both accept `--target-url <url>` so the dedicated browser profile can open a specific page through the planned proxy, current `main` appends `networkcore_proof_token` to that target as `proof_target_url` and emits a matching `traffic_proof_command`, `launch --confirm` starts a dedicated browser profile through `BrowserCaptureProcessRunner` with explicit `--proxy-server` and `--user-data-dir` arguments and records `launch_report`, pid, profile, proxy, target URL, proof target URL, proof token/log, command args, and plugin metadata, `verify --confirm` uses `BrowserCaptureEndpointProbe` to check whether the planned local proxy endpoint is reachable and records `verify_report`, proxy URL, probe type, and plugin metadata, `verify --confirm --target-url <url>` additionally sends an HTTP CONNECT probe for the target host:port through the planned proxy and records `target_url`, `probe=http-connect-target`, and `target_reachable`, `traffic-proof --confirm [--target-url <url>] [--proof-token <token>] [--proof-log <path>]` uses `BrowserCaptureTrafficProofProbe` to inspect an operator-provided proof log for the token, defaults omitted proof token/log to the CONNECT-endpoint session proof binding, and records `traffic_proof_report`, `proof-log-token`, proxy URL, target URL, proof target URL, proof token, proof log path, and plugin metadata, `apply --confirm --pac-file <path> [--policy-file <path>] [--profile-prefs-file <path>] --snapshot <path>` uses `BrowserCapturePacFileStore` to write an operator-provided NetworkCore PAC file plus optional Chromium/Chrome managed proxy policy artifact, optional Firefox dedicated profile prefs, and rollback snapshot, records `LinuxBrowserCapturePacRequest`, `pac_file_path`, `pac_url`, `policy_file_path`, `policy_url`, `profile_prefs_file_path`, `profile_prefs_content`, and `apply_report`, and `rollback --snapshot <path>` reads the NetworkCore snapshot and removes or restores those NetworkCore-created artifacts. The browser hijack path remains `deferred`; system CA trust mutation, browser/system proxy mutation, system PAC installation, full live browser capture automation, HTTPS decryption, and HTTPS request/response rewrite gates stay blocked.

The browser capture mutation path is governed by
`docs/architecture/linux-mitm-browser-capture-source-contract.md`. It requires
`BrowserCaptureProcessRunner`, `LinuxBrowserCaptureLaunchRequest`,
`LinuxBrowserCaptureLaunchReport`, `BrowserCaptureAuthorization`,
`BrowserCaptureEndpointProbe`, `LinuxBrowserCaptureSessionPlanRequest`,
`LinuxBrowserCaptureSessionPlanReport`, `BrowserCaptureTrafficProofProbe`,
`LinuxBrowserCaptureTrafficProofRequest`,
`LinuxBrowserCaptureTrafficProofReport`, `BrowserCapturePacFileStore`,
`LinuxBrowserCapturePacRequest`, `BrowserCaptureRollbackSnapshot`, explicit session-plan/launch/apply/rollback/verify/traffic-proof commands,
and rollback-safe snapshots before any browser/system proxy state can be written.
The current command surface can plan a redacted subscription-to-browser capture
session, launch a dedicated browser process, optionally open a `proof_target_url`
derived from `--target-url` plus `networkcore_proof_token` inside that dedicated
profile, emit a matching `traffic_proof_command`, and verify the planned local
proxy endpoint or target URL proxy route after `--confirm`; `traffic-proof`
can reuse the same default proof binding from `--target-url` when token/log are
omitted. That default token is CONNECT-endpoint based, so a captured
`networkcore-linux start` log can contain the same token through
`engine.native.runtime.http_mitm_connect_browser_proof_observed`. It can also
write/rollback caller-selected NetworkCore PAC and optional browser policy
artifacts with `--pac-file`, optional `--policy-file`, and `--snapshot`; it does not mutate system proxy,
install browser policy, system PAC, TUN, DNS, firewall, CA, or HTTP/TLS data-plane
state. The `start` path can block plugin-rejected explicit SOCKS5 CONNECT
tunnels, and `--proxy-scheme socks5` can route a dedicated browser plan to that
hook, but neither path writes browser/system proxy state or proves HTTPS MITM.

This crate does not modify TUN, DNS, routing, firewall, system trust stores, browser trust stores, profile trust state, service managers, or daemon state. Certificate commands only write operator-provided NetworkCore artifact paths and rollback snapshots. `start` is foreground-only, maps Unix `SIGINT`/`SIGTERM` and injected lifecycle interruption to `cli.linux.start.lifecycle_interrupted` with exit code 130, then stops the current in-process runtime and aggregates native release diagnostics such as `engine.native.runtime.accept_loop_stopped` and `engine.native.runtime.released`. `run-url` is also foreground-only and does not imply daemon, control socket, cross-process `stop`, background `status`, managed logs, packaging, or service installation support. All validation runs in GitHub Actions according to `docs/ci-cd-policy.md`.
