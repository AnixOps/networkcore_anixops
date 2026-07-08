# MITM Policy Ad Block Plugin Source Contract

## Purpose

This contract fixes the first NetworkCore-owned MITM policy plugin over the
pinned `mitm_anixops` C ABI.

The built-in ad-block plugin is intentionally a policy package, not a complete
traffic mutation feature. It proves that NetworkCore can load an AnixOps/Loon
style rule set through `mitm_anixops` and surface stable audit/diagnostics
through `MitmPluginService`; current `main` also exposes structured
`HttpMitmOutcome` plans for future HTTP/TLS data-plane consumption and applies
plugin `Reject` outcomes at the native explicit SOCKS5 CONNECT boundary.

## Current Source Boundary

This contract is governed by
[Third-Party Plugin Onboarding Process](third-party-plugin-onboarding-process.md)
and satisfies `THIRD_PARTY_PLUGIN_SOURCE_CONTRACT` for the first built-in
NetworkCore MITM policy plugin.

Required source anchors:

- `crates/mitm-policy`
- `builtin_ad_block_plugin_package`
- `MITM_POLICY_AD_BLOCK_PLUGIN_ID`
- `BUILTIN_AD_BLOCK_PLUGIN_SOURCE`
- `AnixOpsMitmPolicyEngine`
- `AnixOpsMitmPluginService`
- `MitmPolicyRewritePlan`
- `MitmPolicyBodyRewriteChain`
- `MitmPolicyHeaderField`
- `MitmPolicyScriptKind`
- `HttpMitmEvent`
- `HttpMitmOutcome`
- `HttpMitmAction`
- `HttpHeaderMutation`
- `HttpBodyMutation`
- `HttpMitmScriptDispatch`
- `MitmPluginService::handle_http_mitm_event`
- `NativeHttpMitmPluginHook`
- `plan_socks5_connect_http_mitm`
- `native_proxy_engine_service_with_builtin_mitm_plugin`
- `MITM_POLICY_HTTP_EVENT_MUTATION_PLANNED_CODE`
- `MITM_POLICY_HTTP_EVENT_MUTATION_DEFERRED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_REJECT_APPLIED_CODE`
- `MITM_CLI_COMMAND_GATE`
- `MITM_CERTIFICATE_LIFECYCLE_GATE`
- `MITM_HTTP_TLS_DATA_PLANE_GATE`
- `MITM_BROWSER_CAPTURE_GATE`

The package id is fixed as:

```text
networkcore.adblock
```

The plugin source must load through `anixops_engine_load_config` from the
vendored `mitm_anixops` `v0.45.10-alpha` submodule pinned at commit
`a3ee0fca6376ddccc333bdfe06ac5b5e75ed23e0`.

The safe wrapper may expose 0.45.10 policy results as NetworkCore-owned Rust
types, including aggregated rewrite plan, named header rewrite, bounded
header-list application, body rewrite chain, script dispatch, and JQ max-input
guard state. These are policy/runtime plans, not proof that live traffic
mutation is already wired.

Current user-facing source status: MITM is partially policy-driven but not full
live HTTP/TLS MITM. There is no live URL redirect/header/body/script mutation
path in the current Linux CLI source. The Linux CLI
now exposes `networkcore-linux mitm status`,
`networkcore-linux mitm diagnostics`, and
`networkcore-linux mitm certificate-plan`, and
`networkcore-linux mitm browser-plan`, plus
`networkcore-linux mitm browser-capture plan/launch-plan/session-plan/launch/apply/rollback/verify/traffic-proof` as a
status/diagnostics/certificate-plan/browser-plan/browser-capture command
surface. It reports:

```text
mitm-cli-command-gate-status=partial-active
```

`certificate-plan` adds `mitm_status.certificate_plan` with current certificate
state, plan steps, blocked operations, and `mutation_ready=false`.
`browser-plan` adds `mitm_status.browser_plan` with current capture state, the
planned explicit proxy `127.0.0.1:7890`, plan steps, blocked operations, and
`mutation_ready=false`. `browser-capture` adds a top-level `browser_capture`
machine report with source contract status, action, `LinuxBrowserCaptureManualLaunch`,
`LinuxBrowserCaptureSessionPlanReport`, optional target URL, `LinuxBrowserCaptureLaunchReport`, `LinuxBrowserCaptureVerifyReport`,
`LinuxBrowserCaptureTrafficProofReport`, `LinuxBrowserCapturePacRequest`,
authorization, snapshot, `proxy_scheme`, apply/rollback/verify/traffic-proof reports, PAC
artifact fields, and blocked operations.
`launch-plan` only returns manual dedicated-profile browser command templates,
the planned proxy URL, and loaded `networkcore.adblock` plugin metadata. There
is also a redacted `session-plan <ss://url>` path that returns selected node,
local proxy, browser command, optional `--target-url`, verify command, and
loaded plugin metadata without starting processes. There is also an explicit
`launch --confirm` process-launch path that starts a
dedicated browser profile through `BrowserCaptureProcessRunner` and reports pid,
profile, `proxy_scheme`, proxy, optional target URL, command args, and plugin metadata. `--proxy-scheme socks5` binds session-plan, launch, PAC/browser policy artifact, verify, and traffic-proof to `socks5://127.0.0.1:7890` so a dedicated browser can explicitly target the native SOCKS5 CONNECT hook. `verify --confirm` probes the
planned local proxy endpoint through `BrowserCaptureEndpointProbe`; `verify --confirm --target-url <url>`
uses `probe=http-connect-target` to test whether the planned proxy can open a
CONNECT tunnel to the target host:port and reports `target_reachable` plus
plugin metadata, but does not prove live browser
traffic capture or HTTPS MITM. `traffic-proof --confirm [--target-url <url>] [--proof-token <token>] [--proof-log <path>]`
uses `BrowserCaptureTrafficProofProbe` with `probe=proof-log-token` to inspect
an operator-provided proof log for the token, can reuse the default proof binding
when token/log are omitted, and reports `traffic_proof_report`;
that evidence source still does not prove HTTPS MITM decryption or rewrite
application. `apply --confirm --pac-file <path> [--policy-file <path>] --snapshot <path>` uses
`BrowserCapturePacFileStore` to write only a caller-selected NetworkCore PAC
artifact, optional Chromium/Chrome managed proxy policy artifact, and rollback snapshot; it does not install system PAC or browser
policy. There is still no CA generation/install/trust mutation workflow, no
HTTPS decryption path, and no browser/system proxy mutation path.

Current `main` source also has a policy-plan mutation model:
`control-domain` defines `HttpMitmEvent`, `HttpMitmOutcome`, `HttpMitmAction`,
`HttpHeaderMutation`, `HttpBodyMutation`, and `HttpMitmScriptDispatch`.
`MitmPluginService::handle_http_mitm_event` defaults to the legacy
`handle_http_event` path for older adapters, while `AnixOpsMitmPluginService`
overrides it by reloading the retained `PluginInstance.loaded_source` through
`mitm_anixops` and mapping 0.45.10 URL reject/redirect, header mutation, body
mutation, and script dispatch into a stable domain outcome. `engine-native`
adds `NativeHttpMitmPluginHook` and `plan_socks5_connect_http_mitm`, and
`networkcore-linux start` creates a native engine through
`native_proxy_engine_service_with_builtin_mitm_plugin`. When the plugin outcome
is `HttpMitmAction::Reject`, the native SOCKS5 accept loop applies that
CONNECT-level decision by writing a SOCKS5 general failure response and skipping
outbound selection. Redirect/header/body/script plans are still not applied to
live HTTP requests or responses until `MITM_HTTP_TLS_DATA_PLANE_GATE` is
implemented.

## Multi-Client Boundary

Platform clients must not maintain their own ad-block parser. Linux, macOS,
Windows, iOS, and future UI clients must call the same NetworkCore domain
boundary:

- client imports or enables a plugin package;
- NetworkCore validates `PluginManifest` and permissions;
- `mitm-policy` loads `PluginPackage.source` through `mitm_anixops`;
- `MitmPluginService` returns legacy audit/diagnostics and, on rich
  `HttpMitmEvent` input, a structured `HttpMitmOutcome` mutation plan;
- a later HTTP/TLS data plane applies structured mutations after the data-plane
  gate exists.

This keeps client behavior consistent and keeps platform UI code out of parser
ownership.

## Subscription Boundary

Proxy subscription formats remain separate from MITM plugin formats. `ss://`,
VLESS, VMess, Trojan, Clash YAML, sing-box JSON, Surge, Loon, and Quantumult X
proxy subscriptions must enter through `SubscriptionService` and normalize to
`NodeCatalog`.

MITM plugin packages enter through `PluginPackage.source`. Loon/Surge/QX plugin
compatibility can reuse `mitm_anixops`, but it must not bypass NetworkCore
manifest, permission, audit, and platform capability gates.

## Current Limitations

The current plugin service does not mutate live request or response data. The
native engine can apply only CONNECT-level `Reject` decisions before TLS or HTTP
request parsing.

Blocked until later phases:

- `MITM_CLI_COMMAND_GATE`: currently partial-active for user-facing
  `networkcore-linux mitm status`, `networkcore-linux mitm diagnostics`, and
  `networkcore-linux mitm certificate-plan`, `networkcore-linux mitm browser-plan`,
  and `networkcore-linux mitm browser-capture plan/launch-plan/session-plan/launch/apply/rollback/verify/traffic-proof`; later
  increments must turn blocked reports into actionable controls without claiming
  live MITM before the remaining gates are active.
- `MITM_CERTIFICATE_LIFECYCLE_GATE`: currently plan-only through
  `mitm_status.certificate_plan`; later increments must add CA generation,
  user-approved install, trust detection, fingerprint/expiration/revocation
  checks, uninstall, and rollback boundaries.
- `MITM_BROWSER_CAPTURE_GATE`: currently pac-policy-profile-prefs-active/system-mutation-blocked through
  `mitm_status.browser_plan`, manual launch-plan output, redacted session-plan
  output, optional target URL, `--proxy-scheme socks5` native plugin proxy mode, explicit dedicated-profile launch output, explicit local proxy endpoint verify output, target route verify output, proof-log-token traffic proof output, and
  NetworkCore PAC/browser policy/profile prefs artifact apply/rollback plus `--profile-prefs-file`, `profile_prefs_file_path`, `profile_prefs_content`, and mutation-blocked `browser_capture` reports;
  later increments must add explicit browser/system proxy configuration, system PAC or
  other capture strategy, live capture verification, and rollback boundaries.
  The Linux source contract is
  [Linux MITM Browser Capture Source Contract](linux-mitm-browser-capture-source-contract.md),
  which fixes `LinuxBrowserCaptureManualLaunch`, `LinuxBrowserCaptureSessionPlanRequest`,
  `LinuxBrowserCaptureSessionPlanReport`, `LinuxBrowserCaptureLaunchRequest`,
  `LinuxBrowserCaptureLaunchReport`, `LinuxBrowserCaptureVerifyRequest`,
  `LinuxBrowserCaptureVerifyReport`, `BrowserCaptureProcessRunner`,
  `LinuxBrowserCaptureTrafficProofRequest`, `LinuxBrowserCaptureTrafficProofReport`,
  `BrowserCaptureEndpointProbe`, `BrowserCaptureTrafficProofProbe`, `BrowserCapturePacFileStore`,
  `LinuxBrowserCapturePacRequest`, `BrowserCaptureAuthorization`,
  `BrowserCaptureRollbackSnapshot`, `proxy_scheme`, launch-plan, session-plan, optional `--target-url`, optional `--proxy-scheme socks5`, launch, apply/rollback/verify/traffic-proof,
  explicit authorization, snapshot, and rollback
  boundaries before any browser/system proxy mutation.
- `MITM_HTTP_TLS_DATA_PLANE_GATE`: HTTP CONNECT/TLS interception, SNI/host
  routing, HTTP/1.1 and HTTP/2 parsing, body buffering/limits, compression
  handling, and application of `mitm-policy` URL redirect/header/body/script
  rewrite plans to live HTTP request/response traffic.
- Full HTTP request and response data-plane context with parsed host/scheme,
  decompression, streaming/backpressure, and response framing.
- HTTP/TLS MITM data plane in `engine-native` or another execution adapter.
- Platform certificate install/trust workflow.
- JavaScript runtime and persistent storage.

The current policy-plan diagnostics are:

```text
mitm.policy.http_event.mutation_planned
mitm.policy.http_event.mutation_deferred
```

## GitHub Actions Verification

CI must prove:

- workspace contains `crates/mitm-policy`;
- `mitm_anixops` submodule is pinned to `v0.45.10-alpha` commit
  `a3ee0fca6376ddccc333bdfe06ac5b5e75ed23e0`;
- `mitm-policy` exposes the built-in ad-block package and adapter service;
- `mitm-policy` exposes 0.45.10 rewrite plan, header, body chain, script, and
  JQ max-input wrapper contracts;
- `control-domain` exposes `HttpMitmEvent`, `HttpMitmOutcome`,
  `HttpMitmAction`, `HttpHeaderMutation`, `HttpBodyMutation`,
  `HttpMitmScriptDispatch`, and `MitmPluginService::handle_http_mitm_event`;
- `mitm-policy` contract tests cover `networkcore.adblock` rich reject outcome,
  0.45.10 header/body/script outcome mapping, and missing loaded source
  deferral;
- Linux CLI exposes `mitm_status` JSON, `mitm_status.certificate_plan`,
  `mitm_status.browser_plan`, and `browser_capture` for
  `networkcore-linux mitm status/diagnostics/certificate-plan/browser-plan`
  and `networkcore-linux mitm browser-capture plan/launch-plan/session-plan/launch/apply/rollback/verify/traffic-proof`,
  exposes `traffic_proof_report` for proof-log-token evidence and PAC/browser policy artifact
  fields for `--pac-file` / `--policy-file` apply/rollback,
  keeps `mitm-cli-command-gate-status=partial-active`, and reports browser
  hijack as deferred;
- `engine-native` exposes `NativeHttpMitmPluginHook`,
  `plan_socks5_connect_http_mitm`, and
  `ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_REJECT_APPLIED_CODE`;
- Linux CLI exposes
  `native_proxy_engine_service_with_builtin_mitm_plugin` and uses it from the
  `networkcore-linux start` binary path;
- docs keep `MITM_CLI_COMMAND_GATE`, `MITM_CERTIFICATE_LIFECYCLE_GATE`,
  `MITM_BROWSER_CAPTURE_GATE`, and `MITM_HTTP_TLS_DATA_PLANE_GATE` visible
  while user-facing MITM is deferred;
- docs keep the Linux MITM browser capture source contract discoverable while
  `MITM_BROWSER_CAPTURE_GATE` remains pac-policy-profile-prefs-active/system-mutation-blocked;
- Rust CI builds and tests the workspace on Linux, macOS, and Windows;
- local machines do not run build, test, package, or release verification.
