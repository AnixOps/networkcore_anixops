# mitm-policy

`mitm-policy` is the safe Rust adapter over the vendored `mitm_anixops`
v0.45.10-alpha C ABI.

It owns the first NetworkCore MITM policy boundary:

- RAII ownership for the opaque `mitm_anixops` engine.
- Config loading and rule diagnostics mapped to `control-domain` errors.
- MITM decision, URL rewrite, named header, bounded header-list application,
  body rewrite chain, script dispatch, JQ max-input guard, and aggregated
  rewrite plan helpers for contract tests.
- `MitmPluginService` implementation with legacy deferred audit/diagnostics and
  rich `handle_http_mitm_event` mutation-plan output for future data-plane use.
- A built-in alpha ad-block plugin package.

Current limitation: this crate does not mutate real HTTP traffic by itself. It
maps `mitm_anixops` URL reject/redirect, header mutation, body mutation, and
script dispatch results into `control-domain` `HttpMitmOutcome` plans. The
native explicit-proxy path can consume a `Reject` plan at SOCKS5 CONNECT time,
and the Linux CLI can apply reject/redirect/header/body outcomes to
caller-provided plain HTTP preview input through `mitm http-rewrite`. NetworkCore
still needs TLS interception and live HTTP/TLS data-plane work before these
plans can affect real browser/system traffic.

P4 current stage source of truth: MITM work is now part of P4 Client And
Platform Integration. P3 Runtime Capability Baseline is completed history. The
remaining P4 backlog buckets for this crate are the certificate lifecycle gate,
the HTTP/TLS data plane gate, and the browser capture user flow that proves and
routes real browser traffic before rewrite plans can affect live requests. P3
mentions in completed entries describe the finished baseline only; current MITM
work should be planned and documented as P4.

Full user-facing live MITM is not available yet. The current Linux CLI exposes
`networkcore-linux mitm status`, `networkcore-linux mitm diagnostics`,
`networkcore-linux mitm certificate-plan`, and
`networkcore-linux mitm browser-plan`, plus
`networkcore-linux mitm http-rewrite plan/preview`, plus
`networkcore-linux mitm browser-capture plan/launch-plan/session-plan/launch/apply/rollback/verify/traffic-proof`;
the command surface reports policy-only status, a certificate lifecycle plan, a
browser capture plan, manual dedicated-profile launch templates, a
redacted subscription-to-local-proxy/browser/verify `session_plan`, an optional
dedicated profile target URL, a dedicated-profile `launch_report`, local proxy endpoint `verify_report`,
`traffic_proof_report`, PAC/browser policy artifact apply/rollback reports, `browser_capture` blocked reports, and deferred browser hijack gates. The launch
templates, `session-plan`, `launch --confirm` report, and `verify --confirm`
report carry the loaded `networkcore.adblock` plugin metadata, planned proxy
URL, `proxy_scheme`, and optional target URL; `--proxy-scheme socks5` binds
session-plan, launch, PAC/browser policy artifact, verify, and traffic-proof requests to
`socks5://127.0.0.1:7890` so an authorized dedicated browser can target the
native SOCKS5 CONNECT hook; `verify --confirm --target-url <url>` additionally
records `probe=http-connect-target` and `target_reachable` when the planned proxy
can open a CONNECT tunnel to the target host:port, but these paths do not generate or install a CA, decrypt HTTPS traffic, write
browser/system proxy state, prove live browser traffic capture, or apply rewrite
plans to live traffic. Current `main` also adds
`mitm http-rewrite plan` and `mitm http-rewrite preview --confirm --url <url>`,
which output `http_rewrite` and apply plugin outcomes to caller-provided plain
HTTP input. Current `main` also exposes the native `ListenerKind::Http`
explicit proxy path for real `http://` HTTP/1.x request/response traffic; that
path parses `NativeExplicitHttpProxyRequest`, applies reject, redirect,
header/body rewrite outcomes, and forwards non-terminal requests through the
existing SOCKS outbound primitive. This path is governed by
`docs/architecture/linux-mitm-http-rewrite-source-contract.md` and does not
perform TLS decryption, downstream TLS termination, HTTPS request/response
rewrite, CA trust mutation, browser/system proxy mutation, or script execution;
current `main` additionally allows explicit HTTP `CONNECT host:443` to establish
a pass-through tunnel foundation and bounded ClientHello/SNI observation through
the configured SOCKS outbound. Current `main` also adds
`traffic-proof --confirm [--target-url <url>] [--proof-token <token>] [--proof-log <path>]`, which uses a
`BrowserCaptureTrafficProofProbe` with `probe=proof-log-token` to inspect an
operator-provided proof log for a session proof binding, can default omitted proof token/log to the
same session proof binding, emits `proof_connect_authority` and
`LinuxBrowserCaptureTrafficProofReport`, and reports `binding_mismatch` when the
token is not bound on the same proof log line to the planned proxy URL and
CONNECT authority. Current `main` also adds
`apply --confirm --pac-file <path> [--policy-file <path>] [--profile-prefs-file <path>] --snapshot <path>`, which uses
`BrowserCapturePacFileStore` to write only a caller-selected NetworkCore PAC
artifact, optional Chromium/Chrome managed proxy policy artifact, optional Firefox
dedicated profile prefs, `profile_prefs_file_path`/`profile_prefs_content`, and rollback snapshot. Those proof and artifact paths still do not prove
HTTPS MITM decryption, browser/system proxy mutation, system PAC installation,
or live rewrite application. Current `main` also binds browser proof evidence
into session/launch reports: `proof_target_url` appends `networkcore_proof_token`
to the dedicated browser target URL, and `traffic_proof_command` points at the
matching proof log inspection command. This still only helps correlate an
operator-provided proof log with the launched dedicated browser session; it does
not prove HTTPS MITM decryption or rewrite application. Current `main` also adds rich
`MitmPluginService::handle_http_mitm_event` planning: loaded plugin source is
retained in `PluginInstance`, and `networkcore.adblock` can produce a
`HttpMitmOutcome` reject plan for matching ad URLs. `networkcore-linux start`
loads that built-in plugin into `engine-native` through
`NativeHttpMitmPluginHook`; when an explicit SOCKS5 CONNECT target matches a
`Reject` plan, the native accept loop writes a SOCKS5 general failure response
before outbound selection. This blocks the CONNECT tunnel, but it is not HTTPS
decryption and does not apply redirect/header/body/script rewrite plans.

Release/source split: `v0.1.1-alpha.1` is the latest published prerelease Linux
artifact, and `v0.1.0` remains the latest stable Linux artifact, while this
README describes current `main` source. The prerelease inherits the `v0.1.0`
Linux capability boundary and includes
`verify --confirm`, `verify --confirm --target-url <url>`, `session-plan`,
browser capture `--target-url`, `traffic-proof`, PAC/browser policy artifact
apply/rollback, native SOCKS5 CONNECT plugin reject, the
`--proxy-scheme socks5` native plugin proxy mode, and `mitm certificate
apply/rollback` certificate artifact lifecycle with TLS CA certificate PEM/private key PEM and dedicated profile CA PEM copy output, plus `mitm http-rewrite
plan/preview` caller-provided plain HTTP rewrite foundation and explicit HTTP
proxy `http://` live request/response rewrite, explicit HTTP `CONNECT`
pass-through tunnel foundation, bounded ClientHello/SNI observation, and
controlled downstream TLS termination plan/report, plus caller-provided HTTPS
request reject/redirect/header mutation preview through `NativeHttpsRequestRewritePreviewReport`,
and caller-provided HTTPS response header/body mutation preview through
`NativeHttpsResponseRewritePreviewReport`, plus `traffic-proof`
`proof_connect_authority` and same-line token/proxy/CONNECT authority binding
diagnostics, plus traffic-proof text CONNECT authority output. Later live TLS termination,
TLS decryption and full HTTPS rewrite increments after this tag require a later tag
release before users can download them from GitHub Releases. The full alpha/rc
feature and boundary index is `docs/alpha-release-feature-matrix.md`.
`v0.1.1-alpha.1` also publishes the Windows CLI artifact source/release contract
as contract-only/blocked output; it does not define `package-windows` or upload a
Windows zip. Current `main` is synced to the `v0.1.1-alpha.1` post-release
boundary: browser capture `traffic-proof` records `proof_connect_authority`,
requires token/proxy/CONNECT authority binding in the same proof log line, and
prints the CONNECT authority in text output for manual proof audit; Linux CLI
also freezes caller-provided HTTPS request preview so it still reports
`tls_decryption_ready=false`, `https_response_rewrite_ready=false`, and
`script_dispatch_ready=false`.
Current `main` source lets `engine-native` preview response header
mutation and guarded response body mutation for caller-provided response-phase
`https://` input through `NativeHttpsResponseRewritePreviewReport`, but it still
does not execute JavaScript dispatch, live TLS decryption, live CONNECT-stream
HTTPS rewrite, or full live HTTPS response rewrite.

Required gates before user-facing MITM:

- `MITM_CLI_COMMAND_GATE`: partially active for status, diagnostics,
  certificate-plan, browser-plan, browser-capture session plan, launch report, and
  browser-capture blocked reports only.
- `MITM_CERTIFICATE_LIFECYCLE_GATE`: currently artifact-lifecycle-active/profile-trust-artifact-active/trust-mutation-blocked through
  `mitm_status.certificate_plan` and Linux CLI `certificate_lifecycle`
  apply/rollback reports. `mitm certificate apply --confirm --cert-file
  <path> --key-file <path> [--profile-trust-file <path>] --snapshot <path>`
  writes only NetworkCore-owned CA certificate PEM/private key PEM artifacts, optional
  dedicated profile CA PEM copy, and rollback snapshot; later increments
  must implement CA install, trust detection, revocation, and trust-store
  rollback boundaries. The Linux boundary is documented in
  `docs/architecture/linux-mitm-certificate-lifecycle-source-contract.md`.
- `MITM_BROWSER_CAPTURE_GATE`: currently pac-policy-profile-prefs-active/system-mutation-blocked through
  `mitm_status.browser_plan`, `browser_capture`, manual launch-plan output,
  redacted session-plan output, optional target URL, explicit dedicated-profile
  launch output, local proxy endpoint verify output, target route verify output,
  proof-log-token traffic proof output, `--proxy-scheme socks5` native plugin
  proxy mode, and NetworkCore PAC/browser policy/profile prefs artifact
  apply/rollback; later increments must implement explicit browser/system proxy
  configuration, system PAC or other capture strategy, live capture verification,
  and rollback boundaries. The Linux
  source boundary is
  fixed by `docs/architecture/linux-mitm-browser-capture-source-contract.md`
  and requires `LinuxBrowserCaptureSessionPlanRequest`,
  `LinuxBrowserCaptureSessionPlanReport`, `BrowserCaptureProcessRunner`,
  `LinuxBrowserCaptureLaunchRequest`, `LinuxBrowserCaptureLaunchReport`,
  `LinuxBrowserCaptureVerifyRequest`, `LinuxBrowserCaptureVerifyReport`,
  `BrowserCaptureEndpointProbe`, `BrowserCaptureAuthorization`,
  `LinuxBrowserCaptureTrafficProofRequest`,
  `LinuxBrowserCaptureTrafficProofReport`, `BrowserCaptureTrafficProofProbe`,
  `LinuxBrowserCapturePacRequest`, `BrowserCapturePacFileStore`,
  `BrowserCaptureRollbackSnapshot`, optional target URL, and proof-log-token
  evidence before mutation.
- `MITM_HTTP_TLS_DATA_PLANE_GATE`: currently plain-http-live-data-plane-active/tls-decryption-blocked through
  `mitm http-rewrite plan/preview`, `http_rewrite`, `NativePlainHttpMessage`,
  `NativePlainHttpRewriteReport`, `NativeExplicitHttpProxyRequest`,
  `NativePlainHttpProxyResponse`, `LinuxMitmHttpRewriteReport`, explicit
  authorization, caller-provided plain HTTP preview input, and explicit HTTP
  proxy live `http://` request/response rewrite plus explicit HTTP `CONNECT`
  pass-through tunnel foundation, bounded ClientHello/SNI observation, caller-provided
  HTTPS request preview, and caller-provided HTTPS response preview. Later increments must wire downstream TLS
  termination, HTTPS decryption, script runtime, and full live HTTPS rewrite
  boundaries. The Linux source boundary is fixed by
  `docs/architecture/linux-mitm-http-rewrite-source-contract.md`.

Current CLI gate marker:

```text
mitm-cli-command-gate-status=partial-active
```

Verification is performed only by GitHub Actions, following the repository
CI/CD policy.
