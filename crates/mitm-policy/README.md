# mitm-policy

`mitm-policy` is the safe Rust adapter over the vendored `mitm_anixops`
v0.45.10-alpha C ABI.

It owns the first NetworkCore MITM policy boundary:

- RAII ownership for the opaque `mitm_anixops` engine.
- Config loading and rule diagnostics mapped to `control-domain` errors.
- MITM decision, URL rewrite, named header, bounded header-list application,
  body rewrite chain, script dispatch, JQ max-input guard, and aggregated
  rewrite plan helpers for contract tests.
- `MitmPluginService` implementation returning audit/diagnostics only.
- A built-in alpha ad-block plugin package.

Current limitation: this crate does not mutate real HTTP traffic. NetworkCore
still needs a domain mutation model and HTTP/TLS data plane before URL/header/body
rewrite results can be applied to live requests or responses.

User-facing live MITM is not available yet. The current Linux CLI exposes
`networkcore-linux mitm status`, `networkcore-linux mitm diagnostics`,
`networkcore-linux mitm certificate-plan`, and
`networkcore-linux mitm browser-plan`, plus
`networkcore-linux mitm browser-capture plan/launch-plan/session-plan/launch/apply/rollback/verify`;
the command surface reports policy-only status, a certificate lifecycle plan, a
browser capture plan, manual dedicated-profile launch templates, a
redacted subscription-to-local-proxy/browser/verify `session_plan`, an optional
dedicated profile target URL, a dedicated-profile `launch_report`, local proxy endpoint `verify_report`,
`browser_capture` blocked reports, and deferred browser hijack gates. The launch
templates, `session-plan`, `launch --confirm` report, and `verify --confirm`
report carry the loaded `networkcore.adblock` plugin metadata, planned proxy
URL, and optional target URL, but they do not generate or install a CA, decrypt HTTPS traffic, write
browser/system proxy state, prove live browser traffic capture, or apply rewrite
plans to live traffic.

Release/source split: `v0.1.0-alpha.7` is the latest published Linux artifact,
while this README describes current `main` source. Source-only MITM CLI
increments after that tag, including `verify --confirm`, `session-plan`, and
browser capture `--target-url`, require a later tag release before users can
download them from GitHub Releases.

Required gates before user-facing MITM:

- `MITM_CLI_COMMAND_GATE`: partially active for status, diagnostics,
  certificate-plan, browser-plan, browser-capture session plan, launch report, and
  browser-capture blocked reports only.
- `MITM_CERTIFICATE_LIFECYCLE_GATE`: currently plan-only through
  `mitm_status.certificate_plan`; later increments must implement CA
  generation, install, trust detection, revocation, and rollback boundaries.
- `MITM_BROWSER_CAPTURE_GATE`: currently plan-only/mutation-blocked through
  `mitm_status.browser_plan`, `browser_capture`, manual launch-plan output,
  redacted session-plan output, optional target URL, explicit dedicated-profile
  launch output, and local proxy endpoint verify output; later increments must
  implement explicit browser/system proxy configuration, PAC or other capture
  strategy, live capture verification, and rollback boundaries. The Linux
  source boundary is
  fixed by `docs/architecture/linux-mitm-browser-capture-source-contract.md`
  and requires `LinuxBrowserCaptureSessionPlanRequest`,
  `LinuxBrowserCaptureSessionPlanReport`, `BrowserCaptureProcessRunner`,
  `LinuxBrowserCaptureLaunchRequest`, `LinuxBrowserCaptureLaunchReport`,
  `LinuxBrowserCaptureVerifyRequest`, `LinuxBrowserCaptureVerifyReport`,
  `BrowserCaptureEndpointProbe`, `BrowserCaptureAuthorization`,
  `BrowserCaptureRollbackSnapshot`, and optional target URL before mutation.
- `MITM_HTTP_TLS_DATA_PLANE_GATE`: wire HTTP/TLS interception to
  `mitm-policy` rewrite plans.

Current CLI gate marker:

```text
mitm-cli-command-gate-status=partial-active
```

Verification is performed only by GitHub Actions, following the repository
CI/CD policy.
