# mitm-policy

`mitm-policy` is the safe Rust adapter over the vendored `mitm_anixops`
distribution release `v1.4.6` source commit. The linked C core ABI reports
version `0.45.10`.

## What the crate provides

- RAII ownership for the opaque `mitm_anixops` engine.
- Config loading and rule diagnostics mapped to `control-domain` errors.
- MITM decision, URL rewrite, named header, bounded header-list application,
  body rewrite chain, script dispatch, JQ max-input guard, and aggregated
  rewrite plan helpers for contract tests.
- `MitmPluginService` with legacy deferred audit/diagnostics and rich
  `MitmPluginService::handle_http_mitm_event` planning: loaded plugin source is
  retained in `PluginInstance`, and `mitm_anixops` URL reject/redirect, header
  mutation, body mutation, and script dispatch results map to
  `control-domain` `HttpMitmOutcome` plans.
- A built-in alpha ad-block plugin package, `networkcore.adblock`.
- `ManagedSdwanMitmPolicyGate`, a pure fail-closed admission boundary for an
  opaque immutable verifier-produced Plan B client delivery envelope. It
  snapshots only the linked C core, validates the released V1 capability query,
  client/profile coherence, DNS suffix boundary, consent, certificate trust,
  QUIC, and pinned-TLS observations, and rechecks expiry against the
  caller-supplied trusted current service clock without activating a proxy, POP
  connection, CA operation, script, or host mutation.

This crate never mutates traffic on its own; it only produces plans. Consumers apply them:

- `engine-native` (`NativeHttpMitmPluginHook`) applies a `Reject` plan at the
  explicit SOCKS5 CONNECT layer as a SOCKS5 general failure before outbound
  selection.
- The native explicit HTTP proxy (`NativeExplicitHttpProxyRequest`) applies
  reject, redirect, and header/body rewrite to real `http://` HTTP/1.x traffic.
- `networkcore-linux start --enable-https-mitm` (since `v0.1.2-alpha.3`) applies
  the plan inside the controlled CONNECT TLS data plane when the operator supplies
  CA material and confirmation: authority/SNI-bound TLS termination, web-PKI
  upstream forwarding, up to four bounded HTTP/1.1 exchanges per session, and an
  explicitly mapped local Node runner (trusted local code, bounded body/timeout,
  fail-open, never downloads script URLs).

## Linux CLI surface

The Linux CLI loads this crate for `networkcore-linux mitm status`, `diagnostics`,
`certificate-plan`, `browser-plan`, `certificate apply/rollback`,
`http-rewrite plan/preview` (`http_rewrite` report), and
`browser-capture plan/launch-plan/session-plan/launch/apply/rollback/verify/traffic-proof`.
Browser capture covers dedicated-profile launch, target route verify,
`proof-log-token` traffic proof (`BrowserCaptureTrafficProofProbe`,
`proof_connect_authority`, `binding_mismatch`), `--proxy-scheme socks5`
(`proxy_scheme`) to reach the native SOCKS5 CONNECT hook, and
`apply --confirm --pac-file <path> [--policy-file <path>] [--profile-prefs-file <path>] --snapshot <path>`
through `BrowserCapturePacFileStore`. Command details are in
[apps/linux-cli/README.md](../../apps/linux-cli/README.md); the per-version
boundary index is `docs/alpha-release-feature-matrix.md`.

## Gates

```text
mitm-cli-command-gate-status=partial-active
```

| Gate | Current state | Remaining work | Boundary |
|---|---|---|---|
| `MITM_CLI_COMMAND_GATE` | partial-active | full operable command surface | — |
| `MITM_CERTIFICATE_LIFECYCLE_GATE` | artifact-lifecycle-active/profile-trust-artifact-active/trust-mutation-blocked; explicit Ubuntu-style trust-file apply/rollback | other CA install, trust detection, revocation, trust-store rollback | `docs/architecture/linux-mitm-certificate-lifecycle-source-contract.md` |
| `MITM_HTTP_TLS_DATA_PLANE_GATE` | `mitm http-rewrite` preview: plain-http-live-data-plane-active/tls-decryption-blocked (the separate `start --enable-https-mitm` path is live) | HTTP/2, HTTP/3/QUIC, streaming, broader capture | `docs/architecture/linux-mitm-http-rewrite-source-contract.md` |
| `MITM_BROWSER_CAPTURE_GATE` | pac-policy-profile-prefs-active/system-mutation-blocked; browser hijack deferred | explicit browser/system proxy configuration, system PAC or other capture strategy, live capture verification, rollback | `docs/architecture/linux-mitm-browser-capture-source-contract.md` |

P4 current stage source of truth: MITM work is part of P4 Client And Platform
Integration; P3 Runtime Capability Baseline is completed history. The remaining
P4 backlog buckets for this crate are the certificate lifecycle gate, the
HTTP/TLS data plane gate, and the browser capture user flow.

Verification is performed only by GitHub Actions, following the repository
CI/CD policy.
