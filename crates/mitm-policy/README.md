# mitm-policy

`mitm-policy` is the safe Rust adapter over the vendored `mitm_anixops`
distribution release `v1.4.7` source commit. The linked C core ABI reports
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

## Loon plugin import (P0, P1)

`loon_plugin::import_loon_plugin` imports a user-supplied Loon plugin and
grades every line as supported, partial, deferred, unsupported, or ignored.
The plugin as a whole is graded `full`, `partial`, or `unsupported`.

- `#!` metadata and `[Argument]` go to `LoonPluginMetadata`.
- `[MITM] hostname` (`%APPEND%`/`%INSERT%`, `-host`/`!host` exclusions) goes
  to `LoonMitmHostnames::apply`. Plugins only add hosts.
  `skip-server-cert-verify` is always refused.
- `[Rule]` DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, IP-CIDR, IP-CIDR6, and GEOIP lines with a
  REJECT or DIRECT policy become routing rules. `routing_model_with_plugin_rules`
  puts them before the user's rules.
- URL-REGEX REJECT rules, reject variants, 301–308 redirects, and
  request/response header rewrites stay in the source that the `mitm_anixops`
  core evaluates.
- Rules that name another policy cannot work, because a plugin does not know
  the user's node names.
- `[Script]` `http-request` and `http-response` lines (P1) are planned by the
  `mitm_anixops` core and run on desktop in the in-process QuickJS runtime of
  `crates/script-runtime`. `binary-body-mode` is partial (bodies reach scripts
  as strings), and `cron`, `generic`, and other event scripts are unsupported.
  The iOS JavaScriptCore runtime arrives in M4.
- `[Map Local]` lines, and `[Rewrite]` `mock-response-body` lines, answer a
  matching request locally (`HttpMitmAction::Respond`) without contacting the
  origin. `data-type` may be `text`, `json`, `html`, `base64`, or `tiny-gif`;
  `status-code` and `header="Name:Value|..."` are honored. A remote `data` URL
  is not fetched and is unsupported. The URL pattern is matched by the
  `mitm_anixops` core (`loon_map_local`).
- `[Body Rewrite]` `http-request`/`http-response <url> <regex> <replacement>
  ...` lines are translated into the core's url-first
  `request-body-replace-regex`/`response-body-replace-regex` rules, one per
  pair, and every matching body rule applies in order. Url-first body rewrite
  lines in `[Rewrite]` are supported too. jq lines (`http-response-jq`,
  `response-body-jq`) are unsupported because the core is built without jq.

The corpus in `tests/fixtures/loon-plugins` has an expected level for each
plugin, and `tests/loon_plugin_contracts.rs` prints the graded report for
each one.

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
