# MITM Policy Ad Block Plugin Source Contract

## Purpose

This contract fixes the first NetworkCore-owned MITM policy plugin over the
pinned `mitm_anixops` C ABI.

The built-in ad-block plugin is intentionally a policy package, not a complete
traffic mutation feature. It proves that NetworkCore can load an AnixOps/Loon
style rule set through `mitm_anixops` and surface stable audit/diagnostics
through `MitmPluginService`.

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
- `MITM_POLICY_HTTP_EVENT_MUTATION_DEFERRED_CODE`
- `MITM_CLI_COMMAND_GATE`
- `MITM_CERTIFICATE_LIFECYCLE_GATE`
- `MITM_HTTP_TLS_DATA_PLANE_GATE`

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

Current user-facing status: MITM is policy-only. There is no
`networkcore-linux mitm` command, no CA generation/install/trust workflow, no
HTTPS decryption path, and no live URL/header/body/script mutation path in the
published CLI.

## Multi-Client Boundary

Platform clients must not maintain their own ad-block parser. Linux, macOS,
Windows, iOS, and future UI clients must call the same NetworkCore domain
boundary:

- client imports or enables a plugin package;
- NetworkCore validates `PluginManifest` and permissions;
- `mitm-policy` loads `PluginPackage.source` through `mitm_anixops`;
- `MitmPluginService` returns audit/diagnostics;
- a later HTTP/TLS data plane applies structured mutations after the domain
  mutation model exists.

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

The current plugin service does not mutate live request or response data.

Blocked until later phases:

- `MITM_CLI_COMMAND_GATE`: user-facing `networkcore-linux mitm` command
  surface, status output, diagnostics, and explicit unavailable/deferred states.
- `MITM_CERTIFICATE_LIFECYCLE_GATE`: CA generation, user-approved install,
  trust detection, fingerprint/expiration/revocation checks, uninstall, and
  rollback boundaries.
- `MITM_HTTP_TLS_DATA_PLANE_GATE`: HTTP CONNECT/TLS interception, SNI/host
  routing, HTTP/1.1 and HTTP/2 parsing, body buffering/limits, compression
  handling, and application of `mitm-policy` URL/header/body/script rewrite
  plans to live traffic.
- URL/header/body mutation output in `control-domain`.
- HTTP request and response context with URL, method, phase, host, scheme, and
  response status.
- HTTP/TLS MITM data plane in `engine-native` or another execution adapter.
- Platform certificate install/trust workflow.
- JavaScript runtime and persistent storage.

The required current diagnostic is:

```text
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
- docs keep `MITM_CLI_COMMAND_GATE`, `MITM_CERTIFICATE_LIFECYCLE_GATE`, and
  `MITM_HTTP_TLS_DATA_PLANE_GATE` visible while user-facing MITM is deferred;
- Rust CI builds and tests the workspace on Linux, macOS, and Windows;
- local machines do not run build, test, package, or release verification.
