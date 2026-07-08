# MITM Policy Ad Block Plugin Source Contract

## Purpose

This contract fixes the first NetworkCore-owned MITM policy plugin over the
pinned `mitm_anixops` C ABI.

The built-in ad-block plugin is intentionally a policy package, not a complete
traffic mutation feature. It proves that NetworkCore can load an AnixOps/Loon
style rule set through `mitm_anixops` and surface stable audit/diagnostics
through `MitmPluginService`.

## Current Source Boundary

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
- Rust CI builds and tests the workspace on Linux, macOS, and Windows;
- local machines do not run build, test, package, or release verification.
