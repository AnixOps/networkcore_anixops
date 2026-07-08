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

Verification is performed only by GitHub Actions, following the repository
CI/CD policy.
