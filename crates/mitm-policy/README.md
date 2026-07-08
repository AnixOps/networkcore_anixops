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

User-facing MITM is not available yet. The current Linux release does not expose
a `networkcore-linux mitm` command, does not generate or install a CA, does not
decrypt HTTPS traffic, and does not apply rewrite plans to live traffic.

Required gates before user-facing MITM:

- `MITM_CLI_COMMAND_GATE`: add the `networkcore-linux mitm` command surface.
- `MITM_CERTIFICATE_LIFECYCLE_GATE`: implement CA generation, install, trust
  detection, revocation, and rollback boundaries.
- `MITM_HTTP_TLS_DATA_PLANE_GATE`: wire HTTP/TLS interception to
  `mitm-policy` rewrite plans.

Verification is performed only by GitHub Actions, following the repository
CI/CD policy.
