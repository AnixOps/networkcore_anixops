# mitm-anixops-sys

`mitm-anixops-sys` compiles the vendored `mitm_anixops` distribution release
`v1.4.7` source commit `ee952234c35ddf36f2c63f8aa20f28ad744bd054` and exposes
an unsafe Rust FFI boundary. The linked C core reports version `0.45.10`.

The narrow policy capability query mirrors the released C ABI only:
`policy_capability_query_abi_version()` and `policy_capabilities()` expose the
deterministic V1 policy-core mask. They do not describe host TLS, certificate,
network, storage, script, consent, or platform capabilities.

This crate is intentionally low-level. Safe policy and domain adapter APIs must
live in the `mitm-policy` crate.

Verification for this crate is performed only by GitHub Actions, following the
repository CI/CD policy.
