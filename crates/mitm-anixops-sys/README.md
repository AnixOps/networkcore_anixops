# mitm-anixops-sys

`mitm-anixops-sys` compiles the vendored `mitm_anixops` distribution release
`v1.4.6` source commit `6382f0147e02a8653343571791ef61b8cc885cb1` and exposes
an unsafe Rust FFI boundary. The linked C core reports version `0.45.10`.

The narrow policy capability query mirrors the released C ABI only:
`policy_capability_query_abi_version()` and `policy_capabilities()` expose the
deterministic V1 policy-core mask. They do not describe host TLS, certificate,
network, storage, script, consent, or platform capabilities.

This crate is intentionally low-level. Safe policy and domain adapter APIs must
live in the `mitm-policy` crate.

Verification for this crate is performed only by GitHub Actions, following the
repository CI/CD policy.
