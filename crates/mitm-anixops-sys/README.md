# mitm-anixops-sys

`mitm-anixops-sys` compiles the vendored `mitm_anixops` distribution release
`v1.4.9` source commit `bb66dc7f1fd02259fd87fd9dd576e90bb9ad768b` and exposes
an unsafe Rust FFI boundary. The linked C core reports version `0.45.10`.

The narrow policy capability query mirrors the released C ABI only:
`policy_capability_query_abi_version()` and `policy_capabilities()` expose the
deterministic V1 policy-core mask. They do not describe host TLS, certificate,
network, storage, script, consent, or platform capabilities.

With the default `pcre2` feature the C core is built with
`ANIXOPS_ENABLE_PCRE2`: `pcre2-sys` (pinned `=0.2.9`, PCRE2 10.43) compiles and
links PCRE2 statically (`.cargo/config.toml` sets `PCRE2_SYS_STATIC=1`), and
`vendor/pcre2/pcre2.h` is that version's header. `mitm-policy` switches each
engine to the PCRE2 backend before loading a config. Without the feature the
core falls back to POSIX regex.

This crate is intentionally low-level. Safe policy and domain adapter APIs must
live in the `mitm-policy` crate.

Verification for this crate is performed only by GitHub Actions, following the
repository CI/CD policy.
