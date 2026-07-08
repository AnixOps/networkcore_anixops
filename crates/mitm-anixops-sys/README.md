# mitm-anixops-sys

`mitm-anixops-sys` compiles the vendored `mitm_anixops` v0.41.0-alpha C core
and exposes an unsafe Rust FFI boundary.

This crate is intentionally low-level. Safe policy and domain adapter APIs must
live in the `mitm-policy` crate.

Verification for this crate is performed only by GitHub Actions, following the
repository CI/CD policy.
