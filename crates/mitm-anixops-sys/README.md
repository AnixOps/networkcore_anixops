# mitm-anixops-sys

`mitm-anixops-sys` compiles the vendored `mitm_anixops` C core and exposes a
minimal unsafe Rust FFI boundary.

This crate is intentionally low-level. Safe policy and domain adapter APIs must
live in a later `mitm-policy` crate.

Verification for this crate is performed only by GitHub Actions, following the
repository CI/CD policy.
