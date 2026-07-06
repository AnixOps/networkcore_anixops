# control-domain

`control-domain` contains the first Rust domain contracts for the unified network control kernel.

The crate is intentionally library-only and dependency-free. It defines shared value types and service traits for configuration, subscription parsing, policy routing, proxy engine adapters, DNS policy, MITM plugins, and the control API. Platform SDKs, proxy engine process management, UI code, and transport-specific control APIs must live in later adapter crates.

Verification for this crate is performed only by GitHub Actions, following the repository CI/CD policy.
