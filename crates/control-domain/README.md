# control-domain

`control-domain` contains the first Rust domain contracts for the unified network control kernel.

The crate is intentionally library-only and dependency-free. It defines shared value types and service traits for configuration, listener configuration, subscription parsing, policy routing, platform capability status, proxy engine adapters, DNS policy, MITM plugins, and the control API. Platform SDKs, proxy engine process management, UI code, and transport-specific control APIs must live in later adapter crates.

`NodeDescriptor` includes stable metadata for per-protocol adapter parameters that do not belong in the common endpoint shape. The first metadata anchors are `NODE_METADATA_SHADOWSOCKS_METHOD`, `NODE_METADATA_SHADOWSOCKS_PASSWORD`, `NODE_METADATA_TROJAN_PASSWORD`, `NODE_METADATA_VLESS_UUID`, `NODE_METADATA_VMESS_UUID`, and `NODE_METADATA_SOURCE_FORMAT` for subscription URL import and public engine translation. Adapter diagnostics must not echo secret metadata values.

Verification for this crate is performed only by GitHub Actions, following the repository CI/CD policy.
