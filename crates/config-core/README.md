# config-core

`config-core` contains the first pure configuration and subscription parsing services for the unified network control kernel.

The crate implements `ConfigurationService` for a minimal TOML document shape with `schema_version`, `profile`, `profiles`, `listeners`, `nodes`, and `routes` fields. It normalizes profiles, inbound listeners, local nodes, and default route sets into `ConfigSnapshot` without reading files, making network requests, starting proxy engines, or depending on platform adapters.

The crate also implements `SubscriptionService` as `CoreSubscriptionService`. It accepts explicit `inline:` subscription sources, parses the same minimal TOML `nodes` and `routes` subset, single `ss://`, `trojan://`, and `vless://` URLs, plaintext proxy link lists, and base64 encoded proxy link lists into `SubscriptionDocument`, and normalizes them into `NodeCatalog`. Remote subscription fetching, file loading, authentication, DNS, plugin, duplicate-id, and listener/node graph validation remain out of scope for this crate; secrets are only carried as node metadata for adapter translation and must not be echoed in diagnostics.

`networkcore-linux run-url` consumes the URL subscription path directly for the first `sing-box` foreground local proxy workflow. `networkcore-linux start` consumes normalized local configuration through the runtime and native engine path; persisted subscription catalogs are not yet wired into generic runtime startup.

Verification for this crate is performed only by GitHub Actions, following the repository CI/CD policy.
