# config-core

`config-core` contains the first pure configuration service for the unified network control kernel.

The crate implements `ConfigurationService` for a minimal TOML document shape with `schema_version`, `profile`, `profiles`, `listeners`, `nodes`, and `routes` fields. It normalizes profiles, inbound listeners, local nodes, and default route sets into `ConfigSnapshot` without reading files, making network requests, starting proxy engines, or depending on platform adapters.

The current parser intentionally keeps DNS, plugin, subscription, secret, duplicate-id, and listener/node graph validation out of scope. `networkcore-linux start` remains unwired until the native engine can validate the normalized graph and hold a real runtime handle.

Verification for this crate is performed only by GitHub Actions, following the repository CI/CD policy.
