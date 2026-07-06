# config-core

`config-core` contains the first pure configuration service for the unified network control kernel.

The crate implements `ConfigurationService` for a minimal TOML document shape with `schema_version`, `profile`, and `profiles` fields. It normalizes profile names into `ConfigSnapshot` without reading files, making network requests, starting proxy engines, or depending on platform adapters. Listener, node, route, and DNS parsing are intentionally still empty until their explicit config contract lands.

Verification for this crate is performed only by GitHub Actions, following the repository CI/CD policy.
