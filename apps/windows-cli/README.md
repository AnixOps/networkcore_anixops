# networkcore-windows

`networkcore-windows` is the Windows CLI source identity for the
`v0.1.1-alpha.2` package/publish path.

Current boundary:

- Binary name: `networkcore-windows`.
- Package source: `apps/windows-cli`.
- Platform capability source: `crates/platform-windows`.
- Release artifact target: `x86_64-pc-windows-gnu`.
- Release archive: `networkcore-windows-${version}-x86_64-pc-windows-gnu.zip`.
- Install model: manual extract.
- System mutation policy: none.

The current command surface is intentionally conservative: `help`, `version`,
`capabilities`, `status`, and `diagnostics`. Shared parser gates may
catalog-import Trojan/VLESS/VMess URLs, Clash YAML, sing-box JSON, and Surge
proxy lines in `config-core`, but Windows subscription run compatibility,
Windows service, driver, installer, `system-proxy-mutation`,
`system-trust-store-mutation`, JavaScript script dispatch, and managed daemon
lifecycle remain blocked or deferred for later slices.
