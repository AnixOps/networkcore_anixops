# networkcore-windows

`networkcore-windows` is the command-line companion to the managed Windows
client introduced in `v0.2.0-alpha.1`.

Current boundary:

- Binary name: `networkcore-windows`.
- Package source: `apps/windows-cli`.
- Platform capability source: `crates/platform-windows`.
- Release artifact target: `x86_64-pc-windows-gnu`.
- Release installer: `networkcore-windows-${version}-x86_64-pc-windows-gnu.msi`.
- Install model: per-machine WiX MSI.
- System mutation policy: managed apply and rollback.

The CLI command surface includes `help`, `version`, `capabilities`, `status`,
`diagnostics`, and the explicit EasyTier tunnel lifecycle. Shared parser gates may
catalog-import Trojan/VLESS/VMess URLs, Clash YAML, sing-box JSON, Surge proxy
lines, Loon proxy lines, and Quantumult X proxy/server lines in `config-core`.
The companion GUI and service activate Windows service control, signed INF
driver package lifecycle, the MSI installer, `system-proxy-mutation`,
`system-trust-store-mutation`, managed daemon lifecycle, and the optional
service-owned sing-box process configured in `managed-config.json`. The service
validates the native sing-box JSON with `check -c` before starting it and writes
core stdout/stderr to the configured log. The GUI now explicitly installs the
verified official Windows core and imports a selected local profile into a
service-ready config using basic Shadowsocks, Trojan, VLESS, or VMess output.
The CLI itself has no core-install or subscription-run command. The GUI/service
provide explicit controlled HTTP/1.1 HTTPS MITM with a service-owned CA and
local sing-box SOCKS upstream. Remote subscription fetch, advanced transport
rendering, HTTP/2, QUIC, streaming, JavaScript script dispatch, and CLI MITM
configuration remain unavailable.
