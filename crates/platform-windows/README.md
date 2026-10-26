# platform-windows

`platform-windows` provides the native system-integration boundary shared by the
NetworkCore GUI, service, installer, and CLI.

Current status:

- `WINDOWS_CLI_ARTIFACT_GATE=windows-managed-client-active`
- `windows-cli-artifact-source-identity=apps/windows-cli`
- `windows-cli-artifact-package-windows=defined`
- Windows service, signed INF driver package lifecycle, WiX MSI installer,
  system proxy mutation, system trust store mutation, and managed daemon
  lifecycle are active.
- The managed schema has an optional `embedded` block: an engine-embedded
  configuration envelope path and a loopback listener. The service runs that
  engine in-process, polls it, and routes a failure through failed-state
  cleanup and proxy rollback. No third-party proxy core is started.
- `root_certificate_path` remains a generic trust-store installation only. The
  separate `native_mitm` block powers the explicit GUI-controlled loopback HTTP
  listener, service-owned CA lifecycle, controlled TLS termination, and the
  embedded engine as its local SOCKS upstream. It handles one bounded HTTP/1.1 exchange only; it
  does not provide HTTP/2, QUIC, streaming, or transparent capture.
- JavaScript script dispatch remains blocked.

`managed` owns the schema-versioned ProgramData configuration and state records.
`system_integration` calls SCM, WinINet/WinHTTP, CryptoAPI, and NewDev directly
and exposes apply, status, rollback, and uninstall operations.

The installed default configuration is intentionally inert: all optional
operations are `null` until an operator supplies absolute paths or proxy
settings. The GUI and service append diagnostics under
`%ProgramData%\\AnixOps\\NetworkCore\\logs`; errors are always recorded, while
verbose GUI status logging can be toggled from the desktop client or enabled
with `networkcore-windows-gui.exe --debug` (the GUI and service live in
[AnixOps/anixops-net](https://github.com/AnixOps/anixops-net)).
