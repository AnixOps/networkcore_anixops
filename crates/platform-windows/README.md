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
- The managed schema now has an optional `sing_box` block. The service owns a
  configured `sing-box.exe` child, runs `check -c` before `run -c`, persists
  its PID/exit status, and appends core stdout/stderr to the configured log path.
- `root_certificate_path` remains a generic trust-store installation only. The
  separate `native_mitm` block powers the explicit GUI-controlled loopback HTTP
  listener, service-owned CA lifecycle, controlled TLS termination, and local
  sing-box SOCKS outbound. It handles one bounded HTTP/1.1 exchange only; it
  does not provide HTTP/2, QUIC, streaming, or transparent capture.
- When the `sing_box` block is removed or disabled, the service uses the persisted
  core log path to stop the previous service-owned child before rollback.
- JavaScript script dispatch remains blocked.

`managed` owns the schema-versioned ProgramData configuration and state records.
`system_integration` calls SCM, WinINet/WinHTTP, CryptoAPI, and NewDev directly
and exposes apply, status, rollback, and uninstall operations.

The installed default configuration is intentionally inert: all optional
operations are `null` until an operator supplies absolute paths or proxy
settings. The GUI and service append diagnostics under
`%ProgramData%\\AnixOps\\NetworkCore\\logs`; errors are always recorded, while
verbose GUI status logging can be toggled from the desktop client or enabled
with `networkcore-windows-gui.exe --debug`.
