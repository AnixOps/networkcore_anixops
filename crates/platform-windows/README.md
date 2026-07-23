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
- Windows `root_certificate_path` remains trust-store installation only. It is
  not a MITM listener, CONNECT handler, TLS termination path, or request/response
  rewrite engine.
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
