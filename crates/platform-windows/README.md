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

## TUN mode

`tun` creates a Wintun adapter for system-wide capture. The client ships
`wintun.dll` next to its executable and passes that absolute path to
`WindowsTun::open`; the DLL is never loaded from the search path. The adapter
gets `172.19.0.1/30` (DNS `172.19.0.2`, answered by the tunnel) and
`fdfe:dcba:9876::1/126`, and the capture routes `0.0.0.0/1`, `128.0.0.0/1`,
`::/1` and `8000::/1`. Closing the adapter removes its address and routes, so
the physical default route is never touched.

The physical interface of each family is recorded before the routes go in.
The host installs an `engine_outbound::protect` socket protector that calls
`bind_socket_to_interface` (`IP_UNICAST_IF` / `IPV6_UNICAST_IF`) so the
engine's own sockets to proxy servers, DNS upstreams and direct destinations
do not loop back into the adapter.
