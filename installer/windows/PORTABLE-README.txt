AnixOps NetworkCore Windows portable package

1. Extract the entire directory to a writable location.
2. Run networkcore-windows-gui.exe. Approve the administrator prompt when
   using service, proxy, certificate, or driver operations.
3. Click Install core in the sing-box profile section when a proxy core is
   needed. This explicitly downloads the official Windows core; the ZIP itself
   does not contain a third-party core.
4. Enter a local profile file path, optionally enter a Node ID, then click
   Import profile. A blank Node ID uses the first supported node.
5. Click Install service, then Start, only when a Windows service is wanted.

The portable ZIP does not register or start the service during extraction.
Managed configuration, state, and logs are stored under:

  %ProgramData%\AnixOps\NetworkCore

To remove a service installed from the portable package, run this command from
an Administrator terminal before deleting the extracted directory:

  networkcore-windows-service.exe purge
  networkcore-windows-service.exe uninstall

The profile importer supports basic Shadowsocks, Trojan, VLESS, and VMess
nodes. Trojan enables TLS; VLESS and VMess are basic TCP only. It does not
preserve TLS/REALITY/WebSocket/gRPC/multiplex/DNS/route fields. Use explicit
native sing-box JSON for those configurations.

sing-box is not bundled. root_certificate_path only manages Windows trust; this
build does not provide a Windows HTTPS MITM data plane.
