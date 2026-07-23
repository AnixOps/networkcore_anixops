AnixOps NetworkCore Windows portable package

1. Extract the entire directory to a writable location.
2. Run networkcore-windows-gui.exe. Approve the administrator prompt when
   using service, proxy, certificate, or driver operations.
3. Click Install core in the sing-box profile section when a proxy core is
   needed. This explicitly downloads the official Windows core; the ZIP itself
   does not contain a third-party core.
4. Enter a local profile file path, optionally enter a Node ID, then click
   Import profile. A blank Node ID uses the first supported node.
5. Click Enable HTTPS MITM when the explicit local HTTP(S) proxy and managed
   CA are required. The core then runs as a SOCKS upstream on 127.0.0.1:7891;
   the native HTTP(S) proxy listens on 127.0.0.1:7890.
6. Click Install service, then Start, only when a Windows service is wanted.

The portable ZIP does not register or start the service during extraction.
Managed configuration, state, and logs are stored under:

  %ProgramData%\AnixOps\NetworkCore

To remove a service installed from the portable package, run this command from
an Administrator terminal before deleting the extracted directory:

  networkcore-windows-service.exe purge
  networkcore-windows-service.exe uninstall

The profile importer renders basic Shadowsocks, Trojan, VLESS, and VMess nodes.
Trojan enables TLS; VLESS and VMess are basic TCP only. A native sing-box JSON
file with top-level inbounds or outbounds is instead copied unchanged, so
TLS/REALITY/WebSocket/gRPC/multiplex/DNS/route fields are preserved. Use the
basic profile path for Enable HTTPS MITM because that action owns the mixed
listener port.

sing-box is not bundled. The HTTPS MITM path handles explicit HTTP proxy
traffic and controlled HTTP/1.1 TLS sessions only. It does not support HTTP/2,
QUIC, streaming/chunked exchanges, TUN, DNS interception, or remote scripts.
