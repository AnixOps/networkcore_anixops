AnixOps NetworkCore Windows portable package

1. Extract the entire directory to a writable location.
2. Run networkcore-windows-gui.exe. Approve the administrator prompt when
   using service, proxy, certificate, or driver operations.
3. Click Install core in the sing-box profile section when a proxy core is
   needed. This explicitly downloads the official Windows core; the ZIP itself
   does not contain a third-party core.
4. Enter a local profile file path or HTTP(S) subscription URL, click Load nodes,
   choose a node, then click Import profile. A blank selector uses the first
   supported node. Native sing-box JSON stays pass-through. After a successful
   URL import, Update URL explicitly refreshes that saved address; it does not
   run in the background or restart the service.
5. Click Enable HTTPS MITM when the explicit local HTTP(S) proxy and managed
   CA are required. The core then runs as a SOCKS upstream on 127.0.0.1:7891;
   the native HTTP(S) proxy listens on 127.0.0.1:7890.
6. Click Install service, then Start, only when a Windows service is wanted.

The portable ZIP does not register or start the service during extraction. It
is included with every Windows tag release alongside the MSI and its own
SHA-256 and manifest files.
Managed configuration, state, and logs are stored under:

  %ProgramData%\AnixOps\NetworkCore

To remove a service installed from the portable package, run this command from
an Administrator terminal before deleting the extracted directory:

  networkcore-windows-service.exe purge
  networkcore-windows-service.exe uninstall

The profile importer renders Shadowsocks, Trojan, VLESS, VMess, Hysteria2, and
TUIC nodes. Local V2Ray share links retain TLS/ALPN/certificate pins/uTLS,
VLESS Vision/REALITY, VMess security/alter-id, and
WebSocket/gRPC/HTTP/HTTPUpgrade/V2Ray-QUIC transport fields. It does not infer
XHTTP, ECH, multiplex, routing, or DNS. Hysteria2 local hysteria2:// or hy2://
links retain supported password, port hopping, obfuscation, and TLS fields.
TUIC local tuic:// links retain UUID, optional password, congestion control,
and TLS fields. These QUIC core paths are not HTTP/1.1 HTTPS MITM traffic. A native sing-box JSON
file with top-level inbounds or outbounds is instead copied unchanged, so
TLS/REALITY/WebSocket/gRPC/multiplex/DNS/route fields are preserved. Use the
basic profile path or a native config with type "mixed" and tag "mixed-in" for
Enable HTTPS MITM. For that exact native inbound, the GUI saves an original JSON
snapshot, moves only the listener to 127.0.0.1:7891, and restores it when MITM
is disabled. Other native inbounds are not modified.

sing-box is not bundled. The HTTPS MITM path handles explicit HTTP proxy
traffic and controlled HTTP/1.1 TLS sessions only. It does not support HTTP/2,
QUIC, streaming/chunked exchanges, TUN, DNS interception, or remote scripts.
