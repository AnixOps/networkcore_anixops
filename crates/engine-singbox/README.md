# engine-singbox

`engine-singbox` is the first public execution engine adapter crate for NetworkCore.

The crate currently provides source contracts for:

- `sing-box` public engine descriptor identity.
- Latest GitHub release metadata parsing.
- Host/target asset selection for official `sing-box-*` archives.
- Downloading the latest selected archive from the official SagerNet GitHub release.
- Verifying the GitHub release asset `sha256:` digest when present.
- Extracting only the `sing-box` executable from `.tar.gz` archives into a NetworkCore-owned engine cache.
- Rendering a deterministic local `mixed` inbound `sing-box` JSON config from a
  basic Shadowsocks, Trojan, VLESS, VMess, Hysteria2, or TUIC `NodeDescriptor`.
- Recognizing a native sing-box JSON configuration without transforming it and
  locating a local `mixed` or `http` inbound for Windows system-proxy setup.
- Rewriting only a native `type: mixed`, `tag: mixed-in` listener for the
  Windows GUI's controlled MITM SOCKS upstream, while leaving snapshot and
  restoration ownership to the Windows managed-client lifecycle.
- Running `sing-box run -c <config>` through an injectable foreground process runner.
- A managed process supervisor that executes `check -c` before `run -c`, owns the
  child process, captures stdout/stderr into an explicit log file, and reports
  running/stopped/failed state with PID and exit code.

The crate does not bundle `sing-box` in NetworkCore release artifacts. It downloads into an operator-visible cache directory at runtime and records version, asset, digest, archive path, executable path, and diagnostics so the control layer can report provenance without leaking host paths outside explicit CLI output.

The existing foreground runner is intentionally a simple blocking runner. The
managed supervisor is the lifecycle primitive used by the Windows service, but
it still requires an explicit executable path and does not claim TUN/DNS,
firewall, or MITM behavior. The installer extracts the Windows official ZIP by
selecting only the `sing-box.exe` entry; service-side download and release
packaging remain separate policy decisions.

The Windows GUI explicitly installs the verified official core and imports an
operator-selected local profile at the configured `config_path`. A native
sing-box document with top-level `inbounds` or `outbounds` is retained verbatim,
including TLS/REALITY/transport/multiplex/route/DNS fields. Other inputs use
the generated path, which supports Shadowsocks, Trojan, VLESS, VMess,
Hysteria2, and TUIC outbounds. The V2Ray-family local-file subset renders
explicit TLS/ALPN/pins/uTLS, VLESS Vision/REALITY, VMess security/alter-id, and
WebSocket/gRPC/HTTP/HTTPUpgrade/V2Ray-QUIC transport metadata. It does not
infer unsupported XHTTP, ECH, multiplex, routing, or DNS fields. Hysteria2 and
TUIC retain only their explicit catalog metadata: credentials, TLS options,
Hysteria2 port hopping/obfuscation, and TUIC congestion control. They are direct
proxy-core QUIC paths, not the GUI HTTPS MITM path. The wrapper
`managed-config.json` only supplies process paths and lifecycle policy; it is
not itself a sing-box configuration.
