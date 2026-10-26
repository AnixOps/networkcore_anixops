# inbound-transport

Server-side transports that wrap an `engine_inbound::StreamInbound`.

- `TlsInbound` / `wrap`: rustls (ring) TLS termination in front of a protocol
  inbound. Settings (`"tls"` in a protocol's inbound config):
  `certificate_path` + `key_path`, or inline PEM `certificate` + `key`, and
  optional `alpn`. File certificates are re-read when their modification time
  changes (checked at most every 30 s), so ACME renewals need no restart; a
  broken replacement keeps the previous certificate.
- `server_config` exposes the rustls `ServerConfig` for QUIC-based inbounds.

Not yet: WebSocket and gRPC server transports. `tests/tls_inbound.rs` covers
inline and file certificates; all verification runs in GitHub Actions.
