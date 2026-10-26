# inbound-transport

Server-side transports that wrap an `engine_inbound::StreamInbound`.

- `TlsInbound` / `wrap`: rustls (ring) TLS termination in front of a protocol
  inbound. Settings (`"tls"` in a protocol's inbound config):
  `certificate_path` + `key_path`, or inline PEM `certificate` + `key`, and
  optional `alpn`. File certificates are re-read when their modification time
  changes (checked at most every 30 s), so ACME renewals need no restart; a
  broken replacement keeps the previous certificate.
- `server_config` exposes the rustls `ServerConfig` for QUIC-based inbounds.

- `WsInbound` / `GrpcInbound` / `wrap_all`: the server side of the outbound
  `transport` object, between TLS and the protocol (`"transport"` in the
  Trojan, VLESS and VMess inbound configs):
  - `{"type": "ws", "path": "/x", "host": "...", "max_early_data": 8192,
    "early_data_header_name": "Sec-WebSocket-Protocol"}`: WebSocket upgrade
    on `path` (query ignored), optional `Host` check, Xray-style early data
    in `Sec-WebSocket-Protocol` (echoed back). Other paths get `404`,
    non-upgrade requests `400`.
  - `{"type": "grpc", "service_name": "Svc"}`: gRPC "gun" calls to
    `/Svc/Tun` (or a full custom path starting with `/`); each call on a
    client connection is one client stream, up to 256 at once. Under TLS
    without configured `alpn`, `h2` is offered.
  - `{"type": "tcp"}` is the same as no transport. VLESS REALITY (and so
    Vision) takes no transport.

`TlsInbound` and `WsInbound` pass `serves_connections` and `datagram` through
to the protocol. `tests/tls_inbound.rs` covers inline and file certificates,
`inbound-trojan/tests/trojan_transports.rs` the WebSocket and gRPC paths; all
verification runs in GitHub Actions.
