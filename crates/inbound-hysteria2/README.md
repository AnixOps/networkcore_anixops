# inbound-hysteria2

Hysteria2 server inbound for the node kernel, built on `engine-inbound` and
`transport-quic`.

- QUIC with ALPN `h3`. Clients authenticate with `POST /auth` and the
  `hysteria-auth` header over a minimal built-in HTTP/3 (static QPACK table
  only); a known password gets status 233, anything else 404 like a web server.
- TCP streams (`0x401`) on an authenticated connection are relayed and charged
  to the user; removing the user closes the connection.
- UDP over QUIC datagrams when the node has a UDP outbound (it announces
  `hysteria-udp: true`): one socket per client session id, fragments
  reassembled and replies fragmented to the datagram limit, bytes charged to
  the user, sessions closed after two idle minutes.
- Optional Salamander obfuscation.
- Config: `{"type": "hysteria2", "users": [{"name": "...", "password":
  "..."}], "tls": {...}, "obfs": {"type": "salamander", "password": "..."}}`.
  `tls` is required.

Not yet: Brutal congestion control, port hopping.
`tests/hysteria2_inbound.rs` runs the engine's Hysteria2 client against the
server.
