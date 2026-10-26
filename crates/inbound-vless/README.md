# inbound-vless

VLESS server inbound for the node kernel, built on `engine-inbound`.

- Users are matched by `uuid`; traffic and online IPs are charged per user,
  users can be added and removed at runtime.
- The response header goes out with the first payload. Clients that are not a
  known VLESS user are relayed to the `fallback` or held open and drained.
- REALITY (`"reality"` instead of `"tls"`): clients whose ClientHello carries
  a valid REALITY marker (server private key, listed short id and SNI, clock
  window) get a TLS 1.3 handshake with a temporary certificate; everything
  else is relayed byte for byte to the `handshake` site.
- Config: `{"type": "vless", "users": [{"name": "...", "uuid": "..."}],
  "tls": {...}, "fallback": {...}}`, or with `"reality": {"private_key":
  "...", "short_ids": ["..."], "server_names": ["..."], "handshake":
  {"server": "www.example.com", "server_port": 443},
  "max_time_difference_secs": 60}`.

Not yet: the `xtls-rprx-vision` flow, UDP and mux (users with a Vision flow
are rejected); REALITY does not mirror the handshake site's record sizes.
`tests/vless_inbound.rs` and `tests/vless_reality.rs` run the engine's VLESS
clients against the server.
