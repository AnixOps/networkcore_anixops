# inbound-vless

VLESS server inbound for the node kernel, built on `engine-inbound`.

- Users are matched by `uuid`; traffic and online IPs are charged per user,
  users can be added and removed at runtime.
- The response header goes out with the first payload. Clients that are not a
  known VLESS user are relayed to the `fallback` or held open and drained.
- Config: `{"type": "vless", "users": [{"name": "...", "uuid": "..."}],
  "tls": {...}, "fallback": {...}}`.

Not yet: the `xtls-rprx-vision` flow, REALITY, UDP and mux (users with a
Vision flow are rejected). `tests/vless_inbound.rs` runs the engine's VLESS
client against the server.
