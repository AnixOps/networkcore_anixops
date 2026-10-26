# inbound-snell

Snell server inbound for the node kernel, built on `engine-inbound` and the
frame codec of `outbound-snell`. Implemented only from
`docs/protocols/snell.md` (clean room).

- Versions 1–4 and 6; a version 4 server also serves v5 clients. v1–v3 accept
  either cipher, v6 uses the configured `mode` (`default`, `unshaped`,
  `unsafe-raw`), v1–v4 support `obfs: "http"`.
- Single user (any clientID) or multi-user: with `users`, the request's
  clientID (Surge `userkey`) must equal a user's `password`; traffic and
  online IPs are charged per user.
- Frames that fail to decrypt, malformed requests, unknown users and replayed
  first salts are closed without a reply. PING gets PONG.
- Config: `{"type": "snell", "psk": "...", "version": 4, "obfs": "http",
  "users": [{"name": "...", "password": "userkey"}]}`; v6 adds `"mode"`.

Each connection serves one request and closes after it, without the server's
zero chunk, so reusing clients do not pool it. Not yet: UDP over TCP, several
CONNECTv2 requests per connection, ERROR replies for unreachable targets.
`tests/snell_inbound.rs` runs the engine's Snell client against the server.
