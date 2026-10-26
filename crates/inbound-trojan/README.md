# inbound-trojan

Trojan server inbound for the node kernel, built on `engine-inbound`.

- Users are matched by SHA-224 of their `password`; traffic and online IPs are
  charged per user, users can be added and removed at runtime.
- A first record that is not a Trojan request for a known user is relayed to
  the `fallback` (usually a local web server) unchanged; without a fallback the
  connection is held open and drained.
- `UDP ASSOCIATE`: packets `ATYP ADDR PORT LENGTH CRLF PAYLOAD` on the
  stream are relayed through the node's UDP outbound, charged to the user.
- Config: `{"type": "trojan", "users": [{"name": "...", "password": "..."}],
  "tls": {...}, "fallback": {"server": "127.0.0.1", "server_port": 8080}}`.
  `tls` is optional for deployments behind a TLS terminator.

Not yet: WebSocket/gRPC transports. `tests/trojan_inbound.rs`
runs the engine's Trojan client against the server.
