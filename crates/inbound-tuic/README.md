# inbound-tuic

TUIC v5 server inbound for the node kernel, built on `engine-inbound` and
`transport-quic`.

- Clients authenticate with UUID and a token exported from the TLS session
  with the user's password; a wrong token closes the connection.
- Connect streams are relayed and charged to the authenticated user; removing
  the user closes the connection.
- Config: `{"type": "tuic", "users": [{"name": "...", "uuid": "...",
  "password": "..."}], "tls": {...}, "congestion_control": "cubic"}`.

Not yet: UDP relay (Packet/Dissociate), zero-RTT. `tests/tuic_inbound.rs`
runs the engine's TUIC client against the server.
