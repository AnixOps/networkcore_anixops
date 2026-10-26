# inbound-vmess

VMess AEAD server inbound (alterId 0) for the node kernel, built on
`engine-inbound`.

- Users are matched by trying each user's AuthID key (CRC and a 120 s
  timestamp window); AuthIDs are remembered for 240 s to refuse replays.
  Unknown or replayed clients are held open and drained.
- Body securities `aes-128-gcm`, `chacha20-poly1305` and `none`; options
  ChunkStream (required), ChunkMasking and GlobalPadding. The response mirrors
  the client's options.
- Config: `{"type": "vmess", "users": [{"name": "...", "uuid": "..."}],
  "tls": {...}}`.

Not yet: authenticated length, legacy alterId > 0, UDP and mux, WebSocket and
gRPC transports. `tests/vmess_inbound.rs` runs the engine's VMess client
against the server.
