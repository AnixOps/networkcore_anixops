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

UDP command: one datagram per body chunk, to the request target. Mux
command: Mux.Cool frames, which Xray clients use for UDP (XUDP) and `mux`.

Not yet: authenticated length and legacy alterId > 0. `tests/vmess_inbound.rs` runs the engine's VMess client
against the server.
