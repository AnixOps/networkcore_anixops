# inbound-shadowsocks

Shadowsocks-2022 (SIP022) TCP and UDP server inbound for the node kernel, built on
`engine-inbound`.

- Methods `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`,
  `2022-blake3-chacha20-poly1305`.
- Single-key mode (no users) or multi-user mode: the server `password` is the
  identity key and each user's `password` is its own key; clients send
  `iPSK:uPSK` (AES methods only, as SIP022 defines).
- Users can be added and removed at runtime through `StreamInbound::users()`;
  traffic and online IPs are charged per user.
- 30 s timestamp window, 60 s replayed-salt cache, failed handshakes are held
  open and drained instead of closed at once.
- UDP on the same port when the node has a UDP outbound
  (`StreamInbound::datagram`): AES separate headers and identity headers,
  XChaCha20-Poly1305 for the ChaCha method, one socket per client session,
  replies to the client's latest address, the same timestamp window and a
  1024-packet replay window per session.
- Config: `{"type": "shadowsocks", "method": "...", "password": "<base64>",
  "users": [{"name": "...", "password": "<base64>"}]}` via
  `ShadowsocksInboundFactory`.

`tests/ss2022_server.rs` runs the engine's own client and the
shadowsocks-rust client (TCP and UDP) against the server; all verification runs in
GitHub Actions.
