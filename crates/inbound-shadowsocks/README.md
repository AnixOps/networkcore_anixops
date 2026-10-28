# inbound-shadowsocks

Shadowsocks-2022 (SIP022) and Shadowsocks AEAD (SIP004) TCP and UDP server
inbounds for the node kernel, built on `engine-inbound`. The `shadowsocks`
config type picks the protocol by method name.

## Shadowsocks-2022

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

## Shadowsocks AEAD (SIP004)

- Methods `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`
  (`chacha20-poly1305` accepted as an alias).
- Always multi-user: each user's `password` is a plain password
  (`EVP_BytesToKey`), and users can be added at runtime even when the inbound
  started without any. An optional inbound `password` is one more key that is
  charged to no user.
- SIP004 carries no user identity, so the server tries the users' keys on the
  first length chunk (the whole packet for UDP); the key that last matched a
  client IP is tried first.
- Authenticated TCP salts are remembered for 10 minutes and replays refused;
  failed handshakes are held open and drained.
- UDP on the same port: a session is the client address plus its key, one
  socket per session.
- Config: `{"type": "shadowsocks", "method": "aes-128-gcm", "users": [{"name":
  "...", "password": "..."}]}`.

`tests/ss2022_server.rs` and `tests/aead_server.rs` run the engine's own client and the
shadowsocks-rust client (TCP and UDP) against the server; all verification runs in
GitHub Actions.
