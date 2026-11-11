# inbound-shadowsocks

Shadowsocks-2022 (SIP022) and Shadowsocks AEAD (SIP004) TCP and UDP server
inbounds for the node kernel, built on `engine-inbound`. The `shadowsocks`
config type picks the protocol by method name. Clients may come through the
SIP003 plugins simple-obfs and v2ray-plugin (see below).

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

## Behind ShadowTLS v3

A `"shadow_tls"` object puts the TCP side of either protocol behind a
ShadowTLS v3 server (`engine_inbound::shadow_tls`): clients make a real TLS
1.3 handshake with the `handshake` site through the port and then carry
Shadowsocks in authenticated ApplicationData records; anything else that
connects is relayed to that site.

- `{"type": "shadowsocks", "method": "...", "password": "...", "users": [...],
  "shadow_tls": {"password": "...", "handshake": {"server":
  "www.example.com", "server_port": 443}}}`: one ShadowTLS password for all
  clients. The users are the Shadowsocks users, and Shadowsocks UDP stays
  on the same port, outside ShadowTLS.
- `"shadow_tls": {"users": [{"name": "...", "password": "..."}],
  "handshake": {...}}` on an inbound without Shadowsocks users: each client
  has its own ShadowTLS password and the inbound's users are these
  (`StreamInbound::users()`, traffic, limits, online IPs). The UDP port is
  not opened, as a datagram names no ShadowTLS user; clients carry UDP in a
  sing-mux stream. A `password` beside `users` serves clients that are no
  user.
- `"strict_mode": true` serves clients only when the handshake site
  answered in TLS 1.3 and relays them to it otherwise; `"version"` may be
  given and must be 3.

## SIP003 plugin clients

Both protocols serve clients that run a SIP003 plugin, with the server side
built into the inbound; no plugin process runs beside the node. The plugins
are for TCP: UDP on the port stays plain Shadowsocks, as those clients send
it.

- simple-obfs (`obfs-local`; mihomo `plugin: obfs`, sing-box
  `"plugin": "obfs-local"`): `"obfs": {"type": "http" | "tls", "host":
  "cdn.example"}` (`src/obfs.rs`).
  - `http`: the client's fake `GET` upgrade request is stripped (the first
    payload may follow it) and the first server payload leaves behind a
    `101 Switching Protocols` response, in one write; then both directions
    are the raw stream.
  - `tls`: the first payload is taken from the session ticket extension of
    the fake ClientHello; the first server payload follows a fake
    ServerHello and ChangeCipherSpec as the encrypted handshake message, and
    everything after is framed as application data records.
  - `host`, when set, is the name clients must send (`obfs-host`): the
    `Host` header (port ignored) or the server name. Any other request is
    held open and drained like a failed Shadowsocks handshake.
- v2ray-plugin, `websocket` mode: `"transport": {"type": "ws", "path": "/x",
  "host": "..."}`, with `"tls": {...}` for its `tls` option, as
  `inbound-transport` takes them. Only without the plugin's multiplexing:
  the reference clients multiplex by default (v2ray-plugin `mux=1`, mihomo
  `mux: true`, sing-box), so they have to be given `mux=0` / `mux: false`.
  `quic` mode is not served. Xray's Shadowsocks outbound on its own `ws`
  transport is the same on the wire.
- `obfs` does not combine with `tls` or `transport`, `ws` is the only
  transport taken, and none of the three combines with `shadow_tls`.

`tests/ss2022_server.rs` and `tests/aead_server.rs` run the engine's own client and the
shadowsocks-rust client (TCP and UDP) against the server, `tests/plugins.rs`
both protocols behind simple-obfs and the WebSocket transport; the reference
plugin clients (mihomo, sing-box) run in `node-runtime`'s
`tests/client_interop.rs`. All verification runs in GitHub Actions.
