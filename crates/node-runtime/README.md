# node-runtime

The runtime behind `anixcore`: a `Node` runs protocol inbounds by tag (TCP
listeners for stream protocols, UDP sockets for QUIC protocols) and relays
through a direct outbound. Inbounds and users are added and removed at
runtime; per-user traffic (with reset) and online IPs are read back for
accounting.

- `config`: the `anixcore` config file (`management`, `allow_private_targets`,
  `inbounds`). Inbound keys besides `tag`, `type`, `listen` and `listen_port`
  go to the protocol factory.
- `api`: local HTTP/JSON management API with a bearer token, shaped after
  what anix-agent's core interface needs (add/remove node, add/remove users,
  traffic slices, online devices).
- The direct outbound refuses loopback, private, CGNAT and link-local
  targets unless `allow_private_targets` is set; each inbound's `fallback` and
  REALITY `handshake` addresses stay reachable.
- Protocols are cargo features (`shadowsocks`, `trojan`, `vless`, `vmess`,
  `hysteria2`, `tuic`, `snell`), all on by default.

`tests/management_api.rs` drives a node through the API with the engine's
Shadowsocks-2022 client.
