# node-runtime

The runtime behind `anixcore`: a `Node` runs protocol inbounds by tag (TCP
listeners for stream protocols, UDP sockets for QUIC protocols) and relays
through a direct outbound. Inbounds and users are added and removed at
runtime; per-user traffic (with reset) and online IPs are read back for
accounting.

- `config`: the `anixcore` config file (`management`, `allow_private_targets`,
  `inbounds`, `egress`). Inbound keys besides `tag`, `type`, `listen` and `listen_port`
  go to the protocol factory.
- `api`: local HTTP/JSON management API with a bearer token, shaped after
  what anix-agent's core interface needs (add/remove node, add/remove users,
  traffic slices, online devices).
- The direct outbound refuses loopback, private, CGNAT and link-local
  targets unless `allow_private_targets` is set; each inbound's `fallback` and
  REALITY `handshake` addresses stay reachable.
- `egress`: the panel's domain egress routes (anix-control 「转发 → 分流」,
  the desired-config member `egress`, set with `PUT /v1/egress`). As a source
  node, connections to a route's domains go to the exit node's
  Shadowsocks-2022 relay; as an exit node, the relays run beside the
  inbounds and always leave directly. Routing applies to every inbound: the
  domain is the requested name, else the TLS SNI / HTTP `Host` of the first
  bytes (waiting up to 300 ms), else the name a DNS answer relayed through the
  node gave the address (`domains::DomainCache`, which layer-3 inbounds with
  their own resolver also fill). Matchers: bare name or `domain:` (with
  subdomains), `full:`, `keyword:`, `regexp:`.
- Listeners on `::` accept IPv4 too on every OS and fall back to `0.0.0.0`
  on hosts without IPv6.
- Protocols are cargo features (`shadowsocks`, `trojan`, `vless`, `vmess`,
  `hysteria2`, `tuic`, `snell`), all on by default.

`tests/management_api.rs` drives a node through the API with the engine's
Shadowsocks-2022 client; `tests/egress.rs` routes domains between two nodes
through a relay.
