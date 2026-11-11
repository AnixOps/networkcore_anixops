# node-runtime

The runtime behind `anixcore`: a `Node` runs protocol inbounds by tag (TCP
listeners for stream protocols, UDP sockets for QUIC protocols) and relays
through a direct outbound. Inbounds and users are added and removed at
runtime; per-user traffic (with reset) and online IPs are read back for
accounting.

- `config`: the `anixcore` config file (`management`, `allow_private_targets`,
  `inbounds`, `egress`). Inbound keys besides `tag`, `type`, `listen`, `listen_port`,
  `outbound`, `ingress` and `accept_proxy_protocol` go to the protocol factory.
- `"accept_proxy_protocol": true` on an inbound with a TCP listener, for a
  node behind a relay or load balancer that sends the PROXY protocol: every
  connection must start with a version 1 or 2 header (read before TLS,
  REALITY or a transport), and the address in it is the client's for device
  limits, online IPs and a forward's own `proxy_protocol`. Connections
  without a valid header are closed and counted as failed handshakes, so
  only that relay may reach the port. `GET /v1/status` lists the feature as
  `accept_proxy_protocol`.
- Clients may multiplex with sing-mux (sing-box `multiplex`, mihomo `smux`)
  in `smux`, `yamux` or `h2mux` (what those clients run when no protocol is
  set), with or without `padding`, on VLESS, VMess, Trojan and Shadowsocks
  inbounds (with TLS, REALITY or a transport too); nothing is configured
  for it. AnyTLS and Snell inbounds do not serve it, and on Hysteria2 and
  TUIC it carries TCP streams only. TCP Brutal is not supported.
  `GET /v1/status` lists the feature as `sing_mux`, and h2mux and padding
  as `sing_mux_h2mux`.
- `"fallbacks"` on VLESS, Trojan and AnyTLS inbounds: a list of `{"name",
  "alpn", "path", "dest", "xver"}` entries that send a connection which is
  not a user's to the destination matching its TLS server name, ALPN
  protocol and HTTP/1.x request path (`dest`: `host:port` or a local port;
  `xver` 1 or 2 writes a PROXY protocol header to it). The entry with the
  most matching conditions wins, an entry without conditions is the
  default, and the single `"fallback"` still works as that default. Behind
  a transport (`ws`, `grpc`, ...) only `path` and the default match.
  `GET /v1/status` lists the feature as `fallbacks`.
- An XHTTP inbound (VLESS, VMess, Trojan) with `h3` in its TLS `alpn`
  also serves HTTP/3: the node binds the UDP port of the same number for
  the inbound's QUIC side (`StreamInbound::packet`), beside its TCP
  listener, with the same users, outbound and counters.
  `accept_proxy_protocol` and the connection cap apply to the TCP side
  only. `GET /v1/status` lists the feature as `xhttp_h3`.
- `api`: local HTTP/JSON management API with a bearer token, shaped after
  what anix-agent's core interface needs (add/remove node, add/remove users,
  traffic slices, online devices).
- The direct outbound refuses loopback, private, CGNAT and link-local
  targets unless `allow_private_targets` is set; each inbound's `fallback`,
  `fallbacks` and REALITY `handshake` addresses stay reachable.
- `egress`: the panel's domain egress routes (anix-control 「转发 → 分流」,
  the desired-config member `egress`, set with `PUT /v1/egress`). As a source
  node, connections to a route's domains go to the exit node's
  Shadowsocks-2022 or VLESS relay (VLESS with REALITY or XHTTP for the
  cross-border standby channel, anx F-54; a relay may listen on a loopback
  `listen` behind a TLS front); as an exit node, the relays run beside the
  inbounds and always leave directly. Routing applies to every inbound: the
  domain is the requested name, else the TLS SNI / HTTP `Host` of the first
  bytes (waiting up to 300 ms), else the name a DNS answer relayed through the
  node gave the address (`domains::DomainCache`, which layer-3 inbounds with
  their own resolver also fill). Matchers: bare name or `domain:` (with
  subdomains), `full:`, `keyword:`, `regexp:`.
- `network`: the network model's device plan (anix-control
  `docs/design/network-model` §6.3, `NetworkPlan` from
  `sdk/api/network/v1`), set with `PUT /v1/network` or the config member
  `network`, beside `/v1/egress`. Each egress is an outbound `egress:<id>`
  bound to its source address (TCP bind then connect, UDP `bind(source:0)`)
  and, with a health check, probed by the kernel from that source. An
  inbound with `"ingress": "<id>"` takes the ingress's active path: a local
  egress, or a transport's registered outbound `<kind>:<transport id>`
  (`anx-line:<id>`), failing over in pairing order with a failback delay.
  `GET /v1/network` reports each egress's state and each ingress's active
  egress and path.
- `tls_fingerprints`: a ClientHello fingerprint bundle
  (`tls_mimic::install_profiles`: `{"format": 1, "revision": "...",
  "profiles": {"chrome": {...}, "safari": {...}}}`), set with
  `PUT /v1/tls-fingerprints` or the config member `tls_fingerprints`. It
  replaces the browser shapes built into the kernel for every outbound of the
  process that imitates a browser, so an agent follows a browser release by
  pushing data. The bundle is the whole state (`"profiles": {}` restores the
  built-in data); one with a profile this kernel cannot reproduce is refused
  with 400 and changes nothing; names the kernel does not know are skipped
  and listed as `ignored`. `GET /v1/tls-fingerprints` answers the revision in
  effect, the replaced names and every name the kernel knows.
- Listeners on `::` accept IPv4 too on every OS and fall back to `0.0.0.0`
  on hosts without IPv6.
- Protocols are cargo features (`shadowsocks`, `trojan`, `vless`, `vmess`,
  `hysteria2`, `tuic`, `snell`), all on by default.

`tests/management_api.rs` drives a node through the API with the engine's
Shadowsocks-2022 client; `tests/egress.rs` routes domains between two nodes
through a relay; `tests/network.rs` sends ingresses through a source-bound
egress and a transport outbound.
