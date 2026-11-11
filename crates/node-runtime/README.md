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
  in `smux` or `yamux` on every inbound whose protocol names a destination;
  nothing is configured for it. `h2mux` (what those clients pick when no
  protocol is set), padding and TCP Brutal are not supported.
  `GET /v1/status` lists the feature as `sing_mux`.
- `api`: local HTTP/JSON management API with a bearer token, shaped after
  what anix-agent's core interface needs (add/remove node, add/remove users,
  traffic slices, online devices).
- The direct outbound refuses loopback, private, CGNAT and link-local
  targets unless `allow_private_targets` is set; each inbound's `fallback` and
  REALITY `handshake` addresses stay reachable.
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
