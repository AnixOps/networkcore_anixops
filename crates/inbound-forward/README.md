# inbound-forward

Port forward for the node kernel: every TCP connection and UDP datagram that
reaches the listen port is relayed to a configured `server:server_port`, or
to one of several `targets` picked by a balancing policy. No handshake, no
users. It is how a panel forwarding rule runs on a node: one `forward`
inbound per rule, its traffic leaving through the inbound's base outbound
(`direct`, `egress:<id>`, or e.g. `anx-line:<link_id>` on anx-node, where the
target is resolved and dialed at the last hop).

- One target: `{"type": "forward", "server": "203.0.113.7", "server_port": 443,
  "network": "tcp,udp"}`; `network` is `tcp`, `udp` or `tcp,udp` (default).
  `server` is an IP address or a name, resolved per connection.
- Several targets (forward.v1 `Policy`), instead of `server`:

  ```json
  {"targets": [{"server": "a.example", "server_port": 443, "weight": 2},
               {"server": "203.0.113.8", "server_port": 443, "priority": 1}],
   "balance": "least_conn",
   "health": {"interval_ms": 5000, "timeout_ms": 2000, "disabled": false},
   "circuit_breaker": {"failure_threshold": 3, "open_ms": 30000}}
  ```

  `balance` is `round_robin` (default, smooth weighted), `random` (weighted),
  `ip_hash` (a client stays on its target while it is up), `least_conn` or
  `failover` (the lowest `priority` that is up); the forward.v1 names
  (`BALANCE_STRATEGY_IP_HASH`) work too. Health checks are a TCP connect to
  each target through the forward's outbound every `interval_ms`; with one
  target or a UDP-only forward they do not run. Failures in a row (checks or
  dials) open a target's breaker for `open_ms`, then one connection or check
  tries it again; any success closes it. A failed dial moves the connection
  on to the next target. When every target is open, all are tried. 0 in any
  number takes the default shown.
- Limits per rule (forward.v1 `Limits`): `bandwidth_bps` (bits per second,
  each direction, shared by all connections and UDP sessions of the rule)
  and `max_conns` (concurrent TCP connections; more are closed at once).
- `proxy_protocol`: `off` (default), `v1` or `v2` (or `PROXY_PROTOCOL_V2`).
  The forward writes the PROXY header to the target ahead of the client's
  bytes, with the client's address and the address it reached; relays pass
  it on untouched. TCP only.
- UDP: one outbound session per client address, which keeps the target it
  was first given, ended after 120 s without traffic; replies leave from the
  listen port. At most 1024 clients at once.
- Adding users is refused. Bytes are counted per inbound by the serve loop;
  node-runtime reports them in the `inbound` member of
  `GET /v1/inbounds/{tag}/traffic`.
- node-runtime lets the forward's own targets through the private-target
  filter and does not apply egress routes to forwards.

`crates/node-runtime/tests/forward.rs` covers TCP, UDP, traffic, a named
outbound, balancing and failover, the PROXY header and `max_conns`.
