# inbound-forward

Fixed-target port forward for the node kernel: every TCP connection and UDP
datagram that reaches the listen port is relayed to one configured
`server:server_port`. No handshake, no users. It is how a panel forwarding
rule runs on a node: one `forward` inbound per rule, its traffic leaving
through the inbound's base outbound (`direct`, or e.g. `anx-line:<link_id>`
on anx-node).

- Config: `{"type": "forward", "server": "203.0.113.7", "server_port": 443,
  "network": "tcp,udp"}`; `network` is `tcp`, `udp` or `tcp,udp` (default).
  `server` is an IP address or a name, resolved per connection.
- UDP: one outbound session per client address, ended after 120 s without
  traffic; replies leave from the listen port. At most 1024 clients at once.
- Adding users is refused. Bytes are counted per inbound by the serve loop;
  node-runtime reports them in the `inbound` member of
  `GET /v1/inbounds/{tag}/traffic`.
- node-runtime lets the forward's own target through the private-target
  filter and does not apply egress routes to forwards.

`crates/node-runtime/tests/forward.rs` covers TCP, UDP, traffic and a named
outbound.
