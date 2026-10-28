# anixcore

The AnixOps node kernel: protocol server inbounds (Shadowsocks-2022 and
Shadowsocks AEAD, Trojan,
VLESS with REALITY, VMess, Hysteria2, TUIC, Snell) in one process, driven by
a local management API so that a node agent such as anix-agent can add and
remove inbounds and users and collect per-user traffic and online IPs.

```text
anixcore run -c config.json
anixcore check -c config.json
anixcore version
```

```json
{
  "management": {"listen": "127.0.0.1:10085", "token": "change-me"},
  "inbounds": [
    {"tag": "ss", "type": "shadowsocks", "listen_port": 8388,
     "method": "2022-blake3-aes-128-gcm", "password": "<base64 key>",
     "users": [{"name": "1001", "password": "<base64 key>"}]}
  ]
}
```

Users may carry `"speed_limit"` (Mbit/s for each direction, shared by all
of the user's connections) and `"device_limit"` (most client IPs online at
once); both default to 0, no limit.

The config format is documented in `crates/node-runtime/src/config.rs` and
the API in `crates/node-runtime/src/api.rs`. Users relay through a direct
outbound that refuses loopback and private targets unless
`"allow_private_targets": true`.

Domain egress routes from the panel (anix-control 「转发 → 分流」) are applied
with `PUT /v1/egress` (or the config member `egress`): the route's domains
leave through the exit node's Shadowsocks-2022 relay, for every inbound, and
an exit node serves the relays. See `crates/node-runtime/src/egress.rs`.

The network model's device plan (anix-control `docs/design/network-model`)
is applied with `PUT /v1/network` (or the config member `network`): every
egress becomes an outbound `egress:<id>` bound to its source address and
health-checked from it, and an inbound with `"ingress": "<id>"` leaves
through that ingress's active path, failing over between egresses. See
`crates/node-runtime/src/network.rs`.

Port forwarding rules from the panel (anix-control 「转发」) are `forward`
inbounds: the listen port relays TCP and UDP to one fixed target, through
the inbound's base outbound only (egress routes do not apply). The target
may be private; it is the operator's, not a user's.

```json
{"tag": "rule-7", "type": "forward", "listen_port": 10001,
 "server": "203.0.113.7", "server_port": 443, "network": "tcp,udp",
 "outbound": "anx-line:7"}
```

`network` is `tcp`, `udp` or `tcp,udp` (the default). A forward has no
users; `GET /v1/inbounds/{tag}/traffic?reset=true` answers its bytes in
`inbound` (`{"up", "down"}` since the last reset), and every inbound reports
the same. `outbound` names a base outbound the binary registered, such as
`anx-line:<link_id>` on anx-node; plain anixcore only has `direct`.
