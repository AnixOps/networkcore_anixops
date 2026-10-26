# anixcore

The AnixOps node kernel: protocol server inbounds (Shadowsocks-2022, Trojan,
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

The config format is documented in `crates/node-runtime/src/config.rs` and
the API in `crates/node-runtime/src/api.rs`. Users relay through a direct
outbound that refuses loopback and private targets unless
`"allow_private_targets": true`.

Domain egress routes from the panel (anix-control 「转发 → 分流」) are applied
with `PUT /v1/egress` (or the config member `egress`): the route's domains
leave through the exit node's Shadowsocks-2022 relay, for every inbound, and
an exit node serves the relays. See `crates/node-runtime/src/egress.rs`.
