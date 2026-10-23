# engine-embedded

In-process engine for the iOS Network Extension (roadmap M1a). It never starts a process and never touches Apple SDK objects; the Swift packet tunnel talks to it only through the C ABI.

- `ffi`: `networkcore_ios_*` C ABI, mirrored by `include/networkcore_ios_runtime.h`. Every symbol catches panics and returns a stable code that maps onto `platform.ios.embedded_runtime.*` diagnostics, following `docs/architecture/ios-embedded-runtime-ffi-boundary-design.md`.
- `EmbeddedRuntime`: parses and validates the JSON config envelope (`schema_version` 1), builds the outbound, owns the tunnel lifecycle and reports a sanitized status (profile id, state, counters; no addresses, keys or traffic).
- `tunnel`: one current-thread tokio runtime on a dedicated thread. Packets from `packetFlow` enter through `input_packet`; packets for `packetFlow` leave through the writer callback. TCP flows go through the outbound; UDP/53 is re-sent as DNS-over-TCP through the outbound; other UDP is dropped so QUIC falls back to TCP.
- Outbounds implement `engine_outbound::TcpOutbound`: `shadowsocks` (Shadowsocks-2022, single PSK), `vless` (VLESS over REALITY with optional XTLS Vision, from `outbound-vless`) and `direct`. A new protocol plugs in without changing the tunnel.
- `wireguard`: a packet-level mode for one WireGuard peer. Packets skip the TCP/IP stack and are sealed with boringtun's Noise state machine (BSD-3-Clause, `device` feature off) into datagrams on one connected UDP socket; the extension's routes apply the peer's `AllowedIPs`. Buffers stay under 0.5 MiB.

Config envelope:

```json
{
  "schema_version": 1,
  "profile_id": "node-1",
  "mtu": 1500,
  "outbound": {
    "type": "shadowsocks",
    "server": "example.com",
    "port": 8388,
    "method": "2022-blake3-aes-128-gcm",
    "password": "<base64 PSK>"
  },
  "dns": { "upstream": "1.1.1.1:53", "timeout_ms": 5000 },
  "limits": {
    "max_tcp_connections": 128,
    "max_dns_in_flight": 32,
    "tcp_window_bytes": 65536,
    "idle_timeout_secs": 300,
    "connect_timeout_secs": 10
  }
}
```

A VLESS + REALITY outbound uses the same envelope with:

```json
"outbound": {
  "type": "vless",
  "server": "example.com",
  "port": 443,
  "uuid": "<uuid>",
  "flow": "xtls-rprx-vision",
  "reality": {
    "server_name": "www.example.com",
    "public_key": "<pbk>",
    "short_id": "<sid>",
    "fingerprint": "chrome"
  }
}
```

`flow` may be empty for plain VLESS; `short_id` defaults to empty and `fingerprint` to `chrome` (`chrome-nopq` drops the post-quantum key share). The uuid, like the Shadowsocks password, comes from the Keychain and never appears in status.

A WireGuard envelope replaces `outbound` with the fields of one `wg-quick` peer (keys are standard base64; `preshared_key` and `persistent_keepalive_secs` are optional, `dns` and `limits` are ignored):

```json
"outbound": {
  "type": "wireguard",
  "private_key": "<base64>",
  "peer_public_key": "<base64>",
  "preshared_key": "<base64>",
  "server": "vpn.example.com",
  "port": 51820,
  "persistent_keepalive_secs": 25
}
```

`dns` and `limits` are optional. The defaults keep the worst case near 128 flows × (2 × 64 KiB window + relay and cipher buffers), about 25 MiB, inside the roughly 50 MiB Network Extension limit. Real peak memory is measured on an iPhone during M1 acceptance.

Tests: `tests/shadowsocks_interop.rs` checks the client against the shadowsocks-rust server (Unix only, dev-dependency), `tests/tunnel_packets.rs` drives raw IP packets through the stack, `tests/wireguard_packets.rs` round-trips packets through an in-process boringtun peer, and `tests/ffi_contracts.rs` exercises the C ABI. All verification runs in GitHub Actions.
