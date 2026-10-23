# engine-embedded

In-process engine for the iOS Network Extension (roadmap M1a). It never starts a process and never touches Apple SDK objects; the Swift packet tunnel talks to it only through the C ABI.

- `ffi`: `networkcore_ios_*` C ABI, mirrored by `include/networkcore_ios_runtime.h`. Every symbol catches panics and returns a stable code that maps onto `platform.ios.embedded_runtime.*` diagnostics, following `docs/architecture/ios-embedded-runtime-ffi-boundary-design.md`.
- `EmbeddedRuntime`: parses and validates the JSON config envelope (`schema_version` 1), builds the outbound, owns the tunnel lifecycle and reports a sanitized status (profile id, state, counters; no addresses, keys or traffic).
- `tunnel`: one current-thread tokio runtime on a dedicated thread. Packets from `packetFlow` enter through `input_packet`; packets for `packetFlow` leave through the writer callback. TCP flows go through the outbound; UDP/53 is re-sent as DNS-over-TCP through the outbound; other UDP is dropped so QUIC falls back to TCP.
- Outbounds implement `engine_outbound::TcpOutbound` and are built by the protocol registry (`engine_outbound::registry`) from the config `type`: `shadowsocks` (Shadowsocks-2022, from `outbound-shadowsocks`), `vless` (VLESS over REALITY with optional XTLS Vision, from `outbound-vless`) and `direct`. A new protocol plugs in without changing the tunnel.
- `wireguard`: a packet-level mode for one WireGuard peer. Packets skip the TCP/IP stack and are sealed with boringtun's Noise state machine (BSD-3-Clause, `device` feature off) into datagrams on one connected UDP socket; the extension's routes apply the peer's `AllowedIPs`. Buffers stay under 0.5 MiB.

## Protocol modules

Each protocol is its own crate behind a cargo feature; `src/protocols.rs` registers the enabled ones. The default build enables all of them.

| feature | config `type` | crate |
| --- | --- | --- |
| (always) | `direct` | this crate |
| `shadowsocks` | `shadowsocks` | `outbound-shadowsocks` |
| `vless` | `vless` | `outbound-vless` |
| `wireguard` | `wireguard` | this crate + boringtun |
| `local-proxy` | (desktop mode, not a protocol) | `inbound-mixed` |

`cargo build -p engine-embedded --no-default-features --features vless` builds a runtime with only VLESS and direct; any other `type` is rejected with `config_rejected`. To add a protocol: create an `outbound-<name>` crate that implements `TcpOutbound` and `engine_outbound::registry::OutboundFactory`, add it as an optional dependency with a feature here, and register its factory in `protocols::default_registry`. `EmbeddedRuntime::with_registry` accepts a caller-built registry, for protocol crates kept outside this repository. The CI job `Protocol feature matrix` builds, lints and runs the C ABI contract tests with each feature alone.

## Desktop local proxy

`local_proxy::LocalProxy::start(config, listen, settings)` takes the same config envelope and serves its outbound (single or `routing`) behind a SOCKS5/HTTP mixed listener from `inbound-mixed`, on its own thread and tokio runtime. Because applications hand the proxy a host name, domain rules match without FakeIP. WireGuard is a packet tunnel and is rejected in this mode. Bind it to loopback; `tests/local_proxy.rs` covers direct, routed and failure cases.

## Config envelope



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

Tests: `crates/outbound-shadowsocks/tests/shadowsocks_interop.rs` checks the Shadowsocks client against the shadowsocks-rust server (Unix only, dev-dependency), `tests/tunnel_packets.rs` drives raw IP packets through the stack, `tests/wireguard_packets.rs` round-trips packets through an in-process boringtun peer, and `tests/ffi_contracts.rs` exercises the C ABI. All verification runs in GitHub Actions.
