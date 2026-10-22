# engine-embedded

In-process engine for the iOS Network Extension (roadmap M1a). It never starts a process and never touches Apple SDK objects; the Swift packet tunnel talks to it only through the C ABI.

- `ffi`: `networkcore_ios_*` C ABI, mirrored by `include/networkcore_ios_runtime.h`. Every symbol catches panics and returns a stable code that maps onto `platform.ios.embedded_runtime.*` diagnostics, following `docs/architecture/ios-embedded-runtime-ffi-boundary-design.md`.
- `EmbeddedRuntime`: parses and validates the JSON config envelope (`schema_version` 1), builds the outbound, owns the tunnel lifecycle and reports a sanitized status (profile id, state, counters; no addresses, keys or traffic).
- `tunnel`: one current-thread tokio runtime on a dedicated thread. Packets from `packetFlow` enter through `input_packet`; packets for `packetFlow` leave through the writer callback. TCP flows go through the outbound; UDP/53 is re-sent as DNS-over-TCP through the outbound; other UDP is dropped so QUIC falls back to TCP.
- Outbounds implement `engine_outbound::TcpOutbound`: `shadowsocks` (Shadowsocks-2022, single PSK) and `direct`. A new protocol plugs in without changing the tunnel.

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

`dns` and `limits` are optional. The defaults keep the worst case near 128 flows × (2 × 64 KiB window + relay and cipher buffers), about 25 MiB, inside the roughly 50 MiB Network Extension limit. Real peak memory is measured on an iPhone during M1 acceptance.

Tests: `tests/shadowsocks_interop.rs` checks the client against the shadowsocks-rust server (Unix only, dev-dependency), `tests/tunnel_packets.rs` drives raw IP packets through the stack, and `tests/ffi_contracts.rs` exercises the C ABI. All verification runs in GitHub Actions.
