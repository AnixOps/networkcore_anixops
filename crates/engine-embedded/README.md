# engine-embedded

In-process engine for the iOS Network Extension (roadmap M1a). It never starts a process and never touches Apple SDK objects; the Swift packet tunnel talks to it only through the C ABI.

- `ffi`: `networkcore_ios_*` C ABI, mirrored by `include/networkcore_ios_runtime.h`. Every symbol catches panics and returns a stable code that maps onto `platform.ios.embedded_runtime.*` diagnostics, following `docs/architecture/ios-embedded-runtime-ffi-boundary-design.md`.
- `EmbeddedRuntime`: parses and validates the JSON config envelope (`schema_version` 1), builds the outbound, owns the tunnel lifecycle and reports a sanitized status (profile id, state, counters; no addresses, keys or traffic).
- `tunnel`: one current-thread tokio runtime on a dedicated thread. Packets from `packetFlow` enter through `input_packet`; packets for `packetFlow` leave through the writer callback. TCP flows go through the outbound; UDP/53 is re-sent as DNS-over-TCP through the outbound; other UDP goes through the outbound's `open_udp`, one flow per app socket and destination (at most 256, closed after 60 s without traffic). An outbound without UDP drops those datagrams, so QUIC falls back to TCP. UDP currently works through `direct`, routing rules and groups, VMess, Hysteria2, TUIC, Snell, Trojan and VLESS.
- Outbounds implement `engine_outbound::TcpOutbound` and are built by the protocol registry (`engine_outbound::registry`) from the config `type`: `shadowsocks` (Shadowsocks-2022 and AEAD `aes-128-gcm`/`aes-256-gcm`/`chacha20-ietf-poly1305`, from `outbound-shadowsocks`), `vless` (VLESS over REALITY with optional XTLS Vision, or over TCP/standard TLS with an optional WebSocket, from `outbound-vless`), `vmess` (VMess AEAD over TCP/TLS/WebSocket, from `outbound-vmess`), `hysteria2` and `tuic` (TCP over QUIC, from `outbound-hysteria2` and `outbound-tuic`), `snell` (from `outbound-snell`), `mieru` (from `outbound-mieru`), `trojan`, `socks`, `http` and `direct`. A new protocol plugs in without changing the tunnel.
- `wireguard`: a packet-level mode for one WireGuard peer. Packets skip the TCP/IP stack and are sealed with boringtun's Noise state machine (BSD-3-Clause, `device` feature off) into datagrams on one connected UDP socket; the extension's routes apply the peer's `AllowedIPs`. Buffers stay under 0.5 MiB.

## Protocol modules

Each protocol is its own crate behind a cargo feature; `src/protocols.rs` registers the enabled ones. The default build enables all of them.

| feature | config `type` | crate |
| --- | --- | --- |
| (always) | `direct` | this crate |
| `http` | `http` (HTTP CONNECT proxy, optional TLS and Basic auth) | `outbound-http` |
| `hysteria2` | `hysteria2` (QUIC + HTTP/3 password auth, TCP streams; optional `"obfs": {"type": "salamander", "password": ...}`; no port hopping yet) | `outbound-hysteria2` (QUIC from `transport-quic`) |
| `mieru` | `mieru` (Mieru over TCP, `username`, `password`, optional `port_range` `low-high`; one session per connection, no UDP transport, multiplexing or low entropy segments yet) | `outbound-mieru` (clean-room from `docs/protocols/mieru.md`) |
| `shadowsocks` | `shadowsocks` (`method` `2022-blake3-*` or an AEAD method) | `outbound-shadowsocks` |
| `snell` | `snell` (Snell v1–v4 and v6, `psk`, `version`, v6 `mode` `default`/`unshaped`/`unsafe-raw`, `obfs` `http` for v1–v4, `reuse`, `userkey`; TCP, UDP over TCP in the crate API) | `outbound-snell` (clean-room from `docs/protocols/snell.md`) |
| `socks` | `socks` (SOCKS5, optional username/password) | `outbound-socks` |
| `tuic` | `tuic` (TUIC v5: UUID + password, `congestion_control` `cubic`/`new_reno`/`bbr`; TCP only) | `outbound-tuic` (QUIC from `transport-quic`) |
| `trojan` | `trojan` (TCP, or `"transport": {"type": "ws"}` / `{"type": "grpc", "service_name": ...}`) | `outbound-trojan` (TLS from `transport-tls`, WebSocket from `transport-ws`, gRPC from `transport-grpc`) |
| `vless` | `vless` (`reality`, or `tls` and/or `"transport": {"type": "ws"}` / `{"type": "grpc"}`) | `outbound-vless` |
| `vmess` | `vmess` (AEAD, alterId 0; `security` `auto`/`aes-128-gcm`/`chacha20-poly1305`; optional `tls` and `"transport": {"type": "ws"}` / `{"type": "grpc"}`) | `outbound-vmess` |
| `wireguard` | `wireguard` | this crate + boringtun |
| `local-proxy` | (desktop mode, not a protocol) | `inbound-mixed` |

`cargo build -p engine-embedded --no-default-features --features vless` builds a runtime with only VLESS and direct; any other `type` is rejected with `config_rejected`. To add a protocol: create an `outbound-<name>` crate that implements `TcpOutbound` and `engine_outbound::registry::OutboundFactory`, add it as an optional dependency with a feature here, and register its factory in `protocols::default_registry`. `EmbeddedRuntime::with_registry` accepts a caller-built registry, for protocol crates kept outside this repository. The CI job `Protocol feature matrix` builds, lints and runs the C ABI contract tests with each feature alone.

## Desktop local proxy

`local_proxy::LocalProxy::start(config, listen, settings)` takes the same config envelope and serves its outbound (single or `routing`) behind a SOCKS5/HTTP mixed listener from `inbound-mixed`, on its own thread and tokio runtime. Because applications hand the proxy a host name, domain rules match without FakeIP. WireGuard is a packet tunnel and is rejected in this mode. Bind it to loopback; `tests/local_proxy.rs` covers direct, routed and failure cases.

`routing.rule_sets` carries named lists for `RULE-SET,<name>,<target>` rules: `{"china": {"domain_suffix": [...], "ip_cidr": [...]}}`, up to 16 sets and 500,000 entries in all. A set is one rule, matched by a hash lookup per domain suffix and a binary search over merged networks, so a list the size of the mainland China domains costs the same per connection as a short one. Its networks match only a destination that is already an address; a domain is never resolved for them. A rule naming a set the envelope does not carry is rejected.

## HTTPS decryption (MITM)

The default `mitm` feature lets the packet tunnel decrypt HTTPS for host names listed in a plugin's `[MITM]` section. Add an optional `mitm` object to the config envelope:

| Field | Meaning |
| --- | --- |
| `policy` | Optional plugin text (`[URL Rewrite]`, `[Header Rewrite]`, `[Map Local]`, `[MITM]`) evaluated by the same rewrite engine as the desktop proxy (`engine-native` hook plus the `mitm-policy` core). |
| `plugins` | Optional Loon plugin texts. Each is imported with `mitm_policy::loon_plugin` and merged with `policy` into one policy (`merged_plugin_source`): rewrite sections keep plugin order and `[MITM]` hostname lists are combined, with an excluded host staying excluded. A plugin the policy core refuses is left out; `[Rule]` lines are not applied here. |
| `ca_certificate` | Base64 DER of the device root that the iOS app generates and the user trusts. |
| `ca_private_key` | Base64 X9.63 P-256 private key (`04 ‖ X ‖ Y ‖ D`), as `SecKeyCopyExternalRepresentation` returns it. |

TCP flows to port 443 whose ClientHello SNI matches the hostname list are terminated with a per-host leaf signed by that root, re-encrypted to the origin through the configured outbound, and parsed as HTTP/1.1 so rewrite rules can reject, redirect, rewrite headers or answer locally. Only `http/1.1` is offered over ALPN. Requests ask for `Accept-Encoding: identity`; bodies over 1 MiB, server-sent events and protocol upgrades are relayed unchanged. Other flows are untouched. Tunnel stats count `mitm_flows` and `mitm_failed`. A build without the feature rejects a config that has a `mitm` section. `tests/mitm.rs` runs a client, the engine and a TLS origin over in-memory streams.

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

Tests: `crates/outbound-shadowsocks/tests/shadowsocks_interop.rs` and `aead_interop.rs` check the Shadowsocks-2022 and AEAD clients against the shadowsocks-rust server (Unix only, dev-dependency), `tests/tunnel_packets.rs` drives raw IP packets through the stack, `tests/wireguard_packets.rs` round-trips packets through an in-process boringtun peer, and `tests/ffi_contracts.rs` exercises the C ABI. All verification runs in GitHub Actions.
