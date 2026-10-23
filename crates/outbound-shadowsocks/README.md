# outbound-shadowsocks

Shadowsocks-2022 (SIP022) TCP client outbound: `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm` and `2022-blake3-chacha20-poly1305`, with SIP022 multi-user identity headers (`iPSK:...:uPSK`) on the AES methods.

`ShadowsocksFactory` registers it under config `"type": "shadowsocks"` in an `engine_outbound::registry::OutboundRegistry`; `engine-embedded` links it through its `shadowsocks` feature.

`tests/shadowsocks_interop.rs` runs the client against the shadowsocks-rust server (Unix only, dev-dependency). All verification runs in GitHub Actions.
