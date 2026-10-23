# inbound-mixed

Local mixed inbound: SOCKS5 and HTTP proxy requests on one port, relayed through any `engine_outbound::TcpOutbound` (a single protocol outbound or a routed one). It replaces the `mixed` inbound that the desktop clients got from an external engine.

- SOCKS5 (RFC 1928) `CONNECT`, no auth or username/password (RFC 1929). `BIND` and `UDP ASSOCIATE` answer "command not supported".
- HTTP/1.x `CONNECT` tunnels and absolute-form plain requests, forwarded in origin form with `Connection: close`; optional `Proxy-Authorization: Basic`.
- The first byte picks the protocol. Request heads are capped at 16 KiB; handshake and connect timeouts and a connection cap come from `MixedSettings`. Counters in `MixedStats` carry no addresses or contents.

Bind it to loopback. `tests/mixed_proxy.rs` covers both protocols end to end; all verification runs in GitHub Actions.
