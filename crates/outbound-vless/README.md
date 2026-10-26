# outbound-vless

`outbound-vless` is the VLESS outbound for the embedded engine (M1b). It
implements `engine_outbound::TcpOutbound` as VLESS over REALITY, with optional
XTLS Vision (`xtls-rprx-vision`).

- **REALITY client** (`reality`): the ClientHello comes from `tls-mimic`; the
  session id carries the AES-256-GCM sealed version, timestamp and short id
  under `HKDF-SHA256(X25519(ephemeral, server key), random[..20], "REALITY")`.
  The server must answer with an Ed25519 certificate whose signature equals
  `HMAC-SHA512(auth_key, public_key)`; anything else (for example the real
  camouflage site) fails the connection with `PermissionDenied` before any
  VLESS byte is sent.
- **VLESS** (`protocol`): version 0 request header with the Vision addon, TCP
  command, IPv4/IPv6/domain targets. The header is sent with the first payload.
- **Vision** (`vision`): padding frames with the user UUID prefix, inner TLS
  detection (ClientHello/ServerHello, TLS 1.3 with a non-CCM8 suite), and
  direct copy: after the `direct` command each direction leaves the outer TLS
  and inner TLS 1.3 records travel over the raw transport.

Inputs use the share-link encodings: UUID in hyphenated hex, REALITY public key
in base64 (URL-safe or standard, padding optional) and short id in hex. UDP
uses VLESS command 2 (`open_udp`): one connection per flow, no flow addon even
for Vision users, each datagram a big-endian `u16` length plus payload. XUDP
(Mux.Cool) is not implemented. Credentials are redacted from
`Debug` output and never placed in error messages.

The `reality_interop` tests are ignored by default and run in the
`REALITY interop (Linux)` CI job against Xray-core and sing-box servers.
Whether a given server survives real-world censorship still needs manual
validation on real networks.
