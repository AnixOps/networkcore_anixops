# tls-mimic

`tls-mimic` produces browser-shaped TLS 1.3 ClientHello messages (a uTLS-like
fingerprint layer) and runs a minimal TLS 1.3 client on top of them. It is the
shared fingerprint module for REALITY and any later protocol that needs to look
like a browser on the wire.

Fingerprints:

- `Fingerprint::Chrome` (default): desktop Chrome shape with GREASE cipher,
  group, version and extension values, per-connection permutation of all
  non-GREASE extensions, `X25519MLKEM768` + `X25519` key shares, ECH GREASE
  (`0xfe0d`), ALPS on the new code point (`0x44cd`), brotli certificate
  compression offer, and ALPN `h2`, `http/1.1`.
- `Fingerprint::ChromeNoPq`: the same without the post-quantum hybrid group.

The client supports only what these protocols need: TLS 1.3 full handshakes
with `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384` and
`TLS_CHACHA20_POLY1305_SHA256`; `X25519` and `X25519MLKEM768`; Ed25519, ECDSA
P-256/P-384 and RSA-PSS CertificateVerify; KeyUpdate. It rejects TLS 1.2,
HelloRetryRequest, client certificates and compressed certificates, and never
resumes sessions.

Trust is decided by the caller through `HandshakeHooks`:
`edit_client_hello` may rewrite the encoded ClientHello (REALITY uses the
session id) and `verify_server_certificates` must accept the chain. The crate
does not ship a WebPKI verifier yet, so it must not be used for ordinary HTTPS
until one is added. `TlsStream` can hand the raw transport over one direction
at a time (`start_raw_read` / `start_raw_write`) for XTLS Vision.

Known fingerprint limits: the hybrid and standalone key shares reuse one X25519
key (so REALITY servers derive the same auth key from either), and no TLS
padding extension is sent. Validation is the contract test suite plus the
`REALITY interop (Linux)` CI job against OpenSSL, Xray-core and sing-box.

`tls_mimic::server` is the matching minimal TLS 1.3 server for REALITY-style
inbounds: the caller reads and inspects the ClientHello first
(`read_client_hello` keeps every consumed byte so the connection can be
replayed elsewhere), then `accept` finishes the handshake with an X25519 key
exchange and an Ed25519 certificate.
