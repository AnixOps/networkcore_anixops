# tls-mimic

`tls-mimic` produces browser-shaped TLS 1.3 ClientHello messages (a uTLS-like
fingerprint layer) and runs a minimal TLS 1.3 client on top of them. It is the
shared fingerprint module for REALITY and any later protocol that needs to look
like a browser on the wire.

Fingerprints:

- `Fingerprint::Chrome` (default): desktop Chrome shape with GREASE cipher,
  group, version, signature scheme and extension values, per-connection
  permutation of all non-GREASE extensions, `X25519MLKEM768` + `X25519` key
  shares, ECH GREASE (`0xfe0d`), ALPS on the new code point (`0x44cd`), brotli
  certificate compression offer, and ALPN `h2`, `http/1.1`.
- `Fingerprint::ChromeNoPq`: the same without the post-quantum hybrid group.
- `Fingerprint::Safari`: Safari and every other client of Apple's network
  stack (NSURLSession) on iOS and macOS, taken from Safari 26.6.2 on macOS
  26.7.2: its own cipher order (with the CBC and 3DES suites), a fixed
  extension order, `X25519MLKEM768` + `X25519` key shares, zlib certificate
  compression offer, no ALPS, no ECH GREASE, no session ticket extension.
  `tests/data/` holds the captured ClientHello the contract test compares
  against.

`Fingerprint::platform_default()` (config name `auto`) is Safari on Apple
platforms and Chrome elsewhere: a Chrome ClientHello from a device whose
TCP/IP stack is Apple's is unusual, and on iOS it is the largest class of
client.

Fingerprints are data. Each built-in one is a JSON file under `fingerprints/`
(format in `src/profile.rs`: cipher suites, the ordered extension list with
its parameters, `"grease"` placeholders, whether extensions are permuted,
BoringSSL-style `padding`, and `raw` for an extension with a fixed body that
this crate has no name for). `install_profiles` replaces them for the process
with a delivered bundle:

```json
{ "format": 1, "revision": "2026-11-10", "profiles": { "chrome": { ... }, "safari": { ... } } }
```

so following a browser release means pushing a new bundle, not shipping a new
build. A bundle is validated as a whole (unknown keys, an extension type this
build cannot encode, or a ClientHello this client could not finish a handshake
from reject it and leave the previous state), profile names this build does not
know are skipped, and fingerprints the bundle does not name go back to their
built-in data. `node-runtime` (`tls_fingerprints` in the node config and
`PUT /v1/tls-fingerprints`) and `engine-embedded` (`tls_fingerprints` in the
runtime config) are the delivery points.

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
key (so REALITY servers derive the same auth key from either), and a profile
can only carry key shares for `X25519` and `X25519MLKEM768`. Validation is the contract test suite plus the
`REALITY interop (Linux)` CI job against OpenSSL, Xray-core and sing-box.

`tls_mimic::server` is the matching minimal TLS 1.3 server for REALITY-style
inbounds: the caller reads and inspects the ClientHello first
(`read_client_hello` keeps every consumed byte so the connection can be
replayed elsewhere), then `accept` finishes the handshake with an X25519 key
exchange and an Ed25519 certificate.
