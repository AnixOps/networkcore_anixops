# inbound-naive

NaiveProxy server inbound for the node kernel, built on `engine-inbound`:
an HTTP/2 `CONNECT` proxy inside TLS, for NaiveProxy clients and sing-box's
`naive` outbound. Written from the protocol's public description; HTTP/2 is
the `h2` crate.

- A client authenticates every `CONNECT` with `proxy-authorization: Basic`.
  The login name is the user's `username`, or its `name` without one;
  traffic, speed and device limits and online IPs are per user, and users
  can be added and removed at runtime. One client connection carries many
  tunnels (at most 256 at once).
- Payload padding (`src/padding.rs`): the first eight reads and writes of a
  tunnel are framed in each direction as `payload length (u16) | padding
  length (u8) | payload | zeros`, with 0 to 255 bytes of padding. A client
  asks for it with `padding-type-request` (answered in
  `padding-type-reply`) or, before those headers existed, with a `padding`
  header alone; a client that sends neither gets a plain tunnel. Every
  `200` carries a `padding` header of 30 to 62 random symbols, so the
  HEADERS frame varies in size. Only payload is charged to the user.
- A target that cannot be connected gets `502`.
- Anything else gets the decoy treatment. A connection that does not start
  with the HTTP/2 preface (an HTTP/1.1 client, a prober) is relayed to the
  `fallback` unchanged; without a fallback it is held open and drained. A
  request on an HTTP/2 connection that is not a `CONNECT` with a known
  user's credentials is repeated to the fallback over cleartext HTTP/2 and
  answered with its response; without a fallback it is held unanswered for
  the reject hold time and then reset. The fallback therefore has to speak
  HTTP/1.1 and cleartext HTTP/2 (prior knowledge) on its port, as nginx
  with `http2 on` and Caddy with `h2c` do.
- Config: `{"type": "naive", "users": [{"name": "...", "username": "...",
  "password": "..."}], "tls": {...}, "fallback": {"server": "127.0.0.1",
  "server_port": 8080}}`. Without `tls.alpn` the inbound offers `h2` and
  `http/1.1`. `tls` is optional for deployments behind a TLS terminator
  that passes HTTP/2 through.

Not included: HTTP/3 (QUIC), UDP, sing-mux, and HTTP/1.1 `CONNECT`.

`tests/naive_inbound.rs` runs a client written from the protocol (the `h2`
client and hand-made padding) against the server; the client interop table
of `node-runtime` runs sing-box's `naive` outbound against it.
