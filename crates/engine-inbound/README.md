# engine-inbound

Server-side inbound interfaces for running NetworkCore as a node kernel (the
kernel that anix-agent drives on a proxy server). It mirrors `engine-outbound`:

- `StreamInbound`: a protocol takes an accepted client stream, authenticates
  the user and returns `Accepted { user, target, stream }`, or `Rejected`
  (optionally asking the serve loop to hold the connection and discard input,
  so a failed handshake is not an obvious probe signal).
- `UserStore`: the users of one inbound, keyed by name. Users can be added,
  replaced and removed while the inbound runs; removing a user closes its open
  connections. `traffic(reset)` reports per-user bytes (traffic of removed users
  is kept until it is collected once), `online()` reports open connections per
  user and remote IP. `UserIndex` gives a protocol a cached credential lookup.
- `server::serve`: TCP accept loop with a connection cap and handshake/connect
  timeouts that relays every accepted stream through an
  `engine_outbound::TcpOutbound` (direct or routed) and charges bytes to the
  user as they move. `server::handle_connection` is the same per-connection
  path for TLS or QUIC transports.
- `registry`: config `type` name to `InboundFactory`, one crate and cargo
  feature per protocol.

Errors and counters never contain credentials. `tests/serve_loop.rs` covers
traffic, online IPs, revocation and held rejections; all verification runs in
GitHub Actions.
