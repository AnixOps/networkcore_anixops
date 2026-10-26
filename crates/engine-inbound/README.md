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
- `udp`: UDP egress (`UdpOutbound`, implemented by the node's direct
  outbound) and relays. Protocols that carry datagrams on the client stream
  (Trojan UDP associate, VLESS/VMess UDP) set `Accepted::udp` to their
  `DatagramCodec`; the serve loop (`serve_with_udp`) opens a session, relays
  both ways, charges payload bytes and ends the session when idle for two
  minutes or when the user is removed. Without a UDP outbound, UDP requests
  are refused. `SessionRelay` keeps one socket per protocol session id for
  QUIC protocols (Hysteria2, TUIC; `PacketInbound::serve` takes the UDP
  outbound) and Shadowsocks UDP (`StreamInbound::datagram`, same port).
- `mux` (internal): Mux.Cool for VLESS/VMess command 3. A protocol sets
  `Accepted::mux`; the serve loop then runs TCP sessions through the outbound
  and UDP sessions (XUDP, per-datagram addresses) through the UDP outbound on
  the one client stream, at most 128 sessions per connection.
- `registry`: config `type` name to `InboundFactory`, one crate and cargo
  feature per protocol.

Errors and counters never contain credentials. `tests/serve_loop.rs` covers
traffic, online IPs, revocation and held rejections; all verification runs in
GitHub Actions.
