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
- `proxy_protocol`: PROXY protocol versions 1 and 2. With
  `ServeSettings::accept_proxy_protocol` the accept loop reads the header a
  relay in front sent (`read_header`) before the protocol sees the stream
  and uses its addresses as the client's and the reached one; a connection
  without a valid header is closed. `ProxyProtocol::header` writes one, for
  forwards.
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
- `sing_mux` (internal): sing-mux, the `multiplex` of sing-box and `smux` of
  mihomo outbounds, for the protocols whose `Accepted` the serve loop relays
  (VLESS, VMess, Trojan, Shadowsocks, under TLS, REALITY or a transport): a
  client asks for `sp.mux.sing-box.arpa:444` and runs smux or yamux on the
  stream. Inbounds that connect their streams themselves (AnyTLS, Snell) do
  not serve it, and a stream of a QUIC inbound (Hysteria2, TUIC) carries
  TCP streams only. Each stream is relayed like a connection of its own
  (TCP through the outbound, UDP with or without packet addresses through
  the UDP outbound), with the user's traffic, speed limit, destination
  counts and QoS; at most 256 streams per connection, a stream counting
  until its relay has ended. h2mux, padding and TCP Brutal are not
  supported: such a connection is closed and counted as a failed handshake.
- `registry`: config `type` name to `InboundFactory`, one crate and cargo
  feature per protocol.

Errors and counters never contain credentials. `tests/serve_loop.rs` covers
traffic, online IPs, revocation and held rejections, `tests/sing_mux.rs` the
smux and yamux streams; all verification runs in
GitHub Actions.
