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
  path for TLS or QUIC transports, and `ConnectionContext::new` gives a
  transport that accepts connections itself the context of the serve loop.
- `proxy_protocol`: PROXY protocol versions 1 and 2. With
  `ServeSettings::accept_proxy_protocol` the accept loop reads the header a
  relay in front sent (`read_header`) before the protocol sees the stream
  and uses its addresses as the client's and the reached one; a connection
  without a valid header is closed. `ProxyProtocol::header` writes one, for
  forwards.
- `fallback`: where an inbound that fronts for web servers (VLESS, Trojan,
  AnyTLS) relays a connection that is not its protocol's. `Fallbacks` holds
  the rules of `"fallbacks"` (`name`: server name of the TLS or REALITY
  handshake, `alpn`: its ALPN protocol, `path`: path of the HTTP/1.x request
  the connection starts with, `dest`: `host:port` or a local port, `xver`:
  PROXY protocol version written to the destination) and the single
  `"fallback"` as the rule without conditions. Of the matching rules the one
  with the most conditions wins, the earlier one of equals; without a match
  the connection is held. The conditions read a `ConnInfo`, which the serve
  loop (`StreamInbound::accept_with`, `ConnectionContext::conn`) fills with
  the addresses and the TLS layer with the server name and ALPN; behind a
  transport such as WebSocket only `path` and the default can match.
- `udp`: UDP egress (`UdpOutbound`, implemented by the node's direct
  outbound) and relays. Protocols that carry datagrams on the client stream
  (Trojan UDP associate, VLESS/VMess UDP) set `Accepted::udp` to their
  `DatagramCodec`; the serve loop (`serve_with_udp`) opens a session, relays
  both ways, charges payload bytes and ends the session when idle for two
  minutes or when the user is removed. Without a UDP outbound, UDP requests
  are refused. `SessionRelay` keeps one socket per protocol session id for
  QUIC protocols (Hysteria2, TUIC; `PacketInbound::serve` takes the UDP
  outbound) and Shadowsocks UDP (`StreamInbound::datagram`, same port).
  `StreamInbound::packet` is the QUIC side of a stream inbound on the UDP
  port of the same number (XHTTP over HTTP/3).
- `mux` (internal): Mux.Cool for VLESS/VMess command 3. A protocol sets
  `Accepted::mux`; the serve loop then runs TCP sessions through the outbound
  and UDP sessions (XUDP, per-datagram addresses) through the UDP outbound on
  the one client stream, at most 128 sessions per connection.
- `sing_mux` (internal): sing-mux, the `multiplex` of sing-box and `smux` of
  mihomo outbounds, for the protocols whose `Accepted` the serve loop relays
  (VLESS, VMess, Trojan, Shadowsocks, under TLS, REALITY or a transport): a
  client asks for `sp.mux.sing-box.arpa:444` and runs smux, yamux or h2mux
  (the clients' default: HTTP/2 on the stream as it is, a CONNECT request
  per stream, served with the `h2` crate) on the stream, padded for its
  first 16 writes each way when the session request asks for padding.
  Inbounds that connect their streams themselves (AnyTLS, Snell) do not
  serve it, and a stream of a QUIC inbound (Hysteria2, TUIC) carries TCP
  streams only. Each stream is relayed like a connection of its own (TCP
  through the outbound, UDP with or without packet addresses through the
  UDP outbound), with the user's traffic, speed limit, destination counts
  and QoS; at most 256 streams per connection, a stream counting until its
  relay has ended. TCP Brutal is not negotiated.
- `shadow_tls`: a ShadowTLS v3 server in front of a protocol inbound
  (`shadow_tls::wrap`, from a `"shadow_tls"` object in the inbound's
  settings; the Shadowsocks factory takes one). It relays the client's TLS
  handshake record by record to the `handshake` site through the inbound's
  outbound, finds the client by the HMAC-SHA1 tag in its ClientHello
  session id, marks the site's ApplicationData records (XOR with
  SHA-256(password ‖ ServerRandom), a four-byte tag of a running HMAC in
  front) and, from the client's first tagged record on, carries the wrapped
  protocol in tagged ApplicationData records. A record with a wrong tag is
  answered with what an encrypted alert looks like and the connection ends.
  Everything that is not a ShadowTLS client (no TLS, a ClientHello signed
  with no known password, with `strict_mode` a site that does not answer in
  TLS 1.3) is relayed to the site unchanged. Clients share one `password`,
  or `users` gives each a password: those users are then the inbound's
  (added and removed at runtime, charged, limited), the wrapped protocol
  must have none of its own, and its UDP side stays closed. Versions 1 and
  2, a handshake site per server name and wildcard SNI are not implemented.
- `registry`: config `type` name to `InboundFactory`, one crate and cargo
  feature per protocol.

Errors and counters never contain credentials. The fallback matcher has unit
tests in `src/fallback.rs`, and `node-runtime`'s `tests/fallbacks.rs` runs
it behind TLS. `tests/serve_loop.rs` covers
traffic, online IPs, revocation and held rejections, `tests/sing_mux.rs` the
smux, yamux and h2mux streams and a padded session, `tests/shadow_tls.rs`
a ShadowTLS session, its fallbacks and the alert; all verification runs
in GitHub Actions.
