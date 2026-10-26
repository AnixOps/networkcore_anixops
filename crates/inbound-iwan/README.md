# inbound-iwan

Panabit iWAN server inbound for the node kernel, built on `engine-inbound`
and the packet codec of `outbound-iwan`. Implemented only from
`docs/protocols/iwan.md` §12 (clean room).

- One UDP port serves every user. Clients log in with `username` (or the
  user's `name`) and `password` (1–16 bytes); failures get OPENREJ. Login
  names and fixed addresses are unique: adding a user that reuses one fails. A new
  login of the same user or from the same source replaces the old session;
  sessions end after 60 s without packets, on CLOSE or when the user is
  removed.
- Addresses come from `pool`; its first address is the gateway (ping and
  DNS on UDP 53, relayed to `dns_upstream`). Users get their last address
  back for 10 minutes after a session ends; a user's `address` fixes it.
- One userspace TCP/IP stack per inbound terminates the tunnelled TCP and UDP
  for any destination and relays each connection through the node's router,
  charged to the user, so the panel's domain egress routes apply (SNI /
  HTTP `Host`, or the DNS answers relayed for the client).
- Packets with a source other than the session's address are dropped;
  packets to other users' addresses only pass with
  `allow_client_to_client`.
- Config: `{"type": "iwan", "pool": "10.66.0.0/16", "mtu": 1400,
  "dns_upstream": "1.1.1.1", "allow_client_to_client": false,
  "allow_encrypt": true, "users": [{"name": "1001", "username": "alice",
  "password": "...", "address": "10.66.0.9"}]}`.

iWAN has no confidentiality or integrity (spec §9).

`tests/end_to_end.rs` runs the `outbound-iwan` client and raw datagrams
against the server.
