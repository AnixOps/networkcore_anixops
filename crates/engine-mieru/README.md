# engine-mieru

`engine-mieru` is the external-core adapter boundary for Mieru. It does not
copy Mieru source, bundle a Mieru binary, or silently download a release.

The current source-only slice provides:

- structured `mierus://` parsing for credentials, server/authority or query
  port, repeated TCP ports, port range,
  MTU, multiplexing, handshake mode, and traffic pattern;
- a redacted debug representation and a `Protocol::Mieru` node descriptor;
- explicit local executable SHA-256 verification;
- official-shape TCP client JSON rendering with a loopback SOCKS5 port,
  including user/server/port-binding, MTU, multiplexing, and handshake fields;
- a cross-platform child-process supervisor whose executable, arguments,
  working directory, log path, and expected digest are caller supplied.
- a local SOCKS5 readiness report that requires both a live child process and
  a reachable listener; a PID alone is never reported as ready.

The renderer deliberately keeps traffic-pattern metadata as a deferred
diagnostic until the official protobuf representation is decoded; it does not
claim that option is active. Official-release download and the Linux/Windows
CLI/service wiring remain separate follow-up work. A process is not considered
ready from a PID alone; the caller must verify the local listener and any Mieru
control/API evidence before reporting a connected state.
