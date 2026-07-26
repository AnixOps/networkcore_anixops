# engine-mieru

`engine-mieru` is the external-core adapter boundary for Mieru. It does not
copy Mieru source, bundle a Mieru binary, or silently download a release.

The current source-only slice provides:

- structured `mierus://` parsing for credentials, server/port, port range,
  MTU, multiplexing, handshake mode, and traffic pattern;
- a redacted debug representation and a `Protocol::Mieru` node descriptor;
- explicit local executable SHA-256 verification;
- a cross-platform child-process supervisor whose executable, arguments,
  working directory, log path, and expected digest are caller supplied.

Official-release download and the Linux/Windows CLI/service wiring remain
separate follow-up work. A process is not considered ready from a PID alone;
the caller must verify the local listener and any Mieru control/API evidence
before reporting a connected state.
