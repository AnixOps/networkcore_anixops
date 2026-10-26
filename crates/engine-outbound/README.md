# engine-outbound

`engine-outbound` holds the pluggable outbound interfaces shared by the
embedded engine (`engine-embedded`, iOS/macOS Network Extension) and the
protocol crates that plug into it (Shadowsocks-2022, VLESS + REALITY, and
later WireGuard and private protocols).

It contains interfaces only, plus the default `TcpDialer`:

- `TargetAddr`: IP socket address or domain plus port, with `port()`,
  `host()` and `From<SocketAddr>`.
- `ProxyStream` / `BoxStream`: a `Send + Unpin` tokio `AsyncRead + AsyncWrite`
  stream, type-erased.
- `Dialer`: opens the transport connection to a proxy server. Outbounds receive
  an `Arc<dyn Dialer>` when they are constructed, so the Network Extension can
  inject a dialer bound to the physical interface.
- `TcpOutbound`: `protocol()` tag, `connect(&TargetAddr)` and
  `open_udp(&TargetAddr)`, which returns a `UdpFlow` (a `DatagramSend` and a
  `DatagramRecv` half) to one destination. Protocols without UDP keep the
  default `open_udp`, which fails with `ErrorKind::Unsupported`.
  `UdpFlow::message_stream` adapts a stream that carries one datagram per
  write and read.

Errors are `std::io::Error`; implementations must not put credentials in error
messages.
