# netstack-smoltcp (vendored)

Userspace TCP/IP stack used by `engine-embedded`'s packet tunnel (the iOS
Network Extension and other TUN clients). Vendored from
[netstack-smoltcp 0.2.4](https://github.com/cavivie/netstack-smoltcp)
(MIT OR Apache-2.0, see `LICENSE-MIT` and `LICENSE-APACHE`) so it can be
tuned for phones. The upstream examples and integration tests are not copied.

Changes against 0.2.4 are listed here; measure each one with the
`Tunnel perf` workflow (`crates/engine-embedded/examples/tunnel_bench.rs`).

- (none yet)
