# engine-native

`engine-native` contains the first native proxy execution engine adapter contracts.

The crate implements `ProxyEngineService` with stable descriptor, structured listener/node/route graph validation, lifecycle, status, and event diagnostics for the future in-process native engine. It also exposes the first runtime handle contract for config-driven runtime assembly planning, real loopback TCP listener binding and release, a controlled loopback TCP accept loop, accepted connection counting, pre-protocol connection close diagnostics, SOCKS5 greeting version/auth-method read diagnostics, SOCKS5 no-auth method selection and unsupported-auth rejection diagnostics, SOCKS5 auth method response write diagnostics, SOCKS outbound handler handoff, startup failure release reports, native runtime events, and foreground lifecycle handoff status. `NativeProxyEngineService::start` still rejects with a stable unavailable diagnostic until those resources are connected to SOCKS5 command parsing, route, and outbound behavior.

The accept loop only accepts loopback TCP connections, reads the first SOCKS5 greeting version/auth-method bytes when present, selects no-auth or rejects unsupported auth methods for diagnostics, writes the SOCKS5 method response, and then closes the connection before command parsing, route, and outbound handling. It does not implement CONNECT/BIND/UDP ASSOCIATE commands, outbound data plane, UDP, TUN, DNS, MITM, daemon control, platform mutation, or `networkcore-linux start` wiring.

Verification for this crate is performed only by GitHub Actions, following the repository CI/CD policy.
