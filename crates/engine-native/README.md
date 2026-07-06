# engine-native

`engine-native` contains the first native proxy execution engine adapter contracts.

The crate implements `ProxyEngineService` with stable descriptor, structured listener/node/route graph validation, lifecycle, status, and event diagnostics for the future in-process native engine. It also exposes the first runtime handle contract for config-driven runtime assembly planning, real loopback TCP listener binding and release, a controlled loopback TCP accept loop, accepted connection counting, SOCKS outbound handler handoff, startup failure release reports, native runtime events, and foreground lifecycle handoff status. `NativeProxyEngineService::start` still rejects with a stable unavailable diagnostic until those resources are connected to proxy protocol, route, and outbound behavior.

The accept loop only accepts and closes loopback TCP connections as a source contract. It does not implement proxy protocol handling, outbound data plane, UDP, TUN, DNS, MITM, daemon control, platform mutation, or `networkcore-linux start` wiring.

Verification for this crate is performed only by GitHub Actions, following the repository CI/CD policy.
