# engine-native

`engine-native` contains the first native proxy execution engine adapter contracts.

The crate implements `ProxyEngineService` with stable descriptor, structured listener/node/route graph validation, lifecycle, status, and event diagnostics for the future in-process native engine. It also exposes the first source-level runtime handle contract for loopback listener ownership, SOCKS outbound handler handoff, startup failure release reports, native runtime events, and foreground lifecycle handoff status. `NativeProxyEngineService::start` still rejects with a stable unavailable diagnostic until those contracts are backed by real runtime resources and connected deliberately.

It does not implement real TCP accept loops, UDP, TUN, DNS, MITM, daemon control, platform mutation, or `networkcore-linux start` wiring.

Verification for this crate is performed only by GitHub Actions, following the repository CI/CD policy.
