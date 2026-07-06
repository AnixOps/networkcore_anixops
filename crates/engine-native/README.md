# engine-native

`engine-native` contains the first native proxy execution engine adapter contracts.

The crate implements `ProxyEngineService` with stable descriptor, structured listener/node/route graph validation, lifecycle, status, and event diagnostics for the future in-process native engine. It consumes typed `ConfigSnapshot.nodes` and runtime request nodes from `ProxyEngineConfig`, rejects duplicate ids and missing route targets, and still reports unsupported listener and outbound protocol diagnostics until real native handlers exist.

It does not implement TCP, UDP, TUN, DNS, MITM, daemon control, platform mutation, runtime handle ownership, or `networkcore-linux start` wiring.

Verification for this crate is performed only by GitHub Actions, following the repository CI/CD policy.
