# engine-native

`engine-native` contains the first native proxy execution engine adapter contracts.

The crate implements `ProxyEngineService` with stable descriptor, configuration rejection, lifecycle, status, and event diagnostics for the future in-process native engine. It does not implement listener graph validation, TCP, UDP, TUN, DNS, MITM, daemon control, platform mutation, or `networkcore-linux start` wiring.

Verification for this crate is performed only by GitHub Actions, following the repository CI/CD policy.
