# platform-ios

`platform-ios` is the pure Rust iOS platform capability adapter boundary for NetworkCore.

The crate currently contains a source-contract implementation surface:

- Stable iOS diagnostic code constants using the `platform.ios.<area>.<reason>` namespace.
- `IosNetworkExtensionProbe`, `IosEmbeddedRuntimeProbe`, `IosMitmCertificateProbe`, and `IosSharedStorageProbe` data types for sanitized platform facts.
- An `IosPlatformSnapshot` mapper into `control-domain` capability status types.
- A `StaticIosPlatformCapabilityService` test double implementing `PlatformCapabilityService`.
- Contract tests for Network Extension entitlement, VPN configuration, embedded runtime, remote script policy, shared storage, and MITM certificate state mapping.

This crate does not include Swift, an Xcode project, a Network Extension target, entitlement files, signing configuration, TestFlight upload, App Store Connect integration, or an iOS release artifact. Future Apple SDK code must live in an app, extension, or bridge layer and pass sanitized snapshots into this crate. All validation is performed in GitHub Actions according to `docs/ci-cd-policy.md`.
