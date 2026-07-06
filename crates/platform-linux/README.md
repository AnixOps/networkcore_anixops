# platform-linux

`platform-linux` is the Linux platform capability adapter boundary for NetworkCore.

The crate currently contains a read-only contract surface:

- Stable Linux diagnostic code constants using the `platform.linux.<area>.<reason>` namespace.
- A `LinuxPlatformSnapshot` mapper into `control-domain` capability status types.
- A `StaticLinuxPlatformCapabilityService` test double implementing `PlatformCapabilityService`.
- Contract tests for TUN availability, permission denial, unknown DNS and service managers, and MITM certificate state mapping.

This crate does not perform real Linux probing, mutate host networking, install certificates, start services, or run local verification. All validation is performed in GitHub Actions according to `docs/ci-cd-policy.md`.
