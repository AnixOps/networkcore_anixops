# platform-linux

`platform-linux` is the Linux platform capability adapter boundary for NetworkCore.

The crate currently contains a read-only contract surface:

- Stable Linux diagnostic code constants using the `platform.linux.<area>.<reason>` namespace.
- A `LinuxPlatformSnapshot` mapper into `control-domain` capability status types.
- A `StaticLinuxPlatformCapabilityService` test double implementing `PlatformCapabilityService`.
- A `ReadOnlyLinuxPlatformCapabilityService` backed by injectable probes, plus a `HostLinuxReadOnlyProbe` that only inspects Linux capability facts.
- Contract tests for TUN availability, permission denial, unknown DNS and service managers, and MITM certificate state mapping.

This crate does not mutate host networking, install certificates, start services, grant capabilities, or run local verification. All validation is performed in GitHub Actions according to `docs/ci-cd-policy.md`.
