# platform-linux

`platform-linux` is the Linux platform capability adapter boundary for NetworkCore.

The capability portion of the crate is read-only; the separately scoped systemd
adapter exposes explicitly confirmed unit installation and service control:

- Stable Linux diagnostic code constants using the `platform.linux.<area>.<reason>` namespace.
- A `LinuxPlatformSnapshot` mapper into `control-domain` capability status types.
- A `StaticLinuxPlatformCapabilityService` test double implementing `PlatformCapabilityService`.
- A `ReadOnlyLinuxPlatformCapabilityService` backed by injectable probes, plus a `HostLinuxReadOnlyProbe` that only inspects Linux capability facts.
- Contract tests for TUN availability, permission denial, unknown DNS and service managers, and MITM certificate state mapping.
- A systemd unit generation/install boundary and an explicitly confirmed service-control adapter. The command runner is injectable for contract tests and the production runner invokes `systemctl` without forwarding command output.

This crate does not mutate host networking, install certificates, or grant capabilities. Service control is limited to the requested systemd unit and requires caller confirmation. All validation is performed in GitHub Actions according to `docs/ci-cd-policy.md`.
