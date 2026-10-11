# platform-linux

`platform-linux` is the Linux platform capability adapter boundary for NetworkCore.

The capability portion of the crate is read-only; the separately scoped systemd
adapter exposes explicitly confirmed unit installation and service control:

- Stable Linux diagnostic code constants using the `platform.linux.<area>.<reason>` namespace.
- A `LinuxPlatformSnapshot` mapper into `control-domain` capability status types.
- A `StaticLinuxPlatformCapabilityService` test double implementing `PlatformCapabilityService`.
- A `ReadOnlyLinuxPlatformCapabilityService` backed by injectable probes, plus a `HostLinuxReadOnlyProbe` that only inspects Linux capability facts.
- Contract tests for TUN availability, permission denial, unknown DNS and service managers, and MITM certificate state mapping.
- A systemd unit generation/install/removal boundary and an explicitly confirmed service-control adapter. Removal snapshots the unit before deletion, the command runner is injectable for contract tests, and the production runner invokes `systemctl` without forwarding command output.
- An explicitly selected environment-proxy file adapter with 0600 snapshots, post-write verification, external-change detection, and retained rollback snapshots. It never discovers a default system proxy path.

This crate does not mutate host networking, install certificates, or grant capabilities. Service control is limited to the requested systemd unit and requires caller confirmation. All validation is performed in GitHub Actions according to `docs/ci-cd-policy.md`.
# Subscription Refresh Scheduling

`systemd` exposes the Linux-only `LinuxSubscriptionRefreshScheduleRequest` boundary for an explicitly requested
NetworkCore `Type=oneshot` refresh service and persistent timer. It accepts only safe absolute paths, a simple
unit base name, source ID, and an interval of at least 300 seconds; it creates no default paths and scans none.
Install snapshots the rendered plan before any unit write, reloads systemd, starts and verifies the named timer.
Identical installation is idempotent; differing or externally modified files are rejected. Stop and uninstall are
bounded to the named NetworkCore-owned pair and never delete the refresh status record. Unit content contains no
subscription URL or credentials.
