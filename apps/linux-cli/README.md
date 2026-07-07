# networkcore-linux

`networkcore-linux` is the Linux CLI entrypoint for NetworkCore.

The crate currently provides:

- Command parsing for the first Linux command surface.
- A config reader boundary that can be tested without local file-system verification.
- Response and diagnostic mapping for capabilities, prepare-config, start, stop, status, diagnostics, and version commands.
- A foreground lifecycle host source contract for `start` handoff, with default unavailable, current-process, and injectable interruption source implementations.
- JSON response rendering for automation-facing output contracts.
- A minimal binary that wires `capabilities`, `status`, and `diagnostics` to `HostLinuxReadOnlyProbe`, wires `prepare-config` to the pure `config-core` service, and wires `start` to `engine-native::NativeProxyEngineService` through `RuntimeOrchestrator`.

This crate does not modify TUN, DNS, routing, firewall, certificates, service managers, or daemon state. `start` is foreground-only, maps injected lifecycle interruption to `cli.linux.start.lifecycle_interrupted` with exit code 130, and does not imply daemon, control socket, cross-process `stop`, background `status`, packaging, or service installation support. All validation runs in GitHub Actions according to `docs/ci-cd-policy.md`.
