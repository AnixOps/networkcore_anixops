# networkcore-linux

`networkcore-linux` is the Linux CLI entrypoint for NetworkCore.

The crate currently provides:

- Command parsing for the first Linux command surface.
- A config reader boundary that can be tested without local file-system verification.
- Response and diagnostic mapping for capabilities, prepare-config, start, stop, status, diagnostics, and version commands.
- A foreground lifecycle host source contract for future `start` handoff, with a default unavailable host that keeps binary wiring explicit.
- JSON response rendering for automation-facing output contracts.
- A minimal binary that wires `capabilities`, `status`, and `diagnostics` to `HostLinuxReadOnlyProbe`, and wires `prepare-config` to the pure `config-core` service through `RuntimeOrchestrator`.

This crate does not modify TUN, DNS, routing, firewall, certificates, service managers, or daemon state. `start` remains unavailable from the binary until a real proxy engine runtime handle is wired to the foreground lifecycle host; the current `engine-native` crate is diagnostics-only and is not wired into this binary. All validation runs in GitHub Actions according to `docs/ci-cd-policy.md`.
