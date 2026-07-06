# networkcore-linux

`networkcore-linux` is the Linux CLI entrypoint skeleton for NetworkCore.

The crate currently provides:

- Command parsing for the first Linux command surface.
- A config reader boundary that can be tested without local file-system verification.
- Response and diagnostic mapping for capabilities, prepare-config, start, stop, status, diagnostics, and version commands.
- JSON response rendering for automation-facing output contracts.
- A minimal binary that exposes the command parser without wiring real Linux probing, daemon control, system mutation, or release packaging.

This crate does not modify TUN, DNS, routing, firewall, certificates, service managers, or daemon state. All validation runs in GitHub Actions according to `docs/ci-cd-policy.md`.
