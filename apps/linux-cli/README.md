# networkcore-linux

`networkcore-linux` is the Linux CLI entrypoint for NetworkCore.

The crate currently provides:

- Command parsing for the first Linux command surface.
- A config reader boundary that can be tested without local file-system verification.
- Response and diagnostic mapping for help, capabilities, prepare-config, start, stop, status, diagnostics, install-sing-box, and version commands.
- A foreground lifecycle host source contract for `start` handoff, with default unavailable, current-process, injectable interruption source, Unix OS signal source, and interruption cleanup implementations.
- JSON response rendering for automation-facing output contracts.
- A minimal binary that wires `capabilities`, `status`, and `diagnostics` to `HostLinuxReadOnlyProbe`, wires `prepare-config` to the pure `config-core` service, wires `start` to `engine-native::NativeProxyEngineService` through `RuntimeOrchestrator`, and wires `install-sing-box` to the `engine-singbox` latest release installer.

`install-sing-box` downloads the latest official `sing-box` release asset into an operator-visible cache and reports the cached executable path; it does not bundle `sing-box` into NetworkCore release artifacts or start a `sing-box` process.

This crate does not modify TUN, DNS, routing, firewall, certificates, service managers, or daemon state. `start` is foreground-only, maps Unix `SIGINT`/`SIGTERM` and injected lifecycle interruption to `cli.linux.start.lifecycle_interrupted` with exit code 130, then stops the current in-process runtime and aggregates native release diagnostics such as `engine.native.runtime.accept_loop_stopped` and `engine.native.runtime.released`. This does not imply daemon, control socket, cross-process `stop`, background `status`, packaging, or service installation support. All validation runs in GitHub Actions according to `docs/ci-cd-policy.md`.
