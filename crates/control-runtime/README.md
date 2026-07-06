# control-runtime

`control-runtime` contains the first pure orchestration use cases for the unified network control kernel.

The crate depends only on `control-domain`. It composes configuration, platform capability, proxy engine, and MITM plugin ports to prepare configuration, start, reload, stop, inspect status, read events, and evaluate initial MITM plugin gates including platform MITM availability, certificate trust denial states, remote script execution denial and unknown states, manifest validation, manifest non-error diagnostic aggregation, plugin result diagnostic aggregation, platform diagnostic aggregation, permission denial audit boundaries, audit event aggregation, and plugin port error propagation without depending on platform SDKs, external proxy binaries, UI frameworks, network transports, or local filesystem configuration.

Verification for this crate is performed only by GitHub Actions, following the repository CI/CD policy.
