# platform-windows

`platform-windows` is the read-only Windows platform capability boundary used by
the first `networkcore-windows` CLI artifact.

Current status:

- `WINDOWS_CLI_ARTIFACT_GATE=package-windows-active/system-mutation-blocked`
- `windows-cli-artifact-source-identity=apps/windows-cli`
- `windows-cli-artifact-package-windows=defined`
- Windows service, driver, installer, system proxy mutation, system trust store
  mutation, JavaScript script dispatch, and managed daemon lifecycle remain
  blocked.

This crate does not modify Windows system state. It only reports the alpha CLI
artifact/package status and the blocked operations that must stay out of
`v0.1.1-alpha.2`.
