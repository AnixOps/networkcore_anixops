# Windows Managed Client Source Release Contract

This contract activates the first complete Windows desktop integration slice.
The historical `v0.1.1-alpha.2` CLI-only ZIP contract remains in
`windows-cli-artifact-source-release-contract.md`; it does not describe the
current Windows package.

```text
windows-managed-client-source-release-contract=present
windows-managed-client-release-state=implementation-active
windows-managed-client-version-scope=v0.2.0-alpha.1
WINDOWS_CLI_ARTIFACT_GATE=windows-managed-client-active
windows-managed-client-runner=windows-latest
windows-managed-client-runner-kind=github-hosted
windows-managed-client-rust-toolchain=stable
windows-managed-client-rust-profile=minimal
windows-managed-client-target-triple=x86_64-pc-windows-gnu
windows-managed-client-package-format=msi
windows-managed-client-wix-version=4.0.6
windows-managed-client-checksum-algorithm=sha256
windows-managed-client-manifest-schema-version=2
windows-managed-client-install-model=wix-per-machine-msi
windows-managed-client-system-mutation-policy=managed-apply-and-rollback
windows-managed-client-gui=active
windows-managed-client-service=active
windows-managed-client-driver-package-lifecycle=active
windows-managed-client-installer=active
windows-managed-client-system-proxy-mutation=active
windows-managed-client-trust-store-mutation=active
windows-managed-client-managed-lifecycle=active
windows-managed-client-script-dispatch=blocked
windows-managed-client-authenticode-policy=unsigned-alpha-msi-with-github-attestation
windows-managed-client-attestation-policy=github-artifact-attestation-required
windows-managed-client-release-assets=enabled-after-attestation-and-publish-gate
```

## Payload

The MSI contains:

- `networkcore-windows-gui.exe` from `apps/windows-gui`;
- `networkcore-windows-service.exe` from `apps/windows-service`;
- `networkcore-windows.exe` from `apps/windows-cli`;
- schema-version-1 `managed-config.json` from `installer/windows`.

The GUI requests UAC elevation and controls SCM service state, configuration
import, the current-user WinINet proxy, machine WinHTTP proxy, LocalMachine ROOT
certificate entries, and signed INF driver packages. The service applies the
same configuration under LocalSystem, owns the EasyTier tunnel lifecycle, and
restores the captured proxy state on stop. Full MSI uninstall runs the service
`purge` command after `StopServices`, removing managed proxy, certificate,
driver, and tunnel state.

The driver capability installs and removes a caller-configured signed INF by
using NewDev `DiInstallDriverW` and `DiUninstallDriverW`. A kernel driver binary
is not built by this repository and is not accepted unless Windows validates
the package signature.

## CI And Release

GitHub Actions builds all Rust binaries for `x86_64-pc-windows-gnu`, pins WiX
4.0.6, builds and validates the MSI, creates SHA-256 and schema-version-2
manifest files, and attests all four release-bundle files before publication.
No local build, test, installer, or release validation is permitted.
