# Windows Managed Client Source Release Contract

This contract activates the first complete Windows desktop integration slice.
The historical `v0.1.1-alpha.2` CLI-only ZIP contract remains in
`windows-cli-artifact-source-release-contract.md`; it does not describe the
current Windows package.

```text
windows-managed-client-source-release-contract=present
windows-managed-client-release-state=implementation-active
windows-managed-client-version-scope=v0.2.0-alpha.5
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
windows-managed-client-msi-service-start=asynchronous-on-install
windows-managed-client-system-proxy-mutation=active
windows-managed-client-trust-store-mutation=active
windows-managed-client-managed-lifecycle=active
windows-managed-client-sing-box-managed-process=active
windows-managed-client-sing-box-bundled=blocked
windows-managed-client-sing-box-gui-install=active
windows-managed-client-local-profile-import=active
windows-managed-client-remote-subscription-fetch=blocked
windows-managed-client-sing-box-basic-protocols=shadowsocks-trojan-vless-vmess
windows-managed-client-sing-box-advanced-transport-rendering=blocked
windows-managed-client-mitm-data-plane=active
windows-managed-client-mitm-certificate-lifecycle=active
windows-managed-client-mitm-protocol=http1-controlled-tls
windows-managed-client-script-dispatch=blocked
windows-managed-client-authenticode-policy=unsigned-alpha-msi-with-github-attestation
windows-managed-client-attestation-policy=github-artifact-attestation-required
windows-managed-client-release-assets=enabled-after-attestation-and-publish-gate
windows-managed-client-portable-zip=active
windows-managed-client-portable-release-assets=enabled-after-attestation-and-publish-gate
```

## Payload

The MSI contains:

- `networkcore-windows-gui.exe` from `apps/windows-gui`;
- `networkcore-windows-service.exe` from `apps/windows-service`;
- `networkcore-windows.exe` from `apps/windows-cli`;
- schema-version-1 `managed-config.json` from `installer/windows`.

The GUI has an explicit `Install core` action that resolves the official
Windows sing-box release, verifies the published `sha256:` digest when GitHub
provides one, extracts `sing-box.exe` under `%ProgramData%`, and persists its
path for profile import. The MSI itself neither bundles nor silently downloads
the third-party core.

The GUI `Import profile` action reads only an operator-selected local file,
passes its content through `CoreSubscriptionService`, renders a native
`sing-box/config.json`, and writes the matching managed `sing_box` process
block. It supports basic Shadowsocks, Trojan, VLESS, and VMess node fields.
Trojan receives required TLS enablement; VLESS and VMess render basic TCP only.
TLS, REALITY, WebSocket, gRPC, multiplex, routing, DNS, remote subscription
fetching, and all other transport-specific source fields are not preserved by
this path and remain blocked.

The GUI `Enable HTTPS MITM` action generates a service-owned CA key pair below
`%ProgramData%\\AnixOps\\NetworkCore\\mitm`, moves sing-box to the loopback
SOCKS upstream at `127.0.0.1:7891`, and writes a native MITM listener at
`127.0.0.1:7890`. The managed service imports that CA into LocalMachine ROOT,
starts sing-box before the native listener, issues authority-bound leaf
certificates, terminates downstream TLS, verifies upstream TLS, and applies the
built-in policy hook to a bounded HTTP/1.1 request/response exchange. Disable
stops the listener, returns sing-box to `127.0.0.1:7890`, removes the managed
ROOT entry, and deletes the generated private key.

The service validates the generated or operator-supplied native JSON with
`check -c`, owns `run -c`, persists PID/exit state, and redirects core
stdout/stderr to an explicit log.

The installer registers an automatic SCM service, but its install-time start is
asynchronous. MSI completion therefore does not wait for a preserved managed
configuration to reach `Running`; the GUI and `%ProgramData%\\AnixOps\\NetworkCore\\logs`
remain the operator-visible service diagnostics. Stop and uninstall operations
continue to wait so the `purge` rollback order stays deterministic.

Every Windows tag release also contains a portable ZIP with the GUI, service,
CLI, inert `managed-config.json`, and portable README. Extracting the ZIP does
not register or start a service; service and system-mutation operations remain
explicit GUI or service-command actions.

The GUI requests UAC elevation and controls SCM service state, configuration
import, the current-user WinINet proxy, machine WinHTTP proxy, LocalMachine ROOT
certificate entries, and signed INF driver packages. The service applies the
same configuration under LocalSystem, owns the EasyTier tunnel lifecycle, and
restores the captured proxy state on stop. Full MSI uninstall runs the service
`purge` command after `StopServices`, removing managed proxy, certificate,
driver, and tunnel state.

`root_certificate_path` remains a separate generic trust-store lifecycle
operation. Native MITM supports explicit loopback HTTP proxy clients and
controlled HTTP/1.1 TLS exchanges only. HTTP/2, HTTP/3/QUIC, chunked or
streaming exchanges, multi-request CONNECT sessions, arbitrary plugin loading,
remote scripts, remote subscriptions, TUN, DNS interception, firewall changes,
and transparent capture remain unavailable.

The driver capability installs and removes a caller-configured signed INF by
using NewDev `DiInstallDriverW` and `DiUninstallDriverW`. A kernel driver binary
is not built by this repository and is not accepted unless Windows validates
the package signature.

## CI And Release

GitHub Actions builds all Rust binaries for `x86_64-pc-windows-gnu`, pins WiX
4.0.6, builds and validates the MSI, performs bounded real MSI
install/uninstall smoke, creates SHA-256 and schema-version-2 manifest files
for the MSI and portable ZIP, and attests all eight Windows release-bundle
files before publication. No local build, test, installer, or release
validation is permitted.
