# Windows Managed Client Source Release Contract

This contract activates the first complete Windows desktop integration slice.
The historical `v0.1.1-alpha.2` CLI-only ZIP contract remains in
`windows-cli-artifact-source-release-contract.md`; it does not describe the
current Windows package.

```text
windows-managed-client-source-release-contract=present
windows-managed-client-release-state=implementation-active
windows-managed-client-version-scope=v0.2.0
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
windows-managed-client-gui-daily-usability=home-nodes-subscriptions-settings-diagnostics-advanced-active
windows-managed-client-gui-runtime-status=scm-embedded-listener-current-user-proxy-active
windows-managed-client-gui-background-commands=active
windows-managed-client-service=active
windows-managed-client-driver-package-lifecycle=active
windows-managed-client-installer=active
windows-managed-client-msi-service-start=asynchronous-on-install
windows-managed-client-service-start-handoff=immediate-scm-running-then-managed-runtime
windows-managed-client-diagnostics=gui-config-preflight-and-local-report-active
windows-managed-client-system-proxy-mutation=active
windows-managed-client-system-proxy-lifecycle=service-owned-runtime-snapshot-active
windows-managed-client-trust-store-mutation=active
windows-managed-client-managed-lifecycle=active
windows-managed-client-embedded-engine=in-process-local-proxy-active
windows-managed-client-third-party-core=removed
windows-managed-client-embedded-supervision=service-poll-failure-rollback-active
windows-managed-client-embedded-node-switch=envelope-rewrite-and-engine-restart-active
windows-managed-client-embedded-delay-test=in-process-url-request-active
windows-managed-client-embedded-urltest=background-group-health-checks-active
windows-managed-client-embedded-basic-protocols=shadowsocks-trojan-vless-vmess-hysteria2-tuic
windows-managed-client-mitm-upstream=embedded-engine-loopback-socks-7891
windows-managed-client-local-profile-import=active
windows-managed-client-remote-subscription-fetch=operator-initiated-http-s-profile-import-and-update-active
windows-managed-client-remote-subscription-update=single-saved-url-explicit-only
windows-managed-client-profile-node-selector=embedded-envelope-node-and-policy-group-active
windows-managed-client-mitm-data-plane=active
windows-managed-client-mitm-certificate-lifecycle=active
windows-managed-client-mitm-protocol=http1-controlled-tls
windows-managed-client-script-dispatch=blocked
windows-managed-client-authenticode-policy=unsigned-no-authenticode-with-github-attestation
windows-managed-client-attestation-policy=github-artifact-attestation-required
windows-managed-client-release-assets=enabled-after-attestation-and-publish-gate
windows-managed-client-portable-zip=active
windows-managed-client-portable-release-assets=enabled-after-attestation-and-publish-gate
windows-managed-client-webview2-loader=app-local-x64-required
windows-managed-client-webview2-runtime=system-evergreen-runtime-required
```

## Payload

The MSI contains:

- `networkcore-windows-gui.exe` from `apps/windows-gui`;
- the x64 `WebView2Loader.dll` emitted by the pinned `webview2-com-sys` build
  dependency, installed next to the GUI executable;
- `networkcore-windows-service.exe` from `apps/windows-service`;
- `networkcore-windows.exe` from `apps/windows-cli`;
- schema-version-1 `managed-config.json` from `installer/windows`.

The MSI does not bundle or start any third-party proxy core. The GUI and the
service run the embedded engine (`engine-embedded` local proxy) in-process.

`v0.2.0` uses a Tauri/React desktop view with a Rust-owned command bridge and
splits daily UI state, runtime observation, background command dispatch, and
theme into dedicated GUI modules. `Connected` requires independent SCM state,
the embedded engine's recorded running state and loopback listener, and current
interactive-user proxy observations; managed JSON or a persisted state record
alone cannot report a connection. The exact UI control and unavailable-feature
boundary is documented in [Windows GUI Daily Usability](windows-gui-daily-usability.md).

Import accepts an operator-selected local file, a share link, or an
operator-entered `http://`/`https://` subscription URL. The importer parses it
with `CoreSubscriptionService`, keeps every node the embedded engine can run in
`%ProgramData%\\AnixOps\\NetworkCore\\embedded\\nodes.json`, keeps subscription
rules and select/url-test/fallback policy groups in `profile.json`, and writes
the engine's configuration envelope (`envelope.json`) for the selected node,
routing mode and group choices. A URL is downloaded only for that explicit
action, with a bounded client timeout; `Update URL` fetches the saved URL
through the same pipeline, and a failed download or parse leaves the saved
source and current managed config unchanged.

Switching a node or a select group rewrites the envelope and restarts a
connected engine. Delay tests and `Select fastest node` run in the GUI process
against each node's own outbound (HTTP(S) URL, 5-second timeout, 16 at a time)
without changing the managed config. url-test and fallback groups run
background health checks inside the engine. Supported protocols are
Shadowsocks, Trojan, VLESS (including REALITY), VMess, Hysteria2, and TUIC with
the TLS, WebSocket, gRPC and QUIC transports the embedded engine implements.

The GUI `Enable HTTPS MITM` action generates a service-owned CA key pair below
`%ProgramData%\\AnixOps\\NetworkCore\\mitm`, then protects the fixed
`root-ca-key.pem` path before it can enter managed configuration. Its Windows
DACL has inheritance disabled and exactly two full-control ACEs: the generating
account and LocalSystem. Protection rejects reparse points, any other path, or
an ACL readback mismatch; enable removes the private key and stops before any
service, proxy, or trust-store mutation on failure. Before installing the CA
or starting the native listener, and on each managed runtime health poll, the
service reads the same exact ACL back without modifying it; any later drift
fails closed, revokes its recorded managed CA trust entry, and follows the
recorded runtime rollback path. It then moves the embedded engine's listener to
the loopback SOCKS upstream at `127.0.0.1:7891` and writes a native MITM
listener at `127.0.0.1:7890`. The managed service imports that CA into
LocalMachine ROOT, starts the embedded engine before the native listener,
issues authority-bound leaf certificates, terminates downstream TLS, verifies
upstream TLS, and applies the built-in policy hook to a bounded HTTP/1.1
request/response exchange; chunked or streaming exchanges are not handled.
Disable stops the listener, returns the embedded engine to `127.0.0.1:7890`,
removes the managed ROOT entry, and deletes the generated private key.

Advanced settings includes an opt-in `Bilibili web promotional request blocking
(trial)` selection. When selected before `Enable HTTPS MITM`, the service loads
the first-party `networkcore.bilibili-web-adblock` request-only policy instead
of the general ad-block pack. It rejects only four independent recommendation,
topic, dynamic-follow-list, and live shopping endpoints. It does not fetch or
execute BiliUniverse, Loon, Surge, or other third-party scripts; it does not
modify response bodies, video playback, comments, the home feed, or HTTP/2,
HTTP/3, and QUIC traffic. The selection is persisted with a default of off and
requires HTTPS MITM to be enabled again before it affects the managed service.

While SCM is `Running`, the service polls the embedded engine and the enabled
loopback listener. An unexpected stop or failed health observation records
`last_transition=failed`, a redacted cause in `last_error`, stops runtime
resources, restores the service-owned proxy snapshot, then reports SCM
`Stopped`.

The installer registers an automatic SCM service, but its install-time start is
asynchronous. The service completes its SCM `Running` handshake before it
applies a potentially slow or invalid managed configuration, and GUI/CLI
`start` returns the immediately observed SCM state instead of polling for
runtime readiness. MSI completion therefore does not wait for a preserved
managed configuration to reach `Running`; a configuration failure is recorded
in `%ProgramData%\\AnixOps\\NetworkCore\\logs\\service.log` and returns the
service to `Stopped`. Stop and uninstall operations continue to wait so the
`purge` rollback order stays deterministic.

The elevated GUI provides `Validate` and `Diagnostics` actions. `Validate`
parses the managed JSON with the same schema validation as the service and
checks the embedded envelope without starting a proxy, service, tunnel,
certificate, driver, or system-proxy mutation. `Diagnostics` writes and opens
`%ProgramData%\\AnixOps\\NetworkCore\\logs\\diagnostics.txt`, containing the
current SCM status, managed runtime transition and failure detail, embedded
engine and native MITM state, and bounded, redacted tails of the local GUI,
service, and native MITM logs. URL/share links and
password/token/secret/authorization/private-key values are removed before the
report is written. Failed GUI actions generate the same report automatically
and show its path in the error dialog.

Every Windows tag release also contains a portable ZIP with the GUI, its x64
`WebView2Loader.dll`, service, CLI, inert `managed-config.json`, and portable
README. Extracting the ZIP does not register or start a service; service and
system-mutation operations remain explicit GUI or service-command actions.

The app-local loader prevents a missing-`WebView2Loader.dll` launch failure. It
does not embed the Microsoft Edge WebView2 Runtime: the supported Windows host
must provide the Evergreen WebView2 Runtime, which the GUI reports through its
normal launch/runtime diagnostics when unavailable.

The GUI requests UAC elevation and controls SCM service state, configuration
import, the current-user WinINet proxy, machine WinHTTP proxy, LocalMachine ROOT
certificate entries, and signed INF driver packages. The service applies the
same configuration under LocalSystem, owns the EasyTier tunnel lifecycle, and
restores the captured proxy state on stop. Full MSI uninstall runs the service
`purge` command after `StopServices`, removing managed proxy, certificate,
driver, and tunnel state.

`root_certificate_path` remains a separate generic trust-store lifecycle
operation. Native MITM supports explicit loopback HTTP proxy clients and
controlled HTTP/1.1 TLS exchanges with bounded `Content-Length` or `chunked`
body framing only. HTTP/2 and HTTP/3/QUIC MITM, compression, streaming
exchanges, multi-request CONNECT sessions, arbitrary plugin
loading, XHTTP/ECH/multiplex inference for generated link profiles, remote
scripts, TUN, DNS interception, firewall changes, and transparent capture remain
unavailable. Scheduled remote subscriptions, persistent remote subscription
catalogs, and remote route/rule fetch remain unavailable.

The driver capability installs and removes a caller-configured signed INF by
using NewDev `DiInstallDriverW` and `DiUninstallDriverW`. A kernel driver binary
is not built by this repository and is not accepted unless Windows validates
the package signature.

## CI And Release

GitHub Actions builds all Rust binaries for `x86_64-pc-windows-gnu`, pins WiX
4.0.6, builds and validates the MSI, performs bounded real MSI
install/uninstall smoke plus invalid-managed-configuration nonblocking-start
and core-exit proxy-rollback regressions, creates SHA-256 and schema-version-2 manifest files
for the MSI and portable ZIP, and attests all eight Windows release-bundle
files before publication. No local build, test, installer, or release
validation is permitted.
