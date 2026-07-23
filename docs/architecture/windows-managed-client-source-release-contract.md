# Windows Managed Client Source Release Contract

This contract activates the first complete Windows desktop integration slice.
The historical `v0.1.1-alpha.2` CLI-only ZIP contract remains in
`windows-cli-artifact-source-release-contract.md`; it does not describe the
current Windows package.

```text
windows-managed-client-source-release-contract=present
windows-managed-client-release-state=implementation-active
windows-managed-client-version-scope=v0.2.0-alpha.18
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
windows-managed-client-service-start-handoff=immediate-scm-running-then-managed-runtime
windows-managed-client-diagnostics=gui-config-preflight-and-local-report-active
windows-managed-client-system-proxy-mutation=active
windows-managed-client-system-proxy-lifecycle=service-owned-runtime-snapshot-active
windows-managed-client-trust-store-mutation=active
windows-managed-client-managed-lifecycle=active
windows-managed-client-sing-box-managed-process=active
windows-managed-client-sing-box-bundled=blocked
windows-managed-client-sing-box-gui-install=active
windows-managed-client-local-profile-import=active
windows-managed-client-sing-box-native-json-import=active
windows-managed-client-sing-box-native-json-mitm=controlled-mixed-in-snapshot-restore-active
windows-managed-client-remote-subscription-fetch=operator-initiated-http-s-profile-import-and-update-active
windows-managed-client-remote-subscription-update=single-saved-url-explicit-only
windows-managed-client-profile-node-selector=generated-clash-api-runtime-selector-active
windows-managed-client-sing-box-clash-api=loopback-explicit-switch-active
windows-managed-client-sing-box-manual-delay-test=loopback-explicit-single-node-https-active
windows-managed-client-sing-box-runtime-health=loopback-explicit-selector-read-active
windows-managed-client-sing-box-urltest=blocked
windows-managed-client-sing-box-basic-protocols=shadowsocks-trojan-vless-vmess-hysteria2-tuic
windows-managed-client-sing-box-quic-share-link-import=hysteria2-tuic-local-file-active
windows-managed-client-sing-box-v2ray-share-link-compatibility=tls-reality-ws-grpc-http-httpupgrade-quic-local-file-active
windows-managed-client-sing-box-advanced-transport-rendering=v2ray-share-link-subset-active
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

The GUI `Import profile` action accepts either an operator-selected local file
or an operator-entered `http://`/`https://` subscription URL. `Load nodes`
explicitly reads that same operator-selected source without changing the managed
configuration and fills a selector with the parsed NodeCatalog names and stable
IDs. For NodeCatalog imports, `Import profile` writes every translatable node
behind a generated sing-box `selector`, sets the chosen node as its explicit
default, and enables a Clash API controller only at `127.0.0.1:9091`. `Switch
active` makes an explicit PATCH through that loopback controller and reads the
selector state back before persisting the active node ID. The controller is not
listened on a LAN address and has no bundled Web UI. `Test delay` makes one
explicit `GET /proxies/{generated-outbound}/delay` request through that same
loopback controller for the selected loaded node. Its editable HTTPS target is
stored only in desktop state, defaults to `https://www.gstatic.com/generate_204`,
uses a 10-second request timeout, and reports the returned milliseconds without
changing the active selector, managed config, or service lifecycle. A blank
selector uses the first supported node. A URL is
downloaded only for that explicit action, with a bounded client timeout, then
uses the same native JSON inspection and `CoreSubscriptionService` parser as a
local file. After a successful URL import, `Update URL` explicitly fetches that
single saved URL through the same pipeline. It does not use unsaved input text;
a failed download or parse leaves the saved source and current managed config
unchanged. A native sing-box JSON object with `inbounds` or `outbounds` is
copied verbatim to `sing-box/config.json`, so its TLS, REALITY, WebSocket, gRPC,
multiplex, routing, DNS, and other sing-box-owned fields are retained. A
native document remains pass-through and does not expose a generated NodeCatalog
selector; changing its outbound/selector groups remains the operator's native
sing-box configuration choice. The generated selector does not configure
`urltest`, automatic latency selection, scheduled subscription refresh, or an
automatic service restart. The explicit delay action is not scheduled, does
not select an outbound, and is unavailable for native pass-through documents.
`Check core` reads that generated selector once through the same loopback
`GET /proxies/{selector}` endpoint and displays its active outbound plus node
count. It is read-only: it does not persist a selected node, change managed
configuration, or start, stop, or restart the service. It is unavailable for
native pass-through documents that do not provide the generated selector. A
loopback or wildcard `mixed`/`http` inbound is detected to configure the Windows
system proxy endpoint; a native document without one leaves system-proxy
configuration unset. Other supported inputs render the basic Shadowsocks,
Trojan, VLESS, VMess, Hysteria2, and TUIC node fields. The V2Ray-family renderer
preserves the selected explicit share-link/catalog fields: Trojan, VLESS, and
VMess TLS, ALPN, certificate pins, uTLS fingerprint, VLESS Vision flow and
REALITY public-key/short-id metadata; VMess security and alter-id; and
WebSocket, gRPC, HTTP, HTTPUpgrade, or V2Ray QUIC transport details. This is a
deterministic compatibility subset, not inference for arbitrary native fields.
Hysteria2 `hysteria2://`/`hy2://` inputs retain password, supported obfuscation,
port hopping, and TLS metadata; TUIC `tuic://` inputs retain UUID, optional
password, congestion control, and TLS metadata. Hysteria2/TUIC and V2Ray QUIC
transport are direct proxy-core paths, not HTTPS or HTTP/3 MITM traffic. The URL
is retained only for the next explicit import or update; there is no background
refresh, subscription group/catalog, automatic service restart, or route/rule
fetch.
GUI-controlled HTTPS MITM can
also use a native document only when it contains a `type: mixed`,
`tag: mixed-in` inbound. The GUI snapshots the original imported JSON below
`%ProgramData%\\AnixOps\\NetworkCore\\mitm`, changes only that inbound to the
loopback SOCKS upstream listener, and restores the snapshot on disable. Native
documents without that explicit controlled inbound are not modified for MITM.

The GUI `Enable HTTPS MITM` action generates a service-owned CA key pair below
`%ProgramData%\\AnixOps\\NetworkCore\\mitm`, moves sing-box to the loopback
SOCKS upstream at `127.0.0.1:7891`, and writes a native MITM listener at
`127.0.0.1:7890`. The managed service imports that CA into LocalMachine ROOT,
starts sing-box before the native listener, issues authority-bound leaf
certificates, terminates downstream TLS, verifies upstream TLS, and applies the
built-in policy hook to a bounded HTTP/1.1 request/response exchange. Disable
stops the listener, restores a recorded native JSON snapshot when present (or
returns a basic renderer config to `127.0.0.1:7890`), removes the managed ROOT
entry, and deletes the generated private key.

The service validates the generated or operator-supplied native JSON with
`check -c`, owns `run -c`, persists PID/exit state, and redirects core
stdout/stderr to an explicit log. The GUI can directly open that core log in
addition to the general log folder.

The installer registers an automatic SCM service, but its install-time start is
asynchronous. The service completes its SCM `Running` handshake before it
applies a potentially slow or invalid managed configuration, and GUI/CLI
`start` returns the immediately observed SCM state instead of polling for
runtime readiness. MSI completion therefore does not wait for a preserved
managed configuration to reach `Running`; a configuration failure is recorded
in `%ProgramData%\\AnixOps\\NetworkCore\\logs\\service.log` and returns the
service to `Stopped`. Stop and uninstall operations continue to wait so the
`purge` rollback order stays deterministic.

The elevated GUI provides `Open JSON`, `Validate`, and `Diagnostics` actions.
`Validate` first parses the selected managed JSON with the same schema validation
as the service. When an enabled `sing_box` block is present, it then calls the
same `sing-box check -c <config>` preflight used by the managed process without
starting a proxy, service, tunnel, certificate, driver, or system-proxy mutation.
The check output remains in the configured sing-box log. `Diagnostics` writes and
opens `%ProgramData%\\AnixOps\\NetworkCore\\logs\\diagnostics.txt`, containing the
current SCM status, managed runtime state, and bounded tails of the local GUI,
service, sing-box, and native MITM logs. Failed GUI actions generate the same
report automatically and show its path in the error dialog.

The GUI debug toggle records detailed GUI activity only and does not rewrite an
operator-owned sing-box JSON profile. Core debug logging remains an explicit
sing-box setting such as `"log": { "level": "debug" }`; its output is captured
by the configured managed sing-box log path.

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
controlled HTTP/1.1 TLS exchanges only. HTTP/2 and HTTP/3/QUIC MITM, chunked
or streaming exchanges, multi-request CONNECT sessions, arbitrary plugin
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
install/uninstall smoke plus an invalid-managed-configuration nonblocking-start
regression, creates SHA-256 and schema-version-2 manifest files
for the MSI and portable ZIP, and attests all eight Windows release-bundle
files before publication. No local build, test, installer, or release
validation is permitted.
