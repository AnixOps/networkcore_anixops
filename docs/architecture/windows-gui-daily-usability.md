# Windows GUI Daily Usability

This document defines the Windows GUI usability slice for
the current Windows desktop baseline. It replaces the fixed-coordinate Win32 view with a
Tauri 2 and React desktop shell while preserving the existing Rust runtime boundary, Windows
service, managed configuration schema, embedded engine, NodeCatalog parser,
system integration layer, MSI, and portable package.

## Source Markers

```text
windows-gui-daily-usability=active
windows-gui-information-architecture=home-nodes-subscriptions-settings-diagnostics-advanced
windows-gui-runtime-status=scm-embedded-listener-current-user-proxy-active
windows-gui-command-execution=rust-command-bridge-background-workers-all-system-operations-subscription-catalog-refresh-fastest-node-script-runtime-native-groups-active
windows-gui-high-risk-features=advanced-explicit-only
windows-gui-view-runtime=tauri-react-active
windows-gui-command-bridge=rust-owned-system-mutations-only
windows-gui-tauri-command-surface=runtime-connect-node-subscription-settings-diagnostics-advanced-active
windows-gui-tauri-lifecycle=auto-connect-core-recovery-single-instance-tray-proxy-recovery-active
windows-gui-tauri-mitm=enable-disable-legacy-native-mitm-active
```

## Information Architecture

| Page | Purpose | Real backend boundary |
| --- | --- | --- |
| Home | Daily connect/disconnect and a concise runtime summary. | SCM status, the embedded engine's recorded state and listener, and current-user WinINet proxy probe. |
| Proxies | Search/filter imported nodes, switch nodes, test delay, pick the fastest node. | `config-core::CoreSubscriptionService` and `engine-embedded` envelopes and delay probes. |
| Rules | Routing mode, subscription rules, policy groups and the DNS behavior note. | `engine-embedded` profile and routing envelope. |
| Subscriptions | Explicit import or one saved HTTP(S) URL refresh, plus an opt-in hourly refresh. | GUI-owned explicit fetch plus the embedded import path. |
| Settings | Login preferences, theme and language, runtime mode, and managed JSON preflight. | `platform-windows` and existing managed config APIs. |
| Diagnostics | Generate a bounded diagnostics report. | Existing ProgramData log/report contract. |
| Advanced | Explicit service, certificate, driver, network recovery, and HTTPS MITM operations. | Existing explicit authorization, snapshot, rollback, and service paths only. |

## Delivery Status

| Status | Scope | Current boundary |
| --- | --- | --- |
| Completed | Tauri/React shell, runtime dashboard, connect/disconnect/restart, node list/switch/delay, manual and opt-in 30-minute fastest-node selection, five routing modes, subscription rules and policy-group switching, persisted subscription catalog add/select/remove, explicit profile import/update, opt-in hourly refresh for the active saved HTTP(S) subscription, preferences, auto-connect, one core recovery, single-instance focus, tray hide/restore, GUI-owned proxy recovery, diagnostics, explicit service/certificate/driver commands, native HTTPS MITM enable/disable, and an opt-in first-party Bilibili web request-blocking trial. | The Rust command bridge remains the only system-mutation boundary. No third-party proxy core is installed or started. |
| Completed | Commands that can wait on network, SCM, registry, certificate, driver, filesystem, or managed-config I/O run on Tauri blocking workers, including runtime snapshots, connection lifecycle, service/certificate/driver operations, script configuration, and HTTPS MITM enable/disable. | The WebView remains responsive while each operation runs; the frontend still permits one mutation at a time. |
| Not completed | HTTP/2/HTTP/3 MITM data plane. | HTTP/2 and HTTP/3 interception remain outside the native proxy. |
| Not completed | Native MITM JavaScript execution. | The GUI rejects new script-runtime configuration and the Windows service rejects configured scripts until an equivalent no-network, least-privilege sandbox exists. |

The GUI uses a Tauri WebView shell and React view layer. System integration,
subscription parsing, service lifecycle, proxy mutation, certificate, and driver
operations remain Rust-only Tauri commands; the WebView receives serialized state
and cannot directly access the filesystem, shell, process, or Windows settings.

## Runtime Truth

`Connected` is emitted only when all of these are true:

1. SCM reports `Running` for `AnixOpsNetworkCore` (service mode), or the GUI's
   own embedded engine is running (desktop mode).
2. The managed state records the embedded engine as running on the configured
   loopback listener.
3. The current interactive user's WinINet proxy exactly matches the enabled
   managed server and bypass settings.

The managed JSON is never sufficient by itself. Configuration JSON errors map
to `Configuration error`; a failed transition or a stopped engine maps to `Core
error`; SCM pending states map to `Connecting` or `Disconnecting`.

Connect validates the managed JSON and the embedded envelope, starts the
engine, and waits off the UI thread for its listener. Only then does the GUI
apply the configured proxy for the interactive user and atomically persist its
snapshot plus the exact GUI-applied proxy settings. Disconnect restores it
before stopping the engine only when the current proxy still exactly matches
the GUI-owned setting. A later GUI startup or status refresh uses the same rule
after the engine is no longer valid; it never overwrites a user-changed proxy.

Managed configuration schema 2 makes proxy ownership explicit. Existing schema
1 data migrates in memory to `Service`, preserving CLI/service behavior. A GUI
profile import writes `Desktop`, so the user-session GUI is the sole owner of
its current-user snapshot.

## Control Map

| Control | Status | Backend |
| --- | --- | --- |
| Connect / Disconnect | Active | Managed config and envelope preflight, engine start/stop, loopback listener observation, then current-user proxy snapshot/rollback. |
| Restart service | Active | Desktop-owned daily profile: preflight, GUI-owned proxy restore, stop, and the same verified connection path. Service-owned advanced configuration: existing SCM restart path only. |
| Node list / filter | Active | Imported nodes from `embedded/nodes.json`, filtered locally in the React view. |
| Switch node | Active | Rewrites the envelope for the chosen node (or the main policy group's choice in a routed profile) and restarts a connected engine. |
| Test delay / fastest node | Active | In-process URL requests through each node's own outbound (5-second timeout, 16 at a time); the opt-in 30-minute monitor picks the fastest node. |
| Routing mode | Active | Bypass China, GFW list, return to China, direct, or the subscription's own rules; public rule lists are cached locally. |
| Policy groups | Active | Lists the subscription's select/url-test/fallback groups; select groups can be switched. url-test and fallback groups run background health checks in the engine. |
| DNS | Informational | The embedded engine resolves domains that IP rules need with the system resolver; connections through a node have the node server resolve the domain. |
| Import profile / Update saved URL | Active | Explicit input fetch followed by the embedded import path. Fetch or parse failure leaves the current managed config untouched. |
| Automatic subscription refresh | Active | An opt-in monitor attempts the saved HTTP(S) URL once per hour and records an error without replacing the managed configuration when refresh cannot run. |
| Validate | Active | Managed schema validation and envelope check. |
| Diagnostics report | Active | Existing bounded report path. |
| Manual proxy recovery | Active | Restores only a GUI-owned snapshot whose current proxy still exactly matches the GUI-applied settings; otherwise it clears stale ownership without changing the user proxy. |
| Managed TUN / SD-WAN | Removed | The external-core managed tunnel was removed on 2026-10-26; SD-WAN networking returns on the ANX private protocol. |
| Script dispatch | Active but advanced | Shows whether a runtime is configured and accepts a local MITM policy source, Node runner, URL-to-local-script mapping, and optional store. The stopped service loads the policy and executor together on its next start; it never downloads remote scripts. |
| MITM enable / disable | Active | Enabling moves the embedded engine to the loopback SOCKS upstream `127.0.0.1:7891` and configures the service-owned native HTTPS proxy on `127.0.0.1:7890`. Disabling returns the engine to port 7890, removes the service-recorded MITM CA, then restores the prior service state. |
| Certificate and driver | Active but advanced | Existing explicit mutation and rollback operations; not part of the connect path. |
| Start after login | Active | Exact current-user `HKCU\...\Run\AnixOpsNetworkCore` entry, queried from Windows and removed only when its command matches this GUI. |
| Auto-connect | Active | Tauri startup reads the persisted preference and submits one existing desktop connection attempt when the runtime is not already connected. |
| One core recovery | Active | A two-second Tauri background monitor observes the existing runtime status and, after a GUI-started connection enters `CoreError`, submits at most one existing desktop connection attempt. |
| Single instance | Active | The official Tauri single-instance plugin focuses the existing main window when a later launch is requested. |
| System tray | Active | Closing the main window hides it; the persistent tray menu restores the window or explicitly exits the process. |
| Subscription catalog | Active | The desktop state stores multiple local or HTTP(S) sources with each source's last refresh result. Selecting one regenerates the active profile; automatic refresh applies only to that active saved HTTP(S) source. |
| HTTP/2/HTTP/3 MITM | Blocked | Existing platform and MITM boundaries remain unchanged. |

## Responsiveness And Failure Handling

Commands that can wait on network, SCM, process preflight, registry,
certificate/driver APIs, or managed-config filesystem I/O execute through Tauri
blocking workers. The frontend allows one pending operation at a time and disables
repeat requests with an in-page message. Pure in-memory rendering commands remain
direct command calls. A completion refreshes the selected node, delay result,
desktop snapshot, or concise failure message.

A failed node or group switch leaves the persisted choice and the envelope
unchanged. A failed subscription fetch produces no config write. Ordinary
operation failures are displayed in-page with a diagnostics route instead of a
blocking message box; only startup-fatal errors use a modal dialog.

An interrupted GUI-owned proxy is automatically recovered only once after the
runtime is conclusively stopped and its engine is no longer running. A failed attempt
is retained as an in-page error with the existing `Restore network settings`
and Diagnostics actions; periodic status refreshes do not retry it. A later
successful GUI connection starts a new recovery cycle.

## Manual Verification

The following visual and OS-integrated checks cannot be asserted by the current
headless GitHub Actions Windows job and are tracked in
`docs/manual-intervention.md`:

- 100%, 125%, 150%, and 200% DPI; minimum-size and resize behavior.
- Light and dark rendering, long node names/errors, empty subscriptions, and a
  catalog containing hundreds of nodes.
- No network, non-administrator elevation rejection, missing service,
  port collision, sleep/resume, and reboot recovery.
- Interactive-user proxy rollback after an engine stop while the GUI is open and
  after reopening the GUI.
- Tray double-click/menu behavior, login startup toggle, auto-connect once,
  one-shot core restart, startup-entry removal during MSI uninstall, and tray
  icon recovery after an Explorer restart or primary-display DPI change.
- Restart after a generated local or HTTP(S) profile import with networking
  disabled: the unchanged managed config must restore node names/protocols
  locally; an externally changed config must not restore that stale catalog.
- Enable and disable HTTPS MITM. Confirm the system proxy points at the local
  MITM listener on 7890 while the embedded engine listens on 7891, the engine
  returns to 7890 on disable, and the service-recorded CA is removed.
- Select the Bilibili web trial while HTTPS MITM is disabled, enable HTTPS MITM,
  and confirm the persisted managed config selects the first-party request-only
  policy. Browse a Bilibili search page over controlled HTTP/1.1 TLS and confirm
  recommendation-word requests are rejected without enabling script execution;
  then disable the selection, re-enable HTTPS MITM, and confirm the general
  policy returns.
- Enable the hourly saved-subscription refresh, leave the service stopped, and
  confirm a successful update is recorded. Repeat with the service running and
  confirm the existing configuration stays unchanged while the update error is
  recorded.
- Use `Select fastest` with multiple reachable nodes and then enable its
  30-minute monitor. Confirm the persisted active node matches the lowest
  successful delay; unavailable nodes must not replace the active node.
- With native HTTPS MITM enabled and the service stopped, save a local policy
  source containing a `[Script]` rule, a local Node runner, and a mapped local
  script asset. Start the service and confirm a matching request produces the
  native script-executed diagnostic; clear the runtime and confirm it no longer
  loads on the next service start.
- Import a subscription with rules and policy groups, switch a select group on
  the Rules page while connected, and confirm the engine restarts on the new
  choice and keeps it after the next subscription refresh.

GitHub Actions remains the sole environment for TypeScript checks, frontend builds,
Rust tests/builds, MSI
install/uninstall, and portable archive validation.
