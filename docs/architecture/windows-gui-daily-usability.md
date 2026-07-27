# Windows GUI Daily Usability

This document defines the Windows GUI usability slice for
the current Windows desktop baseline. It replaces the fixed-coordinate Win32 view with a
Tauri 2 and React desktop shell while preserving the existing Rust runtime boundary, Windows
service, managed configuration schema, sing-box adapter, NodeCatalog parser,
selector API, system integration layer, MSI, and portable package.

## Source Markers

```text
windows-gui-daily-usability=active
windows-gui-information-architecture=home-nodes-subscriptions-settings-diagnostics-advanced
windows-gui-runtime-status=scm-core-config-validation-loopback-listener-selector-readback-pid-current-user-proxy-active
windows-gui-command-execution=rust-command-bridge-background-workers-all-system-operations-subscription-catalog-refresh-fastest-node-tun-dns-script-runtime-native-groups-active
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
| Home | Daily connect/disconnect and a concise runtime summary. | SCM status, managed configuration/readiness state, owned sing-box PID probe, and current-user WinINet proxy probe. |
| Nodes | Search/filter imported NodeCatalog nodes and explicitly switch/test the generated selector. | `config-core::CoreSubscriptionService` and `engine-singbox` loopback Clash API helpers. |
| Subscriptions | Explicit local import or one saved HTTP(S) URL refresh. | GUI-owned explicit fetch plus existing NodeCatalog/native-JSON import path. No scheduler. |
| Settings | Login preferences, theme selection, explicit sing-box/Mieru installation and checks, and managed JSON preflight. | `platform-windows`, `engine-singbox`, `engine-mieru`, and existing managed config APIs. |
| Diagnostics | Generate a bounded diagnostics report. | Existing ProgramData log/report contract. |
| Advanced | Explicit service, certificate, driver, network recovery, and HTTPS MITM operations. | Existing explicit authorization, snapshot, rollback, and service paths only. |

## Delivery Status

| Status | Scope | Current boundary |
| --- | --- | --- |
| Completed | Tauri/React shell, runtime dashboard, connect/disconnect/restart, node list/switch/delay, manual and opt-in 30-minute fastest-node selection, persisted subscription catalog add/select/remove, explicit profile import/update, opt-in hourly refresh for the active saved HTTP(S) subscription, selector check, core install, preferences, auto-connect, one core recovery, single-instance focus, tray hide/restore, GUI-owned proxy recovery, diagnostics, explicit service/certificate/driver commands, verified EasyTier TUN configuration, stopped-service sing-box DNS block configuration, native selector default and native outbound-group JSON editing, locally mapped Node script dispatch for native MITM, and native HTTPS MITM enable/disable. | The Rust command bridge remains the only system-mutation boundary. |
| Completed | Commands that can wait on network, SCM, process preflight, registry, certificate, driver, filesystem, or managed-config I/O run on Tauri blocking workers, including runtime snapshots, connection lifecycle, native group edits, service/certificate/driver operations, TUN/DNS/script configuration, and HTTPS MITM enable/disable. | The WebView remains responsive while each operation runs; the frontend still permits one mutation at a time. |
| Not completed | HTTP/2/HTTP/3 MITM data plane. | Native outbound groups are editable, but HTTP/2 and HTTP/3 interception remain outside the native proxy. |

The GUI uses a Tauri WebView shell and React view layer. System integration,
subscription parsing, service lifecycle, proxy mutation, certificate, and driver
operations remain Rust-only Tauri commands; the WebView receives serialized state
and cannot directly access the filesystem, shell, process, or Windows settings.

The active command surface exposes runtime snapshot reads, connect/disconnect/
restart, NodeCatalog list/switch/delay test and selector check, local profile or
explicit HTTP(S) subscription import/update, managed configuration validation,
sing-box install, login preferences, diagnostics generation, and explicit
service/certificate/driver/HTTPS MITM operations. The frontend only renders these results
and submits command parameters; it does not own a second runtime state model.

## Runtime Truth

`Connected` is emitted only when all of these are true:

1. SCM reports `Running` for `AnixOpsNetworkCore`.
2. The service-owned state records an enabled running sing-box child whose
   generated configuration passed `sing-box check -c`.
3. The configured loopback proxy listener accepts a bounded connection.
4. A generated NodeCatalog profile's loopback selector API is readable and its
   active outbound equals the generated selector default.
5. The GUI can query that exact child PID and it is still active.
6. The current interactive user's WinINet proxy exactly matches the enabled
   managed server and bypass settings.

For an enabled Mieru plan, the Service's official `status` readback and exact
configured SOCKS5 listener replace the sing-box PID and selector evidence. The
GUI still requires SCM and exact current-user proxy evidence; it does not
invent a Mieru PID or require a selector API that the selected engine does not
provide.

The managed JSON is never sufficient by itself. Configuration JSON errors map
to `Configuration error`; a failed transition or an exited PID maps to `Core
error`; SCM pending states map to `Connecting` or `Disconnecting`.

Connect validates managed JSON and runs the existing `sing-box check -c`
preflight, submits the service start, waits off the UI thread for SCM, the core
PID, and the configured loopback listener. A NetworkCore-generated NodeCatalog
profile also requires its loopback Clash selector API to respond. Only then does
the GUI apply the configured proxy for the interactive user and atomically
persist its snapshot plus the exact GUI-applied proxy settings. Disconnect
restores it before stopping the service only when the current proxy still
exactly matches the GUI-owned setting. A later GUI startup or status refresh
uses the same rule after the service/core are no longer valid; it never
overwrites a user-changed proxy.

For a desktop-owned daily profile, Advanced `Restart service` runs that same
preflight before changing the runtime, restores the GUI-owned proxy, stops the
service, and reuses the full readiness path before applying the proxy again.
Service-owned advanced configurations keep their existing service lifecycle and
do not become a GUI-owned desktop connection.

Managed configuration schema 2 makes proxy ownership explicit. Existing schema
1 data migrates in memory to `Service`, preserving CLI/service behavior. A GUI
profile import writes `Desktop`, so the user-session GUI is the sole owner of
its current-user snapshot while the service continues to own core and other
runtime resources.

## Control Map

| Control | Status | Backend |
| --- | --- | --- |
| Connect / Disconnect | Active | Managed config preflight, SCM start/stop, core PID, loopback listener and generated selector API observation, then current-user proxy snapshot/rollback. |
| Restart service | Active | Desktop-owned daily profile: preflight, GUI-owned proxy restore, stop, and the same verified connection path. Service-owned advanced configuration: existing SCM restart path only. |
| Refresh | Active | Runtime observation only; no mutation. |
| Node list / filter | Active | The persisted NodeCatalog is exposed after a successful generated-profile import and filtered locally in the React view. |
| Filter / selected node | Active | The React view filters the persisted NodeCatalog locally; a selector-generated profile persists the selected node ID and configuration hash. |
| Switch active | Active | Loopback-only generated selector PATCH/readback, then an atomic update of that generated selector's restart default. A failed config commit requests selector rollback to the previously observed outbound. |
| Test delay | Active | One loopback Clash API delay request with the configured timeout. |
| Fastest node selection | Active | The explicit action and opt-in 30-minute monitor measure imported generated-selector nodes through the loopback controller, select the lowest successful delay, and persist the controller switch. |
| Check core | Active | One loopback selector read. |
| Import profile / Update saved URL | Active | Explicit input fetch followed by the existing generated-profile/native-JSON import path while the service is stopped. A sing-box plan clears the mutually exclusive Mieru plan; managed-config failure restores the prior sing-box JSON. Fetch failure leaves current managed config untouched. |
| Automatic subscription refresh | Active | An opt-in monitor attempts the saved HTTP(S) URL once per hour. It uses the same stopped-service import boundary and records an error without replacing the managed configuration when refresh cannot run. |
| Install sing-box | Active | Existing official-release installer and digest-aware adapter path. |
| Validate | Active | Managed schema validation and non-mutating `sing-box check -c`. |
| Diagnostics report | Active | Existing bounded report path. |
| Manual proxy recovery | Active | Restores only a GUI-owned snapshot whose current proxy still exactly matches the GUI-applied settings; otherwise it clears stale ownership without changing the user proxy. |
| Managed TUN | Active but advanced | Accepts the existing validated `WindowsManagedTunnelConfig` JSON. The Windows service performs EasyTier protected-storage preparation, start/status/stop, and rollback. |
| Managed DNS | Active but advanced | Shows whether the active profile contains DNS, accepts one sing-box top-level `dns` JSON block, and rewrites only the stopped active managed config; generated-profile selector state is rehashed after the write. |
| Native outbound groups | Active but advanced | Lists every active native outbound with `outbounds`; selector members can be selected directly, and any listed group can be replaced with validated same-tag JSON while the service is stopped. |
| Script dispatch | Active but advanced | Shows whether a runtime is configured and accepts a local MITM policy source, Node runner, URL-to-local-script mapping, and optional store. The stopped service loads the policy and executor together on its next start; it never downloads remote scripts. |
| MITM enable / disable | Active | Enabling regenerates the imported profile at the local SOCKS upstream, preserves native JSON before changing its loopback listener, and configures the service-owned native HTTPS proxy. Disabling restores the native snapshot or the standard loopback listener, removes the service-recorded MITM CA, then restores the prior service state. |
| Certificate and driver | Active but advanced | Existing explicit mutation and rollback operations; not part of the connect path. |
| Start after login | Active | Exact current-user `HKCU\...\Run\AnixOpsNetworkCore` entry, queried from Windows and removed only when its command matches this GUI. |
| Auto-connect | Active | Tauri startup reads the persisted preference and submits one existing desktop connection attempt when the runtime is not already connected. |
| One core recovery | Active | A two-second Tauri background monitor observes the existing runtime status and, after a GUI-started connection enters `CoreError`, submits at most one existing desktop connection attempt. |
| Single instance | Active | The official Tauri single-instance plugin focuses the existing main window when a later launch is requested. |
| System tray | Active | Closing the main window hides it; the persistent tray menu restores the window or explicitly exits the process. |
| Subscription catalog | Active | The desktop state stores multiple local or HTTP(S) sources with each source's last refresh result. Selecting one regenerates the single active managed profile while the service is stopped; automatic refresh applies only to that active saved HTTP(S) source. |
| HTTP/2/HTTP/3 MITM | Blocked | Existing platform and MITM boundaries remain unchanged. |

## Responsiveness And Failure Handling

Commands that can wait on network, SCM, process preflight, registry,
certificate/driver APIs, or managed-config filesystem I/O execute through Tauri
blocking workers. The frontend allows one pending operation at a time and disables
repeat requests with an in-page message. Pure in-memory rendering commands remain
direct command calls. A completion refreshes the selected node, delay result,
core path, desktop snapshot, or concise failure message.

Failed selector switches update neither the persisted selected node nor the
selector view. After a successful selector PATCH, a failed restart-default
commit requests a rollback to the previously observed outbound. A failed
subscription fetch produces no config write. Ordinary
operation failures are displayed in-page with a diagnostics route instead of a
blocking message box; only startup-fatal errors use a modal dialog.

An interrupted GUI-owned proxy is automatically recovered only once after the
runtime is conclusively stopped and its owned core is absent. A failed attempt
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
- No network, non-administrator elevation rejection, missing service/core,
  port collision, sleep/resume, and reboot recovery.
- Interactive-user proxy rollback after a core exit while the GUI is open and
  after reopening the GUI.
- Tray double-click/menu behavior, login startup toggle, auto-connect once,
  one-shot core restart, startup-entry removal during MSI uninstall, and tray
  icon recovery after an Explorer restart or primary-display DPI change.
- Restart after a generated local or HTTP(S) profile import with networking
  disabled: the unchanged managed config must restore node names/protocols
  locally; an externally changed config must not restore that stale catalog.
- Enable and disable HTTPS MITM for both an operator-provided native sing-box
  JSON profile and a generated NodeCatalog profile. Confirm the service proxy
  changes to the local MITM listener, the native JSON listener is restored from
  its snapshot, and the service-recorded CA is removed during disable.
- Enable the hourly saved-subscription refresh, leave the service stopped, and
  confirm a successful update is recorded. Repeat with the service running and
  confirm the existing configuration stays unchanged while the update error is
  recorded.
- Use `Select fastest` with multiple reachable nodes and then enable its
  30-minute monitor. Confirm the loopback selector and persisted active node
  match the lowest successful delay; unavailable nodes must not replace the
  active node.
- Provide a verified EasyTier tunnel JSON, start the Windows service, and
  record the protected tunnel acceptance evidence required by the existing
  Windows tunnel manual acceptance contract.
- With the service stopped, save a valid sing-box `dns` block, start the
  service, and confirm the active config contains that block. Stop the service,
  clear it, and confirm the block is removed before the next start.
- With native HTTPS MITM enabled and the service stopped, save a local policy
  source containing a `[Script]` rule, a local Node runner, and a mapped local
  script asset. Start the service and confirm a matching request produces the
  native script-executed diagnostic; clear the runtime and confirm it no longer
  loads on the next service start.
- Import a native sing-box profile with selector and non-selector outbound
  groups, stop the service, choose a selector member, then edit one group JSON.
  Confirm the selected group alone changes before the next service start.

GitHub Actions remains the sole environment for TypeScript checks, frontend builds,
Rust tests/builds, MSI
install/uninstall, and portable archive validation.
