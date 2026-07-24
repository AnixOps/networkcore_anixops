# Windows GUI Daily Usability

This document defines the Windows GUI usability slice for
`v0.2.0-alpha.21` candidate baseline. It preserves the existing Rust/Win32 client, Windows
service, managed configuration schema, sing-box adapter, NodeCatalog parser,
selector API, system integration layer, MSI, and portable package.

## Source Markers

```text
windows-gui-daily-usability=active
windows-gui-information-architecture=home-nodes-subscriptions-settings-diagnostics-advanced
windows-gui-runtime-status=scm-core-pid-current-user-proxy-active
windows-gui-background-commands=service-preflight-core-install-subscription-fetch-node-switch-delay-active
windows-gui-high-risk-features=advanced-explicit-only
```

## Information Architecture

| Page | Purpose | Real backend boundary |
| --- | --- | --- |
| Home | Daily connect/disconnect and a concise runtime summary. | SCM status, managed state, owned sing-box PID probe, and current-user WinINet proxy probe. |
| Nodes | Search/filter imported NodeCatalog nodes and explicitly switch/test the generated selector. | `config-core::CoreSubscriptionService` and `engine-singbox` loopback Clash API helpers. |
| Subscriptions | Explicit local import or one saved HTTP(S) URL refresh. | GUI-owned explicit fetch plus existing NodeCatalog/native-JSON import path. No scheduler. |
| Settings | Managed JSON preflight/apply, explicit core installation, manual proxy recovery, GUI debug, and theme selection. | `platform-windows`, `engine-singbox`, and existing managed config APIs. |
| Diagnostics | Logs, core log, bounded diagnostics report, clipboard summary, and GUI debug state. | Existing ProgramData log/report contract. |
| Advanced | MITM, certificate, driver, service installation, and restart. | Existing explicit authorization, snapshot, rollback, and service paths only. |

The GUI stays on native Rust/Win32. No Web UI, Electron runtime, or UI framework
dependency is introduced. Windows threading and clipboard feature flags add no
external runtime or packaging component; they support a read-only core PID probe
and the diagnostic-copy command.

## Runtime Truth

`Connected` is emitted only when all of these are true:

1. SCM reports `Running` for `AnixOpsNetworkCore`.
2. The service-owned state records an enabled running sing-box child.
3. The GUI can query that exact child PID and it is still active.
4. The current interactive user's WinINet proxy is enabled.

The managed JSON is never sufficient by itself. Configuration JSON errors map
to `Configuration error`; a failed transition or an exited PID maps to `Core
error`; SCM pending states map to `Connecting` or `Disconnecting`.

Connect validates managed JSON and runs the existing `sing-box check -c`
preflight, submits the service start, waits off the UI thread for SCM and the
core PID, and only then applies the configured proxy for the interactive user.
That user proxy snapshot and the exact GUI-applied proxy settings are persisted
in desktop state. Disconnect restores it before stopping the service only when
the current proxy still exactly matches the GUI-owned setting. A later GUI
startup or status refresh uses the same rule after the service/core are no
longer valid; it never overwrites a user-changed proxy.

The service remains responsible for its own LocalSystem-managed proxy snapshot
and resource cleanup. The GUI does not alter the service configuration schema.

## Control Map

| Control | Status | Backend |
| --- | --- | --- |
| Connect / Disconnect | Active | Managed config preflight, SCM start/stop, core PID observation, current-user proxy snapshot/rollback. |
| Refresh | Active | Runtime observation only; no mutation. |
| Load nodes | Active | Explicit local/HTTP(S) fetch and `CoreSubscriptionService` normalization. |
| Filter / selected node | Active | In-memory imported NodeCatalog options only. |
| Switch active | Active | Loopback-only generated selector PATCH plus readback verification. |
| Test delay | Active | One loopback Clash API delay request with the configured timeout. |
| Check core | Active | One loopback selector read. |
| Import profile / Update saved URL | Active | Explicit input fetch followed by the existing generated-profile/native-JSON import path. Fetch failure leaves current managed config untouched. |
| Install sing-box | Active | Existing official-release installer and digest-aware adapter path. |
| Validate | Active | Managed schema validation and non-mutating `sing-box check -c`. |
| Open logs / report / copy summary | Active | Existing bounded report/log paths; clipboard summary is read-only. |
| Manual proxy recovery | Active | Existing GUI-owned current-user proxy snapshot/restore. |
| MITM, CA, driver | Active but advanced | Existing explicit mutation and rollback operations; not part of the connect path. |
| Start after login | Active | Exact current-user `HKCU\...\Run\AnixOpsNetworkCore` entry, queried from Windows and removed only when its command matches this GUI. |
| Auto-connect / one core recovery | Active | Persisted opt-in desktop settings; the existing background preflight/start flow runs once after GUI startup, and a GUI-started core error gets at most one preflight-gated restart. |
| System tray | Active | Shared GUI state provides open, observed status/node, connect, disconnect, refresh, and safe exit; window close hides instead of terminating. |
| Subscription groups, scheduled refresh, automatic latency selection | Blocked | No catalog scheduler, `urltest`, or background mutation is added. |
| Native JSON group editing | Not implemented | Native sing-box JSON remains pass-through. |
| TUN, DNS interception, HTTP/2/HTTP/3 MITM, script dispatch | Blocked | Existing platform and MITM boundaries remain unchanged. |

## Responsiveness And Failure Handling

The command dispatcher runs service start/stop/restart, core install, managed
configuration preflight, subscription fetch, node loading, selector switch, and
delay test outside the Win32 message loop. The window allows one pending
operation at a time and rejects a repeat request with an in-page message. A
completion returns to the UI thread to update the selected node, delay, core
path, desktop snapshot, or concise failure message.

Failed selector switches update neither the persisted selected node nor the
selector view. A failed subscription fetch produces no config write. Ordinary
operation failures are displayed in-page with a diagnostics route instead of a
blocking message box; only startup-fatal errors use a modal dialog.

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
  one-shot core restart, and startup-entry removal during MSI uninstall.

GitHub Actions remains the sole environment for Rust tests/builds, MSI
install/uninstall, and portable archive validation.
