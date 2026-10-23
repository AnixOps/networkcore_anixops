# networkcore-linux

`networkcore-linux` is the Linux CLI entrypoint for NetworkCore. This README describes current `main` source.
Release state lives in the repository [README](../../README.md); the per-version feature and boundary index is
`docs/alpha-release-feature-matrix.md`. All validation runs in GitHub Actions according to `docs/ci-cd-policy.md`.

P4 current stage source of truth: this crate is in P4 Client And Platform Integration. P3 Runtime Capability
Baseline is completed history. The active P4 backlog buckets are subscription/client compatibility, MITM data plane
plus certificate lifecycle, and browser capture user flow completion; P3 wording in older changelog or roadmap
entries is historical context only.

## Safety boundary

The CLI does not modify TUN, DNS, routing, firewall, system trust stores, browser trust stores, or profile trust
state, and it never scans default locations. Every command that writes host state requires explicit absolute paths,
a snapshot, and `--confirm`. The exceptions are narrow and named: one NetworkCore systemd unit, one environment proxy
file, one Ubuntu-style CA trust file, and operator-selected certificate/PAC/policy/profile-prefs artifacts.

## Command overview

| Area | Commands |
|---|---|
| Basics | `help`, `version`, `capabilities`, `status`, `diagnostics`, `prepare-config` |
| Foreground runtime | `start`, `stop`, `connect`, `disconnect`, `restart`, `reload`, `rollback` |
| Public engines | `install-sing-box` / `sing-box install`, `run-url`, `run-catalog`, `core list`, `core install/start/stop/status mieru` |
| Nodes | `node list`, `node select`, `node switch`, `node health` |
| Subscriptions | `subscription add/list/remove/select/update/rollback`, `subscription refresh start/status/stop`, `subscription refresh schedule install/status/stop/uninstall` |
| systemd | `install-service`, `uninstall-service`, `service start|stop|restart|status`, `service reload` |
| Environment proxy | `proxy apply/status/rollback` |
| Managed records | `managed-status`, `managed-event`, `managed-log` / `logs` |
| MITM | `mitm status/diagnostics/certificate-plan/browser-plan`, `mitm certificate apply/rollback/trust-apply/trust-rollback`, `mitm http-rewrite plan/preview`, `mitm browser-capture plan/launch-plan/session-plan/launch/apply/rollback/verify/traffic-proof` |

## Foreground runtime

`start` wires `engine-native::NativeProxyEngineService` through `RuntimeOrchestrator` with the built-in
`networkcore.adblock` MITM plugin hook. It is foreground-only: Unix `SIGINT`/`SIGTERM` and injected lifecycle
interruption map to `cli.linux.start.lifecycle_interrupted` with exit code 130, after which the in-process runtime is
stopped and native release diagnostics such as `engine.native.runtime.accept_loop_stopped` and
`engine.native.runtime.released` are aggregated.

**Managed recording.** `start --managed-status <status.json> --managed-snapshot <starting.snapshot.json> --managed-events <event-directory>`
(all three together) records `starting`, `running`, `stopped`, or `failed` with non-overwriting status snapshots and
bounded schema-versioned event records. Recorded state never claims process liveness.

**Control socket (Unix).** The same managed start can add `--managed-control-socket <absolute-path>`. NetworkCore
creates the socket without replacing an existing path, applies owner-only `0600`, and accepts only bounded `stop`,
`reload`, or `rollback` requests with a two-second I/O deadline:

- `stop --managed-control-socket <path> --confirm` interrupts and releases the foreground runtime.
- `reload --managed-control-socket <path> --confirm` reloads it from its explicit start configuration.
- `rollback --managed-control-socket <path> --expected-config-version <n> --confirm` restores the owner-retained prior
  successful configuration only when the version matches, the `Running` check succeeds, and health readback passes.
- `status --managed-control-socket <path>` reports the bounded, redacted runtime health record.

No default socket, PID lookup, or non-Unix fallback exists; see
`docs/architecture/linux-managed-runtime-health-source-contract.md`.

## Public engines and subscriptions

`install-sing-box` uses the `engine-singbox` latest release installer. `run-url <share-link-or-file-uri-or-https-url> [--node-id <id>]`
and `run-catalog <catalog-path> <source-id>` parse input with `config-core` and first create a `PublicEngineRunPlan`:

- Direct `ss://`, `trojan://`, `vless://`, `vmess://`, `hysteria2://`/`hy2://`, and `tuic://` links, supported Clash
  YAML, sing-box JSON, and Surge/Loon/Quantumult X catalog payloads, one explicit absolute `file://` UTF-8 subscription
  file, or one bounded HTTP(S) subscription fetch are accepted.
- Shadowsocks, Trojan, VLESS, VMess, Hysteria2, and TUIC run through the foreground sing-box flow.
- A `mierus://` node uses engine-mieru and requires `--binary <local-path> --sha256 <digest>`; the CLI renders an
  atomic local config with rollback snapshot, invokes official apply/start, and requires a reachable loopback SOCKS5
  listener. Failures return a stable redacted error and do not replace an existing config or running core.
- `--node-id <id>` selects one normalized catalog node; otherwise the first node is used.

`core list` reports registered public engine descriptors. `core install mieru --binary <path> --sha256 <digest>` only
verifies an operator-provided executable. `core start|stop|status mieru --binary <path> --sha256 <digest> --config <path>`
drive the official client's `apply config`, `start`, `stop`, and `status` with a regular absolute config file, never
echoing the client's stdout/stderr.

**Persistent catalog.** `CommandSubscriptionCatalogStore` keeps a local schema version 1 JSON catalog:
`CommandSubscriptionCatalogStore::add_source`, `CommandSubscriptionCatalogStore::list_sources`,
`CommandSubscriptionCatalogStore::remove_source`, `CommandSubscriptionCatalogStore::select_source`,
`CommandSubscriptionCatalogStore::update_source`, and `CommandSubscriptionCatalogStore::rollback_catalog`.
Add/remove/update need explicit catalog and snapshot paths, duplicate or missing ids are rejected, reports are
redacted, and rollback restores a validated snapshot while retaining it.

**Refresh.** `subscription refresh start` refreshes one saved HTTP(S) source after candidate validation, writing only
explicit catalog/status/snapshot paths with confirmation; `status` and `stop` operate on that status record. It never
restarts the core, switches nodes, or changes system settings. `subscription refresh schedule install` additionally
needs a source ID, interval, unit base name, and `--confirm`; it writes a NetworkCore-owned oneshot service plus
persistent timer (no URL or credentials in the units), reloads systemd, and verifies the timer. Identical reinstall is
idempotent, external changes are rejected, and `schedule stop`/`uninstall` retain the final status record.

## systemd service

`install-service --service-executable <absolute-path> --confirm` renders and writes an explicit unit through
`platform-linux::systemd`, with optional `--service-unit`, `--service-description`, `--service-arg`, `--service-user`,
`--service-group`, and `--service-state-dir`. An existing unit is snapshotted under the state directory first and the
written content is verified; installation runs `systemctl daemon-reload` but never enables or starts the unit.

- `service start|stop|restart|status --service-unit <name> --confirm` controls that one unit through `systemctl`
  (status uses `systemctl is-active`).
- `service reload` sends `systemctl reload` to the managed unit.
- `connect`, `disconnect`, and `restart` with `--confirm [--service-unit <name>]` are aliases for service
  start/stop/restart. Without a managed-service selection, `connect --config <path>` is the foreground runtime entry
  and `disconnect`/`restart` return their foreground boundary. `status --service-unit <name>` reads the unit; plain
  `status` stays platform-only.
- `uninstall-service --confirm` stops and removes the matching unit after snapshotting it; the state directory is kept.

Boundary: `docs/architecture/linux-managed-service-unit-source-contract.md`.

## Environment proxy

`proxy apply --file <absolute-path> --snapshot <absolute-path> --url <proxy-url> --confirm` manages one explicit
environment proxy file. `proxy status` is read-only; `proxy rollback --confirm` refuses to overwrite an externally
changed file. No desktop default proxy is discovered or modified.

## Managed records

All records are explicit schema version 1 files and every report fixes `liveness_verified=false`; nothing inspects a
process or controls a runtime.

- **Status.** `CommandManagedForegroundSessionStore::read_status`, `CommandManagedForegroundSessionStore::write_status`,
  `CommandManagedForegroundSessionStore::transition_status`, and `rollback_status`.
  `networkcore-linux managed-status <status-record-path>` reads; `networkcore-linux managed-status init <path> <session-id> <engine-id> <state>`
  creates without overwrite (`record_written=true`); `networkcore-linux managed-status transition <path> <snapshot-path> <expected-state> <next-state>`
  allows only `starting -> running/failed` and `running -> stopped/failed` and writes a non-overwriting snapshot
  (`snapshot_written=true`); `managed-status rollback <path> <snapshot-path> <expected-state>` restores the snapshot only
  when expected state and trimmed session/engine identity match, retaining it (`snapshot_retained=true`).
- **Events.** `CommandManagedForegroundSessionEventStore::read_event` and `CommandManagedForegroundSessionEventStore::write_event`
  read or non-overwritingly write one event (session/engine/event ids, allowed kind, state, caller timestamp).
  `networkcore-linux managed-event <event-record-path>` reads; `networkcore-linux managed-event init <path> <session-id> <engine-id> <event-id> <event-kind> <state> <recorded-at>`
  creates. `CommandManagedForegroundSessionEventStore::list_event_history` backs
  `networkcore-linux managed-event list <event-directory> [--session-id <id>] [--event-kind <kind>] [--state <state>] [--cursor <offset>] [--limit <1-100>]`:
  direct regular JSON files only (no recursion, symlinks skipped), every candidate validated before exact filtering,
  sorted by `(recorded_at, event_id, event_path)`, offset paging; caps are 100 per page, 256 per directory, 65536
  bytes per record.
- **Logs.** `CommandManagedForegroundSessionLogStore::read_tail` backs `managed-log <log-file-path> [--tail-lines <1-1000>]`
  (alias `logs`): one explicit regular UTF-8 file up to 65536 bytes, at most 1000 final lines, URLs and common
  credential values redacted. JSON output is `managed_foreground_log_tail` with `returned_byte_count` (UTF-8 bytes of
  returned line contents, excluding separators). No creation, default search, or live streaming.

## MITM

The `mitm` commands implement the partial `MITM_CLI_COMMAND_GATE` surface: they load the built-in `networkcore.adblock`
policy through `mitm-policy`, emit `mitm_status` JSON, and report `mitm-cli-command-gate-status=partial-active`.
`start` loads the same plugin into `engine-native`: a plugin `Reject` becomes a SOCKS5 general failure at the explicit
CONNECT layer before outbound selection, and CONNECT hook diagnostics
(`engine.native.runtime.http_mitm_connect_browser_proof_observed`) emit the default browser proof token.

### Certificates

`certificate-plan` exposes `mitm_status.certificate_plan` (certificate state, artifact lifecycle steps, dedicated
profile trust artifact step, trust blocked operations, `mutation_ready=false`).

- `mitm certificate apply --confirm --cert-file <path> --key-file <path> [--profile-trust-file <path>] --snapshot <path>`
  writes operator-provided CA certificate PEM, private key PEM, an optional dedicated profile CA PEM copy, and a
  rollback snapshot through `CommandMitmCertificateArtifactStore`, reporting `certificate_lifecycle`,
  `LinuxMitmCertificateArtifactRequest`, `profile_trust_file_path`, `profile_trust_content`,
  `profile_trust_fingerprint`, `LinuxMitmCertificateApplyReport`, and `trust_plan`.
- `mitm certificate rollback --snapshot <path>` removes those artifacts when the snapshot fingerprint still matches.
- `mitm certificate trust-apply --cert-file <path> --trust-file <absolute-path> --snapshot <absolute-path> --confirm`
  manages an Ubuntu-style CA trust file and refreshes it through `update-ca-certificates`; `trust-rollback` restores the
  matching snapshot. Written PEM is verified, symlinks and external changes are refused, and distro defaults, NSS,
  p11-kit, Firefox, and browser profiles are not touched.

Boundary: `docs/architecture/linux-mitm-certificate-lifecycle-source-contract.md`.

### HTTP rewrite and controlled HTTPS

`http-rewrite plan` exposes `MITM_HTTP_TLS_DATA_PLANE_GATE=plain-http-live-data-plane-active/tls-decryption-blocked`.
`http-rewrite preview --confirm --url <url>` builds a `NativePlainHttpMessage`, invokes the plugin, and applies
reject/redirect/header/body outcomes to caller-provided plain HTTP input. For caller-provided `https://` input it also
reports request preview (`https_request_rewrite_preview_ready=true`) and response header/body preview
(`https_response_rewrite_preview_ready=true`, via `NativeHttpsResponseRewritePreviewReport`) once the controlled TLS
termination plan (`NativeControlledTlsTerminationPlanReport`) is ready. The preview report stays preview-only:
`https_response_rewrite_ready=false`, `script_dispatch_ready=false`, `tls_decryption_ready=false`,
`certificate_pinning_bypass_supported=false`, `http2_mitm_supported=false`, `http3_quic_mitm_supported=false`.

The native `ListenerKind::Http` explicit proxy parses real `http://` HTTP/1.x traffic through
`NativeExplicitHttpProxyRequest`, applies reject/redirect/header/body rewrite around SOCKS outbound forwarding, and
supports an explicit `CONNECT` pass-through tunnel that can bounded-peek the TLS ClientHello/SNI.

**Controlled HTTPS (`v0.1.2-alpha.3`).** `start --enable-https-mitm --mitm-ca-cert <ca.pem> --mitm-ca-key <ca.key> --confirm`
issues an authority-bound leaf, decrypts up to four bounded HTTP/1.1 request/response exchanges per TLS session,
forwards upstream with web-PKI validation, and applies the plugin hook in both phases. The session closes on HTTP close
semantics, terminal rewrite, parse failure, or the exchange budget.

**Local scripts.** `start --enable-script-runtime --script-runner <local-runner> --script-map <script-url>=<local-file> [--script-map ...] [--node-binary <path>] --confirm`
attaches the local Node executor. Runner and assets must be local regular non-symlink files; each asset is SHA-256
pinned at creation and rechecked before dispatch. Node runs in a fresh no-network namespace with read-only permission
for the runner, mapped asset, and staged bounded body; no store, write, child-process, addon, or network permission;
V8 old-space capped at 64 MiB; `unshare --kill-child` ends timed-out sandboxes. Failing scripts are fail-open and
reported as `script_dispatch_failed`, preserving validated non-script rewrites. Script URLs are never downloaded and
`--script-store` is rejected.

CA trust, browser/system proxy mutation, HTTP/2, unbounded streaming, and cross-session relay remain blocked.
Boundary: `docs/architecture/linux-mitm-http-rewrite-source-contract.md`.

### Browser capture

`browser-plan` exposes `mitm_status.browser_plan` with the planned explicit proxy `127.0.0.1:7890`, required steps,
blocked operations, and `mutation_ready=false`. `browser-capture` emits a `browser_capture` report:

| Subcommand | Behavior |
|---|---|
| `plan` | Read-only plan |
| `launch-plan` | Manual dedicated-profile browser command templates bound to the plugin and planned proxy URL |
| `session-plan <ss://url>` | Redacted subscription-to-local-proxy/browser/verify/traffic-proof plan with selected node and plugin metadata; starts nothing |
| `launch --confirm` | Starts a dedicated profile through `BrowserCaptureProcessRunner` with `--proxy-server` and `--user-data-dir`; records `launch_report`, pid, profile, proxy, target/proof URLs, proof token/log, args, plugin metadata |
| `verify --confirm` | `BrowserCaptureEndpointProbe` checks the planned local proxy endpoint (`verify_report`); with `--target-url` it performs target route verify via HTTP CONNECT (`probe=http-connect-target`, `target_reachable`) |
| `traffic-proof --confirm [--target-url <url>] [--proof-token <token>] [--proof-log <path>]` | `BrowserCaptureTrafficProofProbe` inspects an operator-provided proof log (`traffic_proof_report`, `proof-log-token`, `proof_connect_authority`); one log line must bind token, proxy URL, and CONNECT authority or the result is `binding_mismatch`; text output prints the CONNECT authority |
| `apply --confirm --pac-file <path> [--policy-file <path>] [--profile-prefs-file <path>] --snapshot <path>` | `BrowserCapturePacFileStore` writes a NetworkCore PAC file, optional Chromium/Chrome managed proxy policy, optional Firefox dedicated profile prefs, and a snapshot; reports `LinuxBrowserCapturePacRequest`, `pac_file_path`, `pac_url`, `policy_file_path`, `policy_url`, `profile_prefs_file_path`, `profile_prefs_content`, `apply_report` |
| `rollback --snapshot <path>` | Removes or restores the NetworkCore-created artifacts from the snapshot |

`session-plan` and `launch` accept `--target-url <url>`; the CLI appends `networkcore_proof_token` to produce
`proof_target_url` and emits a matching `traffic_proof_command`. When token/log are omitted, `traffic-proof` uses the
same default binding, derived from the target CONNECT endpoint plus proxy URL, so it matches the native CONNECT
diagnostic. `session-plan`, `launch`, `apply`, `verify`, and `traffic-proof` accept `--proxy-scheme http|socks5`;
`socks5` plans `socks5://127.0.0.1:7890` so a dedicated browser targets the native SOCKS5 CONNECT hook.

The browser hijack path remains `deferred`. System CA trust, browser/system proxy mutation, system PAC installation,
full live browser capture automation, and HTTPS rewrite of captured browser traffic stay blocked. The mutation path is
governed by `docs/architecture/linux-mitm-browser-capture-source-contract.md`, which requires
`BrowserCaptureProcessRunner`, `LinuxBrowserCaptureLaunchRequest`, `LinuxBrowserCaptureLaunchReport`,
`BrowserCaptureAuthorization`, `BrowserCaptureEndpointProbe`, `LinuxBrowserCaptureSessionPlanRequest`,
`LinuxBrowserCaptureSessionPlanReport`, `BrowserCaptureTrafficProofProbe`, `LinuxBrowserCaptureTrafficProofRequest`,
`LinuxBrowserCaptureTrafficProofReport`, `BrowserCapturePacFileStore`, `LinuxBrowserCapturePacRequest`, and
`BrowserCaptureRollbackSnapshot` before any browser/system proxy state can be written.
