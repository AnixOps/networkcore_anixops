# Windows EasyTier Foreground Tunnel Design

**Status:** Approved for implementation planning

**Date:** 2026-07-20

**Approved approach:** NetworkCore orchestrates an explicitly installed and version-pinned
EasyTier executable. EasyTier owns the Windows TUN/overlay data plane; NetworkCore owns
delivery verification, POP selection, lifecycle policy, route safety, and audit output.

## Goal

Add the first Windows data-plane slice that a maintainer can run manually on an elevated
Windows host: verify a signed NetworkCore client/POP delivery pair, start one foreground
EasyTier tunnel to one selected Linux POP, observe the resulting peer/route state, and stop
the session with deterministic cleanup. The acceptance path must carry real `ping` and `curl`
traffic to a test subnet behind the POP.

## Context and Constraints

The existing `networkcore-windows` artifact is read-only and exposes only capability/status
commands. `config-core` already verifies immutable Ed25519-signed SD-WAN delivery envelopes,
including client POP references and POP route policies. `platform-windows` currently reports
driver, service, installer, proxy, trust-store, and managed-lifecycle operations as blocked.

The repository rules remain in force:

- Local machines may edit files and run Git operations, but must not run Rust tests, builds,
  packaging, or release commands.
- GitHub Actions is the source of truth for format, lint, test, build, dependency audit, and
  package verification.
- No remote subscription fetch, binary download, or secret retrieval is performed by the
  client.
- System proxy, system trust-store, MITM CA, JavaScript dispatch, and automatic service
  registration stay outside this feature.
- Every mutation requires an explicit command and `--confirm`; all invalid or untrusted input
  fails closed.

EasyTier is treated as an external runtime dependency in this first slice. Its upstream
project documents Windows support, administrator-required startup, encrypted overlay nodes,
subnet proxying, and route inspection through `easytier-cli`. The NetworkCore package will not
copy or redistribute EasyTier or a Wintun binary yet; the operator supplies an approved,
version-pinned EasyTier installation and an explicit executable path.

## Scope

### Included

1. A Windows foreground tunnel command family:

   ```text
   networkcore-windows tunnel start <client-envelope> <pop-envelope>
     --pop-id <id>
     --device-id <id>
     --delivery-public-key-file <path>
     --easytier-bin <path>
     --easytier-cli <path>
     --easytier-version <version>
     --easytier-sha256 <hex>
     --network-name <name>
     --network-secret-file <path>
     --state-dir <path>
     --confirm

   networkcore-windows tunnel status <state-file> --format text|json
   networkcore-windows tunnel stop <state-file> --confirm
   ```

2. Delivery verification before any process or route change:

   - verify both envelopes with the configured Ed25519 public key and a trusted current clock;
   - require `bundle_kind=client` for the client envelope and `bundle_kind=pop` for the POP
     envelope;
   - require matching tenant identity and a client target matching the explicit `--device-id`;
   - reject expired envelopes, and reject a sequence that is not greater than the persisted
     last accepted sequence for the same `(tenant_id, bundle_kind, target_id)` identity. Client
     and POP sequences are tracked independently and are never compared with each other;
   - reject unknown transport values and POP references absent from the client profile;
   - accept only the `easytier` transport in this slice.

3. A pure tunnel plan that selects exactly one entry POP and produces a redacted EasyTier
   launch specification. The plan contains the selected endpoint, target route metadata,
   session identifier, delivery digests, and an explicit endpoint-bypass requirement. It never
   contains the network secret value.

4. A Windows platform adapter that:

   - validates the explicit EasyTier executable and CLI paths without downloading anything;
   - checks the executable version and configured SHA-256 pin before launch;
   - reads the secret from an operator-provided file with restrictive ACL expectations;
   - renders a session-owned TOML config and invokes EasyTier with its explicit `--config-file`
     option plus `--disable-env-parsing`; the secret is never passed as an argument, environment
     variable, diagnostic, or process display string;
   - launches EasyTier in the foreground with a dedicated session/state directory;
   - queries `easytier-cli` through the explicit CLI path for peer and route readiness;
   - records only redacted session state and diagnostics;
   - stops only the process owned by the current session and removes only routes/resources
     created by that session.

5. A fail-closed route safety sequence:

   - resolve and preserve a physical-interface bypass route to every EasyTier control/peer
     endpoint before enabling the virtual network route;
   - do not request a default route or destination route until the EasyTier peer and route
     readiness checks succeed;
   - if readiness fails, stop the owned EasyTier process and restore the pre-session route
     snapshot;
   - on explicit stop, remove the session-owned virtual route and then terminate EasyTier;
   - report `rollback_failed` separately when cleanup cannot be proven complete.

6. A manual Windows/Linux POP acceptance record in `docs/manual-intervention.md` covering
   host versions, EasyTier version and hashes, delivery bundle digests, route snapshots,
   `easytier-cli peer`/`route` output summaries, and `ping`/`curl` results.

### Excluded

- Windows GUI screens, tray application, service auto-start, MSI/winget installer, or device
  enrollment.
- Bundling or redistributing EasyTier, Wintun, or any kernel driver.
- Multi-POP failover, client-side multi-hop service-chain execution, dynamic route hot reload,
  DNS interception, full-tunnel kill switch, or IPv6 policy routing.
- MITM certificate installation, system proxy mutation, browser policy, or script execution.
- Automatic controller/POP discovery or downloading a signed delivery/secret from the network.

The POP delivery's service-chain metadata remains a server-side contract in this slice. The
Windows client selects the entry POP; the Linux POP is responsible for applying its verified
route chain to downstream hops.

## Architecture

### Delivery and planning layer

`config-core` remains the only parser/verifier for signed delivery envelopes. A new pure
planning API converts a verified client/POP pair into a `WindowsTunnelPlan`:

```text
WindowsTunnelPlan {
    session_id,
    tenant_id,
    client_bundle_id,
    pop_bundle_id,
    selected_pop_id,
    selected_endpoint,
    transport = "easytier",
    route_intent,
    endpoint_bypass_required = true,
    delivery_digests,
}
```

The plan rejects ambiguous POP selection and unsupported transport before any platform API is
called. Route intent is derived from the verified POP route metadata but is bounded to the
single entry POP in this first slice.

### Windows adapter layer

`platform-windows` gains an adapter boundary rather than embedding EasyTier internals:

- `EasyTierCommandBuilder` is a pure builder for the pinned EasyTier version's arguments and
  configuration file shape. Its debug/display representation redacts the network secret.
- `WindowsTunnelSessionPort` owns start/status/stop operations and returns stable domain
  diagnostics rather than raw process errors.
- `EasyTierProcessRunner` and `EasyTierCliRunner` are injected ports. Production uses Windows
  process execution; contract tests use deterministic fakes. A fresh service instance must first
  obtain an exact process-recovery proof through `EasyTierProcessRunner` before it can query the
  CLI or clean up a persisted session.
- `WindowsRoutePort` owns the endpoint bypass and session-owned route transaction. It never
  accepts a route mutation without a session token produced by `WindowsTunnelPlan`.

   `control-runtime` is not given arbitrary process-spawn responsibilities. The platform adapter
contains the OS-specific process and route mechanics, while the pure plan and lifecycle result
types remain reusable by future GUI or service adapters.

The generated EasyTier config is deleted after a successful stop and retained only on a
failed-cleanup path for manual recovery. It contains the selected peer, network identity,
virtual address, and destination route settings derived from the verified plan. The adapter
accepts only the configured EasyTier version/hash and refuses to launch an unpinned executable.

Persisted foreground state uses schema v2. It records an owned PID, a nonempty creation marker,
the pinned binary hash, a single CLI file name, a single redacted config file name, and destination
CIDRs, but never an absolute executable, CLI, or config path. Schema-v1 records are unrecoverable.
A fresh invocation canonicalizes the existing state directory and requires matching PID,
creation-marker, hash, config, and CLI proof before any `status` or `stop` action. Native recovery
remains fail-closed until a later slice supplies the platform-specific proof.

### CLI layer

`apps/windows-cli` parses the tunnel command and delegates to the injected platform session
service. It renders text and JSON with the same stable fields:

- `session_id`, `state`, `selected_pop_id`, `selected_endpoint`;
- `delivery_bundle_id`, `delivery_sequence`, `plan_digest`;
- `easytier_version`, `peer_ready`, `route_ready`, `route_count`;
- `system_mutation_policy`, `rollback_status`, and redacted diagnostics.

The CLI must refuse `start` without `--confirm`, an explicit state directory, explicit binary
paths, and the network-secret file. It must not print the secret, raw command line, or full
delivery payload.

## Data Flow

1. Operator supplies signed client and POP envelope files, the local device identity, a public
   key file, pinned EasyTier paths/version/hash, a network name, a secret file, and an explicit
   state directory.
2. CLI parses arguments and requests the delivery verifier to verify both envelopes at one
   trusted `now` value.
3. The pure planner checks identity, expiry, sequence, transport, POP selection, and route
   intent. It emits a redacted plan or a stable rejection diagnostic.
4. The Windows adapter validates administrator context, executable hashes, secret-file ACL
   expectations, and the physical endpoint bypass route.
5. The adapter writes a session-owned EasyTier configuration artifact under the state
   directory, launches the explicit EasyTier binary, and waits for peer/route readiness from
   the explicit EasyTier CLI.
6. Only after readiness does the adapter expose `state=running` and allow the operator to run
   traffic tests.
7. `status` reads a schema-v2 session record and, for a fresh service instance, first requires an
   exact injected ownership proof before performing an explicit EasyTier CLI health query. It does
   not scan arbitrary processes or infer liveness from a stale PID.
8. `stop` requires the same proof before it removes the session-owned route or terminates the
   owned EasyTier process. The state record is retained as redacted audit evidence.

## Error and Security Model

Stable diagnostics for this slice include:

```text
windows.tunnel.confirmation_required
windows.tunnel.delivery_invalid
windows.tunnel.delivery_expired
windows.tunnel.sequence_replayed
windows.tunnel.target_mismatch
windows.tunnel.transport_unsupported
windows.tunnel.pop_not_selected
windows.tunnel.easytier_binary_invalid
windows.tunnel.easytier_version_mismatch
windows.tunnel.secret_file_invalid
windows.tunnel.admin_required
windows.tunnel.endpoint_bypass_failed
windows.tunnel.start_failed
windows.tunnel.peer_not_ready
windows.tunnel.route_not_ready
windows.tunnel.status_unavailable
windows.tunnel.stop_failed
windows.tunnel.rollback_failed
```

The adapter fails closed on every preflight error. It must not fall back to a different
EasyTier binary, a different POP, a direct route, or an unverified delivery. A failed start
must leave no session-owned route or running EasyTier process; inability to prove that cleanup
occurred is reported as `rollback_failed` and requires manual intervention.

The network secret is never part of a signed delivery log, process argument string, diagnostic,
JSON response, or GitHub Actions output. CI uses synthetic non-secret fixtures only. Manual
testing uses a local secret file outside the repository.

## Testing and Acceptance

### Automated CI contracts

GitHub Actions must cover:

- command parsing and `--confirm`/path requirements;
- client/POP identity, expiry, sequence, transport, and POP-selection rejection paths;
- independent per-bundle sequence replay rejection and persisted sequence-floor handling;
- deterministic EasyTier command/config generation with secret redaction;
- executable version/hash mismatch and missing-secret diagnostics;
- endpoint bypass transaction ordering and rollback on process/readiness failure;
- status/stop ownership checks and stale-session refusal;
- Windows target format, lint, test, build, dependency audit, and package manifest checks.

No automated job claims that a GitHub-hosted Windows runner established a real tunnel. The
workflow records the distinction between contract verification and manual data-plane evidence.

### Manual end-to-end acceptance

The operator provides one Linux POP and one Windows 11 x64 host. The POP advertises one test
CIDR behind it and uses the same EasyTier network identity as the client. The acceptance record
must show:

1. Pre-start route/process snapshot.
2. Successful `tunnel start` output with the selected POP and redacted plan digest.
3. EasyTier peer and route readiness.
4. Successful `ping` to the EasyTier virtual address.
5. Successful `ping` and `curl` to a host in the POP test CIDR.
6. A negative route test proving an unadvertised CIDR is not sent through the POP.
7. Successful `tunnel status` output.
8. `tunnel stop` output and a post-stop route/process snapshot matching the pre-start state.

The first slice is considered usable only when all eight records are present. A green CI run
alone is not sufficient evidence of Windows packet forwarding.

## Packaging and Rollout

The first artifact remains a manually extracted NetworkCore CLI and documents the required
external EasyTier version/hash. It does not contain a driver, EasyTier binary, installer, or
service registration. A later packaging slice may bundle approved EasyTier/Wintun artifacts
only after license/NOTICE, provenance, Authenticode, rollback, and driver-install contracts are
implemented.

The existing read-only capability fields change only after this foreground path is implemented
and manually accepted. Until then, `windows-driver`, `windows-service`, and `windows-installer`
remain reported as blocked even though the operator can run an externally installed EasyTier
binary for this explicitly confirmed test.
