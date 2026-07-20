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
copy, download, or redistribute EasyTier or a Wintun binary yet; the operator stages approved,
version-pinned EasyTier core and CLI files in the protected
`CommonApplicationData\AnixOps\WindowsTunnel\easytier` directory and supplies their direct-child
paths plus independent hashes.

## Scope

### Included

1. A Windows foreground tunnel command family:

   ```text
   networkcore-windows tunnel prepare-storage --confirm [--format text|json]

   networkcore-windows tunnel start <client-envelope> <pop-envelope>
     --pop-id <id>
     --device-id <id>
     --delivery-public-key-file <path>
     --easytier-bin <path>
     --easytier-cli <path>
     --easytier-version <version>
     --easytier-sha256 <hex>
     --easytier-cli-sha256 <hex>
     --network-name <name>
     --network-secret-file <path>
     --state-path <path>
     --confirm

   networkcore-windows tunnel status <state-file> --format text|json
   networkcore-windows tunnel stop <state-file> --confirm
   ```

2. Delivery verification before any process or route change:

   - read the configured public-key file as exactly 32 raw Ed25519 bytes, not PEM, base64, or
     DER, then verify both envelopes with one trusted current clock value;
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

   - creates or inspects the protected `easytier` install directory with the same exact owner,
     ACL, and non-reparse policy as the other WindowsTunnel directories;
   - accepts only existing non-reparse regular files that are direct children of `easytier` for
     `--easytier-bin` and `--easytier-cli`, without copying or downloading executable content;
   - checks the core and CLI SHA-256 pins before version, peer, route, and strict Running recovery
     commands, and rechecks the CLI immediately before every native CLI invocation;
   - treats `CommonApplicationData` as trusted, then creates or validates the fixed
     `CommonApplicationData\AnixOps\WindowsTunnel` hierarchy with direct `state`, `secrets`, and
     `easytier`
     children only; each owned directory rejects reparse points and must have owner
     BUILTIN\Administrators (`S-1-5-32-544`) with exactly SYSTEM (`S-1-5-18`) and
     BUILTIN\Administrators full-control ACL rules;
   - never repairs a pre-existing owned directory: a failed exclusive create inspects the exact
     existing component and accepts it only when its owner, DACL, and non-reparse invariants are
     already exact;
   - accepts a state file only as a safe, non-reparse direct child of `state`, and a secret only
     as a safe, non-reparse regular direct child of `secrets`; start applies the same protected
     ACL to the secret file before it is read;
   - renders a session-owned TOML config and invokes EasyTier with its explicit `--config-file`
     option plus `--disable-env-parsing`; the secret is never passed as an argument, environment
     variable, diagnostic, or process display string;
   - launches EasyTier in the foreground with a dedicated session/state directory;
   - queries `easytier-cli` through the explicit CLI path for peer and route readiness;
   - records only redacted session state and diagnostics;
   - stops only the process owned by the current session and removes only routes/resources
     created by that session.

5. A fail-closed route safety sequence:

   - snapshot each planned destination prefix from `ActiveStore`, then resolve and preserve a
     physical-interface bypass route to every EasyTier control/peer endpoint before launch;
   - accept the selected endpoint underlay only when `Find-NetRoute` resolves to an up adapter
     proven by `Get-NetAdapter -Physical`; virtual or VPN-only underlays fail before mutation;
   - after explicit peer and route readiness, capture exactly one newly added nonphysical
     `ActiveStore` tuple for every planned destination prefix; the full destination, next-hop,
     interface-index, and metric tuple is the only virtual-route ownership token;
   - if that capture cannot be proven, do not delete an unproven destination route; restore the
     endpoint bypass, stop the owned process, and return `rollback_failed` for manual recovery;
   - on explicit stop, re-prove and remove each owned virtual route before restoring the endpoint
     bypass and terminating EasyTier;
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

Every native child command crosses one trusted execution boundary. System commands accept only the
typed `PowerShell` and `route.exe` tools; their executable paths are derived from
`GetSystemDirectoryW` and canonicalized before launch. The boundary clears the inherited
environment, then restores only the Win32-derived `SystemRoot`, a System32-derived `PATH`, and the
SystemRoot-derived PowerShell module root; it starts in the canonical System32 directory and
always supplies null stdin. It never resolves a command from the caller's `PATH`, inherits
`PSModulePath`, or uses the caller's working directory. Explicit EasyTier core and CLI commands
first canonicalize the executable, receive the same clean baseline, and change to their direct
artifact directory only after the caller has completed its artifact-root validation.

The native foreground EasyTier command builder discards child stdin, stdout, and stderr at the
process boundary. Operator status comes only through the explicitly supplied `easytier-cli` path
and fixed redacted diagnostics, never inherited child output.

   `control-runtime` is not given arbitrary process-spawn responsibilities. The platform adapter
contains the OS-specific process and route mechanics, while the pure plan and lifecycle result
types remain reusable by future GUI or service adapters.

The generated EasyTier config is deleted after a successful stop and retained only on a
failed-cleanup path for manual recovery. It contains the selected peer, network identity,
virtual address, and destination route settings derived from the verified plan. The adapter
accepts only the configured EasyTier version/hash and refuses to launch an unpinned executable.

Persisted foreground state uses schema v4; schema v3 and earlier records are unrecoverable. It
records an owned PID, a nonempty UTC creation-marker string, independently pinned core and CLI
hashes, a single CLI
file name, a single redacted config file name, planned destination CIDRs, exact captured virtual
route tuples, and the secret-free client/pop bundle IDs and sequences plus configured EasyTier
version. It never records an absolute executable, CLI, config path, raw command line, raw envelope,
network secret, exact child output, or numeric creation FILETIME. Start canonicalizes the supplied
core and CLI files before version/hash checks and accepts them only when their canonical parents are
equal and that parent is the protected `easytier` directory. The configuration artifact is created with exclusive-create semantics, then must be a
canonical direct child of the canonical state directory before process start. Fresh recovery applies
the same direct-child config rule before invoking the process port, and accepts a canonical recovered
CLI only when its persisted filename and canonical parent exactly match the canonical, hash-proven
core.

Native proof is an exact `Get-CimInstance Win32_Process -Filter "ProcessId = <u32>"` lookup paired
with the persisted UTC creation-marker, canonical core path and hash pin, and a
`CommandLineToArgvW` parse whose complete non-executable argument vector is exactly
`--config-file <canonical-state-config>` followed by `--disable-env-parsing`, with no duplicate or
additional arguments. WMI also yields a numeric UTC creation FILETIME that exists only in the
in-memory native proof. Before accepting a start or fresh recovery proof, and again immediately
before termination, the runner opens the exact PID with query, terminate, and synchronize access
and requires `GetProcessTimes` to match that FILETIME. It calls `TerminateProcess` and waits on that
same owned handle; RAII closes the handle. It never uses `taskkill`, descendant-tree termination,
process-name scanning, or candidate enumeration. Service boundaries convert process-start and route
proof failures to fixed redacted diagnostics, preserving the fixed cleanup failure diagnostic when
rollback cannot be proven. Native endpoint-bypass ownership is normalized before every mutation as
an IPv4 endpoint `/32`, IPv4 gateway, nonzero interface index, and `u16` metric. The endpoint route
is accepted only when its selected interface is an up physical adapter. Virtual destination ownership
is captured as the exact difference between bounded pre-launch and post-readiness `ActiveStore`
queries for each planned prefix. A captured destination route must be nonphysical, and fresh recovery
or removal requires exactly one `ActiveStore` match for destination prefix, next hop, interface index,
and route metric. Removal uses only the exact
`Remove-NetRoute -InputObject $matches[0] -Confirm:$false -ErrorAction Stop`; it never synthesizes a
deletion from a CIDR, scans broadly, or deletes a default
route. Native route add, proof, and exact removal commands discard child stdin, stdout, and stderr,
exposing only fixed diagnostics at the adapter boundary.

`Running` remains strict: the process and every persisted route tuple must satisfy all ownership
proofs before the service writes `Stopping` or mutates a resource. Native Windows recovery for an
already persisted `Stopping` or `Failed` state instead reconciles one exact `ActiveStore` tuple at a
time. It retains only exact present tuples under the original full ownership key and permits a
proven-absent exact tuple or PID to converge without deletion. PowerShell exit code `3` is reserved
only for that zero-match tuple or absent exact PID result; ambiguity, malformed data, command
failure, physical destination adapter, or any present-process proof/config mismatch fails closed.
No raw tuple, PID, command, or config detail reaches diagnostics.

The native secure-storage boundary has two distinct operations. Elevated `prepare-storage --confirm`
creates the `AnixOps`, `WindowsTunnel`, `state`, and `secrets` components in that order when they
do not exist, then sets and verifies the exact owner/DACL only on components it created. Existing
components are inspection-only and fail closed unless their owner, DACL, and non-reparse invariants
already match. Elevated `start` uses the same guarded preparation before accepting a direct-child
state or secret path. `status` and the path-validation portion of `stop` use a separate
inspection-only path: it checks the existing directories, ACL rules, reparse attributes, and
direct-child state file, but never calls `New-Item`, `Set-Acl`, or another host-mutating operation.
Every native PowerShell invocation uses the same trusted system-command boundary, captures its
standard streams internally, and maps failure to a fixed, path-free diagnostic.

### CLI layer

`apps/windows-cli` parses the tunnel command and delegates through an injected bridge. Production
constructs the native bridge only for `TunnelPrepareStorage`, `TunnelStart`, `TunnelStatus`, and
`TunnelStop`; Help, Version, Capabilities, Status, and Diagnostics retain the read-only entrypoint.
`prepare-storage` requires elevation and `--confirm`, then invokes only the secure input-path policy;
it does not load delivery, access secret/state children, start a lifecycle session, or access
EasyTier, routes, or processes. The start bridge loads the raw 32-byte public key, verifies both
delivery envelopes at one clock value, derives the plan, and passes only that plan plus
secure-path-policy-approved operator paths to the native platform session service. It renders text
and JSON with the same stable fields:

- `session_id`, `state`, `selected_pop_id`, `selected_endpoint`;
- `client_bundle_id`, `client_sequence`, `pop_bundle_id`, `pop_sequence`, and `plan_digest`;
- `easytier_version`, `peer_ready`, `route_ready`, and `route_count`;
- `system_mutation_policy`, `rollback_status`, and redacted diagnostics.

The CLI must refuse `prepare-storage` and `start` without `--confirm`. It must refuse `start`
without an explicit state path, explicit binary paths, and the network-secret file. It must not
print the secret, raw command line, full delivery payload, or any rejected local path.

The supported first-run procedure is:

```text
1. Run elevated: networkcore-windows tunnel prepare-storage --confirm
2. From an elevated terminal, stage the approved EasyTier core and CLI as direct children under
   `%ProgramData%\AnixOps\WindowsTunnel\easytier\`; verify and record each lower-case SHA-256.
3. Create one safe-name secret file under `%ProgramData%\AnixOps\WindowsTunnel\secrets\`.
4. Run elevated tunnel start with the two protected direct-child artifact paths, both hashes, that
   direct-child secret path, and a direct-child state path.
```

Live `tunnel status` also requires elevation because it performs storage, configuration, and
process ownership proof. There is no non-elevated live status mode.

## Data Flow

1. Operator supplies signed client and POP envelope files, the local device identity, a public
   key file, protected direct-child EasyTier paths/version plus independent core/CLI hashes, a network name, a secret file, and an explicit
   state path.
2. For `prepare-storage`, the native bridge checks elevation and confirmation before it creates or
   validates only the fixed storage hierarchy. For `start`, it checks elevation before it reads the
   public key, either envelope, state path, or secret path, then performs guarded preparation and
   validates the protected EasyTier direct-child paths before it verifies either envelope at one
   trusted `now` value.
   For `stop` and live `status`, it checks elevation before it performs inspection-only state-path
   validation or lifecycle access; status remains non-mutating but elevation is required for the
   storage/config/process ownership proof.
3. After both envelopes verify, the native loader derives client and POP identities only from
   verified envelope accessors and reads their independent floors from the protected delivery
   ledger. The pure planner checks identity, expiry, sequence, transport, POP selection, and route
   intent against those floors. A successful signature and plan validation is accepted only after
   the loader durably reserves both newer sequences under the ledger lock, before any process or
   route mutation. The reservation is never rolled back: if a later lifecycle launch fails, those
   sequences are consumed and the controller must issue a newer delivery. The schema-v1 ledger is
   an append-only newline-delimited journal: each reservation appends and syncs a complete floor
   document while holding the exclusive lock. Readers use the last complete record, fail closed on
   malformed complete records, and ignore only a non-newline-terminated trailing partial record so
   a crash cannot erase an earlier durable floor. Before a later reservation appends, the same
   lock permits it to trim only that detected partial tail back to the last complete-record offset;
   it never compacts or truncates a complete journal record.
4. The Windows adapter validates administrator context, protected artifact roots, both executable hashes, secret-file ACL
   expectations, each planned destination snapshot, and a physical endpoint bypass route.
5. The adapter writes a session-owned EasyTier configuration artifact under the state
   directory, launches the explicit EasyTier binary, and waits for peer/route readiness from
   the explicit EasyTier CLI.
6. After readiness, the adapter captures exactly one new nonphysical virtual-route tuple per
   planned destination and persists schema-v4 ownership/audit state before it exposes
   `state=running` and allows the operator to run traffic tests.
7. `status` reads a schema-v4 session record and, for a fresh service instance, first requires an
   exact injected ownership proof before performing an explicit EasyTier CLI health query. It does
   not scan arbitrary processes or infer liveness from a stale PID.
8. `stop` requires the same process proof plus exact endpoint-bypass and virtual-route proof before
   it removes virtual routes, restores the bypass, and terminates the owned process. A virtual-route
   removal failure retains redacted failed state and process ownership without later cleanup. The
   state record is retained as redacted audit evidence.

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

The native bridge checks elevation before `prepare-storage`, `start` delivery/file access, `status`
inspection or lifecycle access, and `stop` inspection or lifecycle access; a non-elevated
invocation fails closed with
`windows.tunnel.admin_required`. It never returns public-key paths, envelope paths, state paths,
verifier messages, ACL output, PowerShell output, or secret-bearing inputs in CLI diagnostics.

Native storage rejects arbitrary parent directories and every reparse point. `prepare-storage` and
`start` may mutate only newly created fixed ProgramData hierarchy components and the approved
secret file after elevation; neither repairs an existing owned component. `status` has no directory
creation or ACL-repair authority, and `stop` obtains that same read-only path proof only after its
elevation gate. A failed path policy maps to the fixed, path-free
`windows.tunnel.start_failed` diagnostic.

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

- command parsing and `--confirm`/path requirements, including storage-only preparation;
- client/POP identity, expiry, sequence, transport, and POP-selection rejection paths;
- independent per-bundle sequence replay rejection, persisted identity-keyed floors, atomic pair
  reservation, malformed-ledger fail-closed behavior, reopening persistence, and safe recovery
  from a trailing partial journal record;
- deterministic EasyTier command/config generation with secret redaction;
- executable version/hash mismatch and missing-secret diagnostics;
- destination snapshot/capture ordering, endpoint-bypass transaction ordering, and rollback on
  process/readiness or unproven destination-capture failure;
- exact ActiveStore virtual-route recovery/removal before bypass restoration and process stop,
  including missing/ambiguous tuple rejection and nonphysical virtual-adapter proof;
- status/stop ownership checks and stale-session refusal;
- injected bridge ordering: unconfirmed or unelevated preparation invokes no path, delivery, or
  lifecycle operation; confirmed elevated preparation invokes only the input-path policy;
  unelevated start/status/stop invoke no prohibited storage or lifecycle operation; elevated start
  validates secure paths before delivery loading; elevated status/stop validate existing state
  before lifecycle delegation; and running/stopped lifecycle evidence maps to the stable readiness
  fields;
- CRLF-normalized source contracts for the trusted ProgramData ancestor, owned AnixOps hierarchy,
  exact owner/DACL rules, reparse rejection, child-stream capture, and inspection-only status
  validation; hosted CI verifies these boundaries but does not establish a real host ACL;
- native `main` routing only for the four tunnel variants, while the bridge's raw-key, one-clock,
  and fixed-redaction behavior remains unit-contract covered;
- Windows target format, lint, test, build, dependency audit, and package manifest checks.

No automated job claims that a GitHub-hosted Windows runner established a real tunnel. The
workflow records the distinction between injected bridge contract verification and manual elevated
data-plane evidence.

### Manual end-to-end acceptance

The operator provides one Linux POP and one Windows 11 x64 host. The POP advertises one test
CIDR behind it and uses the same EasyTier network identity as the client. The acceptance record
must show:

1. Secure ProgramData root owner/DACL evidence and delivery-ledger floors before and after start.
2. Pre-start endpoint and destination ActiveStore tuple snapshots plus proof that the selected
   endpoint adapter is up and physical.
3. Successful `tunnel start` output with the selected POP and redacted plan digest.
4. EasyTier peer and route readiness, followed by exact post-start virtual-route tuples.
5. Successful `ping` to the EasyTier virtual address and successful `ping` and `curl` to a host in
   the POP test CIDR.
6. A negative route test proving an unadvertised CIDR is not sent through the POP.
7. Successful `tunnel status` output.
8. `tunnel stop` output and a post-stop route/process snapshot matching the pre-start state, with
   each exact virtual and endpoint-bypass tuple absent.
9. After a fresh service restart and before `tunnel stop`, record the one ActiveStore route matching
   every persisted tuple field; after stop, record that only those exact routes were removed.
10. In an isolated test environment, make a virtual or endpoint tuple proof missing or ambiguous and
    record that fresh `tunnel stop` fails while the EasyTier process, state, config, and unrelated
    routes remain unchanged; restore the controlled fixture before cleanup.

The first slice is considered usable only when all ten records are present. A green CI run
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
