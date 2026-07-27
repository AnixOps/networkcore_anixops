# Linux Managed Runtime Health Source Contract

`linux-managed-runtime-health-source-contract=active-source-contract`

## Scope

This contract adds an explicit managed-runtime record alongside, and never in
place of, the existing managed foreground session status record. The existing
`managed-status` schema remains a lifecycle audit record with
`liveness_verified=false`.

`networkcore-linux status --managed-control-socket <absolute-path>`
will be the only cross-process runtime read path. It will request a bounded
read-only snapshot from the current foreground owner; there is no default
socket path, PID scan, process-name lookup, or systemd fallback.

The response must contain only non-secret fields:

- engine id and lifecycle state;
- monotonically assigned configuration version and a SHA-256 configuration
  digest;
- foreground process id;
- configuration validation, runtime-resource, listener-connectivity, and
  control-readback booleans;
- a redacted stable failure code when the snapshot is unhealthy.

The foreground owner must create the snapshot only after
`RuntimeOrchestrator::runtime_health` confirms configuration validation,
runtime resources, and a reachable listener. A connected status requires every
health boolean plus a running engine state; PID presence alone is insufficient.

## Mutation Protocol

Managed reload captures an adapter-owned `ProxyEnginePrepareReport` before the
mutation, preserves it as the last successful rollback snapshot with its
configuration version, then performs the existing
`RuntimeOrchestrator::reload_runtime`. The foreground owner reads health back
after the reload and advances the status version only after that readback.
Failed reload automatically restores the prepared snapshot through
`rollback_runtime_engine` with expected state `Running`; a failed restore
returns a stable redacted rollback failure and records a failed runtime
snapshot.

`networkcore-linux rollback --managed-control-socket <absolute-path>
--expected-config-version <positive-integer> --confirm` may only restore the
foreground owner's retained prior-successful snapshot. It requires the same
explicit socket and confirmation boundary as reload. The socket carries exactly
one positive expected version; the owner rejects a stale or missing value before
any runtime mutation, checks that the retained version is older than the active
version, and passes expected state `Running` to the adapter. Absent or
conflicting snapshots are rejected without a runtime write. After rollback it
reads health back and returns the restored version and evidence. A second
rollback without a newly successful reload is rejected as having no retained
prior version.

All socket reads and writes retain the existing two-second deadline and 64-byte
request bound. Runtime snapshots never contain raw configuration, subscription
locations, credentials, tokens, certificate private keys, or full share links.

## Verification

GitHub Actions contract tests cover the explicit CLI parse/confirmation path,
owner interruption handoff, stable diagnostics, bounded socket behavior, and
the reload failure restore path. Adapter failure matrices, listener failure,
and full retained-snapshot rollback readback remain CI coverage work for this
P3 slice. No local build, test, or formatting command is used for this
contract.
