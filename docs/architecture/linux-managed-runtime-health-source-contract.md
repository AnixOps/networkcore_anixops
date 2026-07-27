# Linux Managed Runtime Health Source Contract

`linux-managed-runtime-health-source-contract=proposed`

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
mutation, records the expected state and configuration version, then performs
the existing `RuntimeOrchestrator::reload_runtime`. The foreground owner must
read health back after the reload. Failed reload automatically restores the
prepared snapshot through `rollback_runtime_engine`; a failed restore returns a
stable redacted rollback failure and records a failed runtime snapshot.

`managed-runtime rollback` must require an explicit socket path, expected
state, expected configuration version, and confirmation. It may only restore a
snapshot owned by the same foreground session. After rollback it reads health
back and returns the resulting version and evidence. Repeated rollback of an
already restored version is idempotent; conflicting state or version never
writes a runtime configuration.

All socket reads and writes retain the existing two-second deadline and 64-byte
request bound. Runtime snapshots never contain raw configuration, subscription
locations, credentials, tokens, certificate private keys, or full share links.

## Verification

GitHub Actions contract tests must cover healthy readback, listener failure,
expected-state/version conflict, reload failure with successful automatic
restore, restore failure, explicit rollback readback, timeout, and redaction.
No local build, test, or formatting command is used for this contract.
