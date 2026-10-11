# Windows Tunnel Cleanup Transaction Design

**Status:** Approved under the existing autonomous implementation authorization

**Date:** 2026-07-20

## Goal

Make a Windows EasyTier tunnel stop operation durable and safely resumable when
route removal, process termination, configuration deletion, or a state write is
interrupted. A prior `Running` record must never become a stale ownership claim
after a destructive cleanup action. A failed start must retain its generated
configuration whenever route or process cleanup cannot be proven.

## Scope and Constraints

- Keep the current foreground-only, one-POP EasyTier scope. Do not add a GUI,
  service, driver, installer, controller fetch, IPv6 policy routing, default
  routes, proxy mutation, or MITM behavior.
- Continue to remove only exact `ActiveStore` route objects proven by destination
  prefix, next hop, interface index, and metric. Never synthesize deletion from
  a CIDR or treat an ambiguous match as owned.
- `Running` recovery remains strict: every persisted route tuple, exact owned
  process proof, config artifact, binary pin, and CLI sibling proof must exist.
  Missing or ambiguous resources in `Running` fail closed without mutation.
- `Stopping` and `Failed` are durable cleanup-intent states. They are written
  atomically before the first destructive stop mutation. In these states only,
  a missing exact resource may mean an earlier cleanup step completed; an
  existing resource must still be exactly proven before it is removed.
- State and CLI diagnostics remain redacted. No raw paths, command lines,
  secrets, route gateways, envelopes, or child output may be rendered.
- GitHub Actions remains the only Rust format, lint, test, build, and audit
  authority. Local Rust tooling is not run.

## Chosen Approach

Use one durable cleanup intent plus idempotent reconciliation, rather than a
schema-v4 per-resource journal. This keeps schema-v3 state fields unchanged
while making every cleanup action retryable:

1. A `Running` stop obtains strict ownership proof, writes `Stopping` with a
   pending rollback status through the atomic state writer, then begins cleanup.
   If that write fails, no route, process, or configuration mutation occurs.
2. A fresh `Stopping` or `Failed` stop reconstructs the same session in cleanup
   mode. For each persisted bypass and virtual-route tuple, it accepts either
   one exact safe `ActiveStore` match or no match. One match becomes an in-memory
   remaining resource; no match becomes an already-cleaned resource; more than
   one match or any mismatched tuple fails closed.
3. Cleanup-mode process recovery reports either a fully proven exact process or
   a proven absent PID. A present process must still satisfy the existing PID,
   creation marker, binary hash, exact command arguments, config path, and
   handle FILETIME checks. An existing but unprovable process fails closed.
4. Cleanup proceeds in order: remaining virtual routes, remaining endpoint
   bypasses, exact owned process, then direct-child configuration file. Each
   step stops on failure, writes `Failed`, retains the config, and returns the
   fixed rollback diagnostic. A failed `Failed` write leaves the already durable
   `Stopping` intent, which a later stop reconciles idempotently.
5. A final `Stopped` write is also retryable: if it fails, the durable
   `Stopping` intent remains; a later stop observes all resources absent and
   writes `Stopped` without deleting anything else.

## Start Rollback

Start rollback distinguishes three process conditions:

```text
NotStarted
Owned(handle)
Unproven
```

`NotStarted` is valid only before a process launch attempt. `Owned(handle)`
requires an exact stop proof. `Unproven` covers a native launch that could not
prove child termination. The generated configuration is removed only after all
required destination-route, bypass-route, and process cleanup actions succeed.
Every failure or `Unproven` outcome retains the direct-child config for manual
recovery and returns `windows.tunnel.rollback_failed`.

The service classifies a process-runner start error with
`windows.tunnel.rollback_failed` as `Unproven`; every other start error is
`NotStarted`. This preserves the native runner's existing fixed diagnostic
without exposing its child-process details.

## Interfaces

`EasyTierProcessRunner` gains cleanup recovery with a discriminated result:

```rust
pub enum EasyTierCleanupRecovery {
    Present(RecoveredEasyTierProcess),
    Absent,
}

fn recover_for_cleanup(
    &mut self,
    spec: &EasyTierRecoverySpec,
) -> DomainResult<EasyTierCleanupRecovery>;
```

`WindowsRoutePort` gains cleanup recovery for exact persisted tuples. Strict
recovery remains unchanged for `Running`; cleanup recovery records only exact
tuples still present under the original session key, while accepting a bounded
zero-match result as already removed.

The session service receives an injectable state port so lifecycle contracts can
force atomic-write failures without weakening production state protection. The
production port delegates to the existing secure state reader/writer; test ports
preserve their last successful state on a configured write failure.

```rust
pub trait WindowsTunnelStatePort {
    fn read(&mut self, path: &Path) -> DomainResult<WindowsTunnelState>;
    fn write(&mut self, path: &Path, state: &WindowsTunnelState) -> DomainResult<()>;
}
```

## Error Handling

- Any malformed, ambiguous, physical, default, IPv6, host-bit, or unproven
  route remains a fixed redacted failure and is never removed.
- Cleanup reconciliation accepts absence only after persisted `Stopping` or
  `Failed` intent; `Running` never accepts absence.
- A missing config is accepted only in cleanup recovery after the process has
  been proven absent. A present process with a missing config is an ownership
  mismatch.
- Any failure to write a transition leaves the prior durable state untouched by
  the atomic writer. No subsequent destructive action is allowed unless a
  durable cleanup intent already exists.

## Test Strategy

- Add test-only red contracts for every failed-start branch that must retain
  config and return rollback failure when route/process cleanup is unproven.
- Add lifecycle tests using a failing state port and deterministic fake route
  and process ports for partial virtual removal, partial bypass removal, process
  stop, config removal, failed-state persistence, and final-stopped persistence.
  Each case restarts a fresh service and requires eventual idempotent `Stopped`.
- Add source contracts for native cleanup recovery: exact bounded ActiveStore
  queries accept only zero or one match in cleanup mode, preserve physical and
  virtual adapter checks, and native process absence is distinguished from an
  unprovable process without exposing child output.
- Keep the existing redaction, exact tuple, default-route, IPv4-only, and
  manual-evidence contracts green.

## Manual Acceptance

An elevated Windows operator must add evidence for state-writer access denied,
disk-full, native move failure, interruption between each cleanup action, and
fresh `tunnel stop` convergence after each condition. The record must also keep
the existing physical-underlay, exact tuple, Linux POP readiness, ping, curl,
and post-stop absence evidence.
