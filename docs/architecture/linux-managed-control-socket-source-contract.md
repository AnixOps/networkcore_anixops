# Linux Managed Control Socket Source Contract

评估时间：2026-07-27。

```text
linux-managed-control-socket-source-contract=active
linux-managed-control-socket-operation=explicit-foreground-stop
linux-managed-control-socket-permissions=0600
linux-managed-control-socket-default-path=blocked
linux-managed-control-socket-reload=blocked
linux-managed-control-socket-status=blocked
```

## Scope

`networkcore-linux start` may add
`--managed-control-socket <absolute-path>` only together with the explicit
`--managed-status`, `--managed-snapshot`, and `--managed-events` lifecycle
paths. The foreground process creates one Unix domain socket without replacing
an existing filesystem entry, applies owner-only `0600` permissions, and keeps
the socket alive for the foreground lifecycle. Startup failure, normal return,
or interruption drops the owner guard and removes the path only when it still
identifies a Unix socket.

`networkcore-linux stop --managed-control-socket <absolute-path> --confirm`
connects to that exact socket, writes the bounded `stop` command, closes its
write side, and requires the bounded `accepted` response. Both server-side
reads and writes use a two-second deadline; malformed, oversized, timed-out,
or unsupported requests receive no control effect. A missing
confirmation, relative path, connection failure, unsupported command, or
non-Unix platform returns a stable diagnostic and never falls back to PID
signals, default-path discovery, systemd, or process-name matching.
The CLI form accepts only one `--managed-control-socket`, `--confirm`, and
`--format`; unrelated flags are rejected before any socket connection attempt.

The server maps an accepted request to the existing foreground interruption
path. The Unix signal interruption source checks the accepted control request
alongside `SIGINT`/`SIGTERM`, emits
`cli.linux.start.managed_control_stop_requested`, and the current-process host
then calls `RuntimeOrchestrator::stop_runtime`, aggregates native release
diagnostics, and lets managed lifecycle recording transition `running -> stopped`.
The socket protocol does not expose reload,
rollback, status, logs, events, arbitrary payloads, or remote transport.

## Verification

GitHub Actions must run
`managed_control_socket_accepts_confirmed_stop_and_cleans_up`. The contract
uses an injected `ManagedControlInterrupter` to prove a real UnixStream request
is accepted once without signalling the test process, checks `0600`, verifies
the authorization gate, rejects `reload` without interrupting the session, and
proves guard cleanup. The Unix foreground
interruption contract separately proves the default control interrupter is
consumed as `managed-control-stop` with
`cli.linux.start.managed_control_stop_requested`. Local machines do not run
build or test commands.
