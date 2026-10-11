# Linux Managed Control Socket Source Contract

评估时间：2026-07-27。

```text
linux-managed-control-socket-source-contract=active
linux-managed-control-socket-operation=explicit-foreground-stop-reload
linux-managed-control-socket-permissions=0600
linux-managed-control-socket-default-path=blocked
linux-managed-control-socket-reload=explicit-foreground-active
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

`networkcore-linux reload --managed-control-socket <absolute-path> --confirm`
uses the same exact-path authorization and bounded request/response exchange.
An accepted `reload` is consumed by the current foreground process, invokes
`RuntimeOrchestrator::reload_runtime` with the already explicit `start`
configuration, and resumes the foreground lifecycle only after a successful
reload. Reload failure reports a stable diagnostic, attempts current-runtime
cleanup, and transitions managed recording to `failed`; it does not infer a
configuration path or start a new process.

The server maps accepted requests to the existing foreground lifecycle path.
The Unix signal interruption source checks them alongside `SIGINT`/`SIGTERM`:
`stop` emits `cli.linux.start.managed_control_stop_requested`, calls
`RuntimeOrchestrator::stop_runtime`, aggregates native release diagnostics, and
lets managed lifecycle recording transition `running -> stopped`; `reload`
emits `cli.linux.start.managed_control_reload_requested` and re-enters the
foreground wait after the runtime reload. The socket protocol does not expose
rollback, status, logs, events, arbitrary payloads, or remote transport.

## Verification

GitHub Actions must run
`managed_control_socket_accepts_confirmed_stop_and_cleans_up`. The contract
uses an injected `ManagedControlInterrupter` to prove real UnixStream `reload`
and `stop` requests are accepted without signalling the test process, checks
`0600`, verifies the authorization gate, and proves guard cleanup. The Unix foreground
interruption contract separately proves the default control interrupter is
consumed as `managed-control-stop` and exposes the reload diagnostic. Local
machines do not run build or test commands.
