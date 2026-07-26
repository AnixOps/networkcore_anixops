# Managed Foreground Session Log Source Contract

评估时间：2026-07-25。

当前合同状态：

```text
managed-foreground-session-log-source-contract=active
managed-foreground-session-log-operation=tail-read
managed-foreground-session-log-cli-operation=managed-log
managed-foreground-session-log-max-lines=1000
managed-foreground-session-log-max-bytes=65536
managed-foreground-session-log-liveness-verification=blocked
```

## Scope

`CommandManagedForegroundSessionLogStore::read_tail` reads the final bounded
lines of one caller-selected UTF-8 log file. The request carries an
explicit `log_path` and `line_limit`; the report returns the selected path,
limit, total line count, tail lines, the UTF-8 byte count of the returned line
contents, and `liveness_verified=false`. The byte count excludes discarded
content and line separators; it is an audit field, not an additional read
limit.

The source boundary rejects an empty path, a non-file path, unreadable or
non-UTF-8 content, a limit outside `1..=1000`, and a log larger than 65536
bytes. It does not create files, search directories, follow a default log
location, tail a live file, stream updates, rotate logs, inspect PID/port/
socket state, or start/reload/stop a runtime.

## API

- `ManagedForegroundSessionLogTailRequest`
- `ManagedForegroundSessionLogTailReport`
- `CommandManagedForegroundSessionLogStore::read_tail`
- `MANAGED_FOREGROUND_LOG_TAIL_DEFAULT_LIMIT`
- `MANAGED_FOREGROUND_LOG_TAIL_MAX_LIMIT`
- `MANAGED_FOREGROUND_LOG_TAIL_MAX_BYTES`

`networkcore-linux managed-log <log-file-path> [--tail-lines <1-1000>]
[--format text|json]` exposes the same bounded report. Text output includes
the returned lines; JSON exposes `managed_foreground_log_tail` with the path,
requested limit, total line count, returned lines, returned byte count, and
`liveness_verified=false`.

Managed runtime linkage, reload/rollback orchestration, log search, and live
streaming require separate contracts and GitHub Actions validation.

## Verification

GitHub Actions must run the Rust contract test
`managed_foreground_session_log_tail_reads_explicit_bounded_log_without_liveness_claim`.
It must also run `managed_foreground_session_log_cli_reads_bounded_explicit_log`.
Local machines do not run build or test commands.
