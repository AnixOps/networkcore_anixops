# Managed Foreground Session Event Source Contract

本文定义 `v0.1.2-alpha.2` managed foreground lifecycle 的两个 source-only event record 切片、一个只读 CLI 接线切片和一个初始写入 CLI 接线切片。它只读取、初始写入并校验调用方显式指定的单个 JSON event record，不扫描目录、不聚合事件，也不把事件内容误称为进程存活或实时事件流。

## Source Of Truth

- `managed-foreground-session-event-source-contract=active`
- `managed-foreground-session-event-version-scope=v0.1.2-alpha.2`
- `managed-foreground-session-event-operation=event-read`
- `managed-foreground-session-event-storage=json`
- `managed-foreground-session-event-schema-version=1`
- `managed-foreground-session-event-default-path=blocked`
- `managed-foreground-session-event-write-operation=event-write`
- `managed-foreground-session-event-cli-read-operation=managed-event`
- `managed-foreground-session-event-cli-init-operation=managed-event-init`
- `managed-foreground-session-event-cli-overwrite=blocked`
- `managed-foreground-session-event-runtime-stream=blocked`
- `managed-foreground-session-event-liveness-verification=blocked`

## Operation

源码增量提供 `ManagedForegroundSessionEventRequest`、`ManagedForegroundSessionEventReport` 和
`CommandManagedForegroundSessionEventStore::read_event`。调用方必须显式提供一个 event record JSON 文件路径。
record 不存在、JSON 无法解析、schema version 不匹配、任一必填标识或 `recorded_at` 为空、event kind 不在允许集合，或
recorded state 不在 `starting`、`running`、`stopped`、`failed` 集合时，操作必须返回稳定错误。

schema version 1 固定为：

```json
{
  "schema_version": 1,
  "session_id": "session-1",
  "engine_id": "native",
  "event_id": "event-1",
  "event_kind": "status_transition",
  "state": "running",
  "recorded_at": "2026-07-10T00:00:00Z"
}
```

允许的 `event_kind` 为 `session_started`、`status_transition`、`session_stopped` 和 `session_failed`。
`recorded_at` 只要求为非空的调用方记录值；本切片不校验时钟、时区、时间顺序或事件新鲜度。

report 只输出显式 event 路径、trim 后的 session id、engine id、event id、event kind、recorded state、recorded_at 和
`liveness_verified=false`。该字段表示本切片没有检查 PID、端口、socket 或进程状态；event record 只代表持久化数据，
不代表跨进程 runtime 正在运行，也不代表存在实时事件订阅。

第二个源码增量提供 `ManagedForegroundSessionEventWriteRequest`、`ManagedForegroundSessionEventWriteReport` 和
`CommandManagedForegroundSessionEventStore::write_event`。调用方必须显式提供 event record 路径、session id、engine id、
event id、event kind、state 和 recorded_at。write 使用 schema version 1 并在写入前校验所有字段；目标路径已存在时必须
拒绝覆盖。report 输出 trim 后的字段、`record_written=true` 和 `liveness_verified=false`，不检查或声称 live process。

第三个源码增量将读取能力接入 `networkcore-linux managed-event <event-record-path>`。该命令要求一个显式位置参数，
不扫描默认路径；它调用 `CommandManagedForegroundSessionEventStore::read_event`，在 text/JSON response 中输出 event
路径、session id、engine id、event id、event kind、recorded state、recorded_at 和 `liveness_verified=false`。event
record 缺失、schema 或字段无效时保留稳定 `cli.linux.managed_foreground_event.*` 错误；查询不写入、删除、归档、列出或
扫描 event，也不检查 PID、端口、socket 或进程状态。

第四个源码增量将初始写入能力接入 `networkcore-linux managed-event init <event-record-path> <session-id> <engine-id> <event-id> <event-kind> <state> <recorded-at>`。
该命令要求七个显式位置参数，不扫描默认路径；它调用 `CommandManagedForegroundSessionEventStore::write_event`，在
text/JSON response 中输出 event 路径、session id、engine id、event id、event kind、recorded state、recorded_at、
`record_written=true` 和 `liveness_verified=false`。目标 event record 已存在时保留稳定 write-failed 错误且不覆盖原始内容；
该命令不删除、归档、列出或扫描 event，也不检查 PID、端口、socket 或进程状态。

## Boundaries

本切片不删除、归档或列出 event record，不创建 snapshot，不读取日志，不扫描默认路径，不读取远程或 subscription
文件，不修改 status/catalog，不启动、停止、reload 或 rollback runtime，不创建 daemon/control socket，也不安装 service。
它不执行 system proxy、system trust store、TUN、DNS 或 firewall mutation。

任意 event 覆盖、事件列表/游标、实时 runtime event stream、日志读取、PID/port liveness 检查和 runtime control 由后续独立功能处理。
所有测试、构建、格式化、lint 和安全扫描只能在 GitHub Actions 执行。

## Acceptance Test

合同测试必须证明一次 `read_event`：

- 从显式 schema version 1 record 读取 trim 后的 session id、engine id、event id、event kind、state 和 recorded_at；
- report 固定 `liveness_verified=false`，不声称跨进程 runtime 存活或实时事件流；
- 读取不修改 event record；
- record 缺失时返回稳定 read-failed 错误。

第二个合同测试必须证明一次 `write_event`：

- 将显式 event record 路径写为 schema version 1，并 trim 所有字段；
- report 固定 `record_written=true` 与 `liveness_verified=false`；
- 目标 record 已存在时返回稳定 write-failed 错误，且不覆盖原有内容。

第三个合同测试必须证明 `managed-event`：

- 解析一个显式 event record 路径，并从该路径读取 event id、event kind、recorded state 和 recorded_at；
- text/JSON response 都固定 `liveness_verified=false`，不声称跨进程 runtime 存活或实时事件流；
- record 缺失时保留稳定 read-failed 错误，且不写入、删除或扫描 event。

第四个合同测试必须证明 `managed-event init`：

- 解析显式 event record 路径、session/engine/event 标识、event kind、state 和 recorded_at，并写入 schema version 1 record；
- text/JSON response 都固定 `record_written=true` 与 `liveness_verified=false`；
- 目标 record 已存在时保留稳定 write-failed 错误，且不覆盖原始内容。
