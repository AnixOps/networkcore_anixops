# Managed Foreground Session Event Source Contract

本文定义 `v0.1.2-alpha.2` managed foreground lifecycle 的 event record 读取、初始写入、只读 CLI 接线、初始写入 CLI 接线，以及未发布的受限 event history 查询增量。它只读取、初始写入并校验调用方显式指定的 JSON event record；history 查询也只能读取调用方显式指定目录中的直接 JSON 文件，不能把持久化内容误称为进程存活或实时事件流。

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
- `managed-foreground-session-event-history-operation=event-history`
- `managed-foreground-session-event-cli-history-operation=managed-event-list`
- `managed-foreground-session-event-history-default-limit=50`
- `managed-foreground-session-event-history-max-limit=100`
- `managed-foreground-session-event-history-max-records=256`
- `managed-foreground-session-event-history-max-record-bytes=65536`
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
该命令不删除、归档或扫描默认 event 位置，也不检查 PID、端口、socket 或进程状态。

第五个未发布源码增量提供 `ManagedForegroundSessionEventHistoryRequest`、
`ManagedForegroundSessionEventHistoryReport` 和 `CommandManagedForegroundSessionEventStore::list_event_history`，并接入
`networkcore-linux managed-event list <event-directory> [--session-id <id>] [--event-kind <kind>] [--state <state>] [--cursor <offset>] [--limit <1-100>]`。
调用方必须显式提供目录；查询不创建该目录，也不读取默认路径。它只考虑目录第一层的常规 `.json` 文件，不递归目录、
枚举时跳过 event record symlink，并忽略非 JSON 文件。查询最多枚举 256 条 record，每条最多 65536 bytes；超过上限返回稳定
`cli.linux.managed_foreground_event.history_limit_exceeded` 错误。`limit` 必须在 1 到 100 之间，缺失或不支持的
session id、event kind、state 过滤值返回稳定 `cli.linux.managed_foreground_event.history_query_invalid` 错误。

实现会先读取并校验每一条候选 record，再应用 exact trim 后的 `session_id`、`event_kind` 和 `state` 过滤，故任何直接
JSON record 损坏、schema 不兼容或字段非法都会使整个查询以既有稳定 `cli.linux.managed_foreground_event.*` 读取错误失败，
不能通过过滤条件绕过损坏 record。匹配项按 `(recorded_at, event_id, event_path)` 升序确定排序；`recorded_at` 仍只是调用方
提供的非空字符串，因此该排序只提供确定性，不验证真实时间或全局事件顺序。`cursor` 是匹配排序后的零基 offset，返回页的
`next_cursor` 仅在仍有匹配项时存在；目录在分页之间变化时不会提供快照隔离或游标稳定性保证。report 固定输出过滤条件、
effective cursor、next cursor、matching count、当前页 entries 和 `liveness_verified=false`；查询完全只读。

## Boundaries

本切片不删除、归档或修改 event record，不创建 snapshot，不读取日志，不扫描默认路径，不读取远程或 subscription
文件，不修改 status/catalog，不启动、停止、reload 或 rollback runtime，不创建 daemon/control socket，也不安装 service。
history 查询不是实时 stream、tail 或 watcher；它只读取调用方明确指定目录中的有界直接 JSON 文件。
它不执行 system proxy、system trust store、TUN、DNS 或 firewall mutation。

任意 event 覆盖、实时 runtime event stream、日志读取、PID/port liveness 检查和 runtime control 由后续独立功能处理。
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

第五个合同测试必须证明 `list_event_history` 和 `managed-event list`：

- 只读取显式目录的直接常规 JSON record，以 `(recorded_at, event_id, event_path)` 确定排序，并忽略嵌套目录与非 JSON 文件；
- exact session id、event kind、state 过滤在 schema 校验后生效，跨页 cursor 返回稳定的 `next_cursor`、matching count 与当前页；
- 不支持的过滤条件或 page limit 返回稳定 history-query-invalid 错误，超过目录/单 record 上限返回稳定 history-limit-exceeded 错误；
- 损坏的直接 JSON record 使查询失败且不会修改任一来源文件；
- CLI text/JSON 都输出 query、分页结果与 `liveness_verified=false`，不声称进程存活、实时订阅或 runtime control。
