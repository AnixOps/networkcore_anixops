# Managed Foreground Session Status Source Contract

本文定义 `v0.1.2-alpha.2` managed foreground lifecycle 的三个 source-only status record 切片，以及只读、初始写入和 expected-state 迁移三个 CLI 接线切片。
它只读取、初始写入或显式迁移调用方指定的 managed foreground session status record；CLI 只对调用方显式提供的 record 执行相同范围的操作，不把记录内容误称为进程存活证明。

## Source Of Truth

- `managed-foreground-session-status-source-contract=active`
- `managed-foreground-session-status-version-scope=v0.1.2-alpha.2`
- `managed-foreground-session-status-operation=status-read`
- `managed-foreground-session-status-write-operation=status-write`
- `managed-foreground-session-status-transition-operation=status-transition`
- `managed-foreground-session-status-cli-read-operation=managed-status`
- `managed-foreground-session-status-cli-init-operation=managed-status-init`
- `managed-foreground-session-status-cli-transition-operation=managed-status-transition`
- `managed-foreground-session-status-storage=json`
- `managed-foreground-session-status-schema-version=1`
- `managed-foreground-session-status-default-path=blocked`
- `managed-foreground-session-status-liveness-verification=blocked`
- `managed-foreground-session-status-daemon-control-socket=blocked`

## Operation

源码增量提供 `ManagedForegroundSessionStatusRequest`、`ManagedForegroundSessionStatusReport` 和
`CommandManagedForegroundSessionStore::read_status`。调用方必须显式提供 status record JSON 文件路径。
record 不存在、JSON 无法解析、schema version 不匹配、session id/engine id 为空或 state 不在
`starting`、`running`、`stopped`、`failed` 集合时，操作必须返回稳定错误。

schema version 1 固定为：

```json
{
  "schema_version": 1,
  "session_id": "session-1",
  "engine_id": "native",
  "state": "running"
}
```

report 只输出显式 status 路径、trim 后的 session id、engine id、记录 state 和
`liveness_verified=false`。该字段表示本切片没有检查 PID、端口、socket 或进程状态；`running` 只代表
recorded state，不代表跨进程 runtime 正在运行。

## Boundaries

第二个源码增量提供 `ManagedForegroundSessionStatusWriteRequest`、
`ManagedForegroundSessionStatusWriteReport` 和 `CommandManagedForegroundSessionStore::write_status`。调用方必须
显式提供 status record 路径、session id、engine id 和 state。write 使用 schema version 1，并在写入前校验
id 和 state；目标路径已存在时必须拒绝覆盖。report 输出 trim 后的 id/state、`record_written=true` 和
`liveness_verified=false`，不检查或声称 live process。

第三个源码增量提供 `ManagedForegroundSessionStatusTransitionRequest`、
`ManagedForegroundSessionStatusTransitionReport` 和 `CommandManagedForegroundSessionStore::transition_status`。
调用方必须显式提供 status record 路径、未存在的 snapshot 路径、expected state 和 next state。迁移会先读取并
验证 schema version 1 record；只有当前 recorded state 与 trim 后的 expected state 相同才会继续。允许的状态边为
`starting -> running`、`starting -> failed`、`running -> stopped` 和 `running -> failed`；`stopped` 与 `failed`
为终态。迁移将原始 record 内容以不覆盖方式写入 snapshot，再将 status record 写为 next state。report 输出
trim 后的 session id、engine id、previous state、next state、`snapshot_written=true` 和
`liveness_verified=false`。expected state 不匹配、snapshot 已存在、路径相同或状态边不允许时，操作必须拒绝，
且不修改 status record。

第四个源码增量将读取能力接入 `networkcore-linux managed-status <status-record-path>`。该命令要求显式的
位置参数，不扫描默认路径；它调用 `CommandManagedForegroundSessionStore::read_status`，在 text/JSON response
中输出 record 路径、session id、engine id、recorded state 和 `liveness_verified=false`。record 缺失、schema 或
字段无效时保留稳定 `cli.linux.managed_foreground_status.*` 错误，不创建 snapshot，不写入或迁移 record，也不
检查 PID、端口、socket 或进程状态。

第五个源码增量将初始写入能力接入 `networkcore-linux managed-status init <status-record-path> <session-id> <engine-id> <state>`。
该命令要求四个显式位置参数，不扫描默认路径；它调用 `CommandManagedForegroundSessionStore::write_status`，在
text/JSON response 中输出 record 路径、trim 后的 session id、engine id、recorded state、`record_written=true`
和 `liveness_verified=false`。目标 record 已存在时保留稳定 write-failed 错误且不覆盖原始内容；该命令不创建
snapshot、不迁移 record，也不检查 PID、端口、socket 或进程状态。

第六个源码增量将 expected-state 迁移能力接入 `networkcore-linux managed-status transition <status-record-path> <snapshot-path> <expected-state> <next-state>`。
该命令要求四个显式位置参数，不扫描默认路径；它调用 `CommandManagedForegroundSessionStore::transition_status`，在
text/JSON response 中输出 status/snapshot 路径、session id、engine id、previous state、next state、
`snapshot_written=true` 和 `liveness_verified=false`。它只允许 `starting -> running/failed` 与
`running -> stopped/failed`，并以不覆盖方式保存迁移前原始 record。stale expected state 返回稳定 state-conflict
错误且不修改 status record 或创建 snapshot；该命令不检查 PID、端口、socket 或进程状态。

本切片只读取、初始写入或显式迁移 status record，不修改 catalog，不启动、停止、reload 或 rollback runtime，
不读取 events/logs，不扫描默认路径，不读取远程或 subscription 文件，不创建 daemon/control socket，
不安装 service，不执行 system proxy、system trust store、TUN、DNS 或 firewall mutation。

任意 record 覆盖、PID/port liveness 检查、events/logs/reload/rollback 由后续独立功能处理。
所有测试、构建、格式化、lint 和安全扫描只能在 GitHub Actions 执行。

## Acceptance Test

合同测试必须证明一次 `read_status`：

- 从显式 schema version 1 record 读取 trim 后的 session id、engine id 和 recorded state；
- report 固定 `liveness_verified=false`，不声称跨进程 runtime 存活；
- record 缺失时返回稳定 read-failed 错误。

第二个合同测试必须证明一次 `write_status`：

- 将显式 record 路径写为 schema version 1，并 trim session id、engine id 和 state；
- report 固定 `record_written=true` 与 `liveness_verified=false`；
- 目标 record 已存在时返回稳定 write-failed 错误，且不覆盖原有内容。

第三个合同测试必须证明一次 `transition_status`：

- 将 explicit `starting` record 迁移为 `running`，并把迁移前的原始内容以不覆盖方式保存到 explicit snapshot；
- report 固定 `snapshot_written=true` 与 `liveness_verified=false`，并报告 previous/next state；
- stale expected state 返回稳定 state-conflict 错误，不修改 status record，也不创建 snapshot。

第四个合同测试必须证明 `managed-status`：

- 解析一个显式 status record 路径，并从该路径读取 session id、engine id、recorded state；
- text/JSON response 都固定 `liveness_verified=false`，不声称跨进程 runtime 存活；
- record 缺失时保留稳定 read-failed 错误，且不写入或创建 snapshot。

第五个合同测试必须证明 `managed-status init`：

- 解析显式 status record 路径、session id、engine id 和 state，并写入 schema version 1 record；
- text/JSON response 都固定 `record_written=true` 与 `liveness_verified=false`；
- 目标 record 已存在时保留稳定 write-failed 错误，且不覆盖原始内容。

第六个合同测试必须证明 `managed-status transition`：

- 解析显式 status/snapshot 路径、expected state 和 next state，并将 `starting` record 迁移为 `running`；
- text/JSON response 都固定 previous/next state、`snapshot_written=true` 与 `liveness_verified=false`；
- stale expected state 保留稳定 state-conflict 错误，不修改 status record，也不创建 snapshot。
