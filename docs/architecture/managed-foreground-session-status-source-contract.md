# Managed Foreground Session Status Source Contract

本文定义 `v0.1.2-alpha.2` managed foreground lifecycle 的两个 source-only status record 切片。
它只读取或初始写入调用方显式指定的 managed foreground session status record，不把记录内容误称为进程存活证明。

## Source Of Truth

- `managed-foreground-session-status-source-contract=active`
- `managed-foreground-session-status-version-scope=v0.1.2-alpha.2`
- `managed-foreground-session-status-operation=status-read`
- `managed-foreground-session-status-write-operation=status-write`
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

本切片只读取或初始写入 status record，不修改 catalog，不启动、停止、reload 或 rollback runtime，
不读取 events/logs，不扫描默认路径，不读取远程或 subscription 文件，不创建 daemon/control socket，
不安装 service，不执行 system proxy、system trust store、TUN、DNS 或 firewall mutation。

CLI command wiring、record 覆盖/状态迁移、PID/port liveness 检查、events/logs/reload/rollback 由后续独立功能处理。
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
