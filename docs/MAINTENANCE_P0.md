# NetworkCore 首批运维交接

首批交付范围是统一诊断事件的校验、JSON 序列化和显式适配边界。NetworkCore 的订阅实际运行、进程管理、MITM、浏览器捕获和跨平台客户端继续按 [ROADMAP](../ROADMAP.md) 推进；这些后续能力不作为 Control + Agent 机器监控首批交付的依赖。

## 当前可调用入口

- `control_domain::maintenance::MaintenanceEvent::from_json` / `to_json`：单事件严格 JSON 校验与序列化。
- `MaintenanceEvent::validate_for_node`：将载荷身份与调用方提供的已认证节点比较。
- `MaintenanceBatch::from_json` / `to_json`：`anixops.maintenance/v1` 批量载荷校验与序列化，保留逐事件成功/失败结果。
- `control_runtime::maintenance::adapt_maintenance_diagnostic`：用显式观察上下文和诊断分类生成事件，原始 `Diagnostic.message`、`source` 和任意 `code` 不进入载荷。

这些是库函数。本仓库没有为该边界启动 WebSocket、持久化待发送队列、运维工单消费者或通知后台任务，也没有把 `managed-event` 本地记录视为真实进程故障来源。生产接入由宿主 Agent 的真实观察、身份、持久化和 ACK 路径承担。单纯构造类型不构成运行时接入验收。

## 配置、启动与日志

宿主必须显式提供 environment、已认证 node ID、plugin/instance/version、event ID、发生时间、首次失败时间、连续失败次数和恢复观察时间。事件 ID 在重传时保持不变。时间格式为 RFC3339，节点 ID 为正十进制字符串。不得从诊断文本或订阅内容推导身份。

宿主已有启动流程调用适配器后，才可把 JSON 交给其已认证 WebSocket 的 `maintenance_events` 消息；逐事件 `maintenance_ack` 中仅 `persisted=true` 可确认持久化。NetworkCore 的适配器不自行发送、删除或确认事件。库返回固定错误说明，不把原始 JSON 或解析异常内容写入日志。

诊断分类必须来自真实观察来源；凭据、权限、签名和配置错误使用固定 `PLUGIN_*` 错误码进入人工处理，安全、数据完整性和 Control 不可用使用重大错误码。生成的摘要为固定可读文案，Control 仍独立执行服务端数据最小化，丢弃传入的 `redacted_summary`、`diagnostic_ref` 和 `ticket_key` 后生成结构化展示。

## 运维规则与权限

- 普通故障同时满足连续失败至少 3 次和持续至少 2 分钟；持续健康 5 分钟才恢复。故障时长从首次失败计算，认领不重置。
- 自动修复仅限宿主明确允许的重试和实例重启，每实例 30 分钟最多 2 次，预算由 Agent 持久化。`circuit_break` 仅报告预算阻断。契约不允许自动 rollback。
- 技术员可重启或手动把单节点恢复到已验证版本；新版本生产升级、批量、数据库或系统网络变更需负责人对具体操作和版本批准，并由 Control 留审计。
- 未关闭工单按 environment/node/plugin/instance 继续聚合，错误码或版本变化不另开单；关闭后的复发由 Control 新建并关联历史。
- 原始诊断 30 天，事件及通知记录 90 天，摘要与审计 1 年；未关闭工单所需证据暂缓清理。NetworkCore 本库不执行清理。

## 人工回滚

先从可信发布记录确认原版本、目标已验证 tag、同提交 CI、目标平台、制品 SHA256、当前能力边界和回滚说明。通过 Control 的人工操作流程记录具体节点、目标版本、执行人和操作结果；高权限操作经过负责人批准。不得把 `managed-status rollback` 恢复本地记录误称为运行中进程或配置的回滚。

没有制品证据、权限或回滚演练时保持待验收，不执行生产变更。真实部署地址、密钥、订阅 URL、API token、私钥和完整流量内容不写入仓库或工单。

## 证据与后续门槛

[交付状态](P4_EXECUTION_STATUS.md) 分开登记源码、当前提交 CI 与真实环境证据。CI 必须覆盖恶意输入、时间/大小/枚举/版本、伪造节点、坏事件隔离、阈值、序列化和诊断脱敏，并完成既有业务回归。真实邮件/Telegram、第三方独立监控、跨地域网络与设备验证属于上线前独立门槛；本仓库合同测试不替代这些证据。

后续发布交接应登记 release、commit、CI run URL、target、制品 SHA256、已验证 rollback release 和 capability gates。上述交接字段是待核对清单，不代表当前 release manifest 已全部实现同名机器字段。无法由当前自动化完成的事项见 [人工介入清单](manual-intervention.md)。
