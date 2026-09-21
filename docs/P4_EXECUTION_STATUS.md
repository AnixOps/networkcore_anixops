# NetworkCore 路线图与首批交付证据

此文件保留原路径以兼容已有链接。“P4 Client And Platform Integration”只表示本仓库内部历史阶段，不能作为三个仓库的共同完成标签。所有能力分别登记源码实现、当前提交 CI 和真实环境验收；没有明确证据不得宣称生产可用。

| 能力 | 源码实现 | 当前提交 CI | 真实环境验收 |
|---|---|---|---|
| 诊断事件校验、序列化、批量坏事件隔离 | 已编写库入口与 Rust 合同测试 | 待提交后记录 run URL、SHA 与结果 | 未执行；库契约不证明运行时接入 |
| NetworkCore Diagnostic 显式适配边界 | 已编写；固定错误码、可信身份上下文、去除原始诊断文本 | 待提交后记录 run URL、SHA 与结果 | 未执行 |
| NetworkCore 到 Agent 实际运行时事件来源、持久化与 WebSocket | 尚未接线；首批只统一边界 | 无该接入验收 | 未执行 |
| Control + Agent 机器监控与运维闭环 | 由各自仓库登记，NetworkCore 不是首批运行依赖 | 不从本仓库 CI 推断 | 邮件、Telegram、外部监控及部署演练分别待验收 |
| 订阅实际运行和节点选择 | 部分解析与本地 catalog 源码；完整 runnable path 待推进 | 历史证据不能替代当前提交；见功能矩阵 | 未提供本轮运行证据 |
| managed lifecycle、进程事件、日志、reload/runtime rollback | 本地 recorded status/event 源码存在；完整进程管理待推进 | 本轮回归由 CI 验证 | 未提供；`liveness_verified=false` 保持明确 |
| MITM 与证书生命周期 | 显式授权的受控 TLS/local script source slice 与能力 gates | 以当前提交工作流结果为准 | 系统信任及真实设备范围另行验收 |
| 浏览器捕获完整用户闭环 | 部分显式 profile/proxy/proof 源码；完整接管待推进 | 以当前提交工作流结果为准 | 跨浏览器、系统代理和真实流量另行验收 |
| Linux/Windows 客户端与发布路径 | 已有源码及制品 gates | 历史发布见功能矩阵；本轮待验证 | 安装、网络及回滚环境逐项登记 |
| iOS 客户端 | source/preflight placeholder | source gates 不能作为应用验收 | Apple 账号、签名、设备、TestFlight/App Review 待验收 |

首批 NetworkCore 范围仅为前两行。后续按自身路线推进订阅实际运行、进程管理、MITM、浏览器捕获和跨平台客户端，完整历史路线保留于 [ROADMAP](../ROADMAP.md) 与 [能力矩阵](alpha-release-feature-matrix.md)。转发、WireGuard、隧道、NAT 与流量核算插件化由 Control/Agent 路线分别承接，不在这里用通用阶段名勾选完成。

## 本轮验证记录

- 源码：`control-domain::maintenance`、`control-runtime::maintenance`、共享 JSON schema 和 fixture。
- CI：待提交后由执行者填入确切 SHA、run URL、合同测试及全量回归结果。本机未运行测试、构建、编译或格式化。
- 真实环境：未执行。尚无本轮邮件/Telegram 实投、第三方监控、跨地域或真实设备证据。
- 发布与生产：未进行。真实演练、灰度观察和维护人员交接属于后续独立门槛。
