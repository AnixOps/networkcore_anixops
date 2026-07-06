# TODO

本文件记录当前最小增量级待办。长期方向见 [ROADMAP.md](ROADMAP.md)，所有验证规则见 [docs/ci-cd-policy.md](docs/ci-cd-policy.md)。

## 当前

- [ ] 补充 `networkcore-linux prepare-config/start` 运行层接线前设计，明确配置服务、代理引擎服务和前台生命周期 adapter 边界。

## 已完成

- [x] 将 `networkcore-linux capabilities/status/diagnostics` 接入 `HostLinuxReadOnlyProbe`，通过 CLI 输出真实只读 Linux 平台诊断。
- [x] 在 `platform-linux` 中新增只读 Linux 平台探测服务，提供 TUN、权限、DNS、service 和证书状态诊断映射合同测试。
- [x] 补充 release workflow 中的 Linux artifact readiness gate，检查 CLI 源码、安装/回滚设计和 release 前置合同，继续阻止未满足门禁的 release asset。
- [x] 补充 Linux CLI artifact 安装、卸载与回滚设计，明确首个压缩包发布前置条件。
- [x] 创建最小 Linux CLI entrypoint crate，提供命令解析骨架与配置/平台诊断合同测试。
- [x] 创建最小 `platform-linux` crate，提供 `PlatformCapabilityService` 测试替身和 Linux 诊断映射合同测试。
- [x] 补充 Linux CLI entrypoint 设计文档，明确首个可运行入口、配置加载、启动/停止和状态查询边界。
- [x] 补充 Linux platform adapter 设计文档，定义 TUN、权限、DNS 与服务管理能力探测边界。
- [x] 补充 Linux artifact 发布前设计文档，明确首个平台产物的源码与 packaging 前置条件。
- [x] 在 release workflow 中补充 artifact rollback 占位说明，定义发布说明必须输出的回滚字段。
- [x] 在 release workflow 中补充 artifact signing/attestation 占位说明，定义真实 artifact 的签名或证明进入条件。
- [x] 在 release workflow 中补充 artifact checksum 占位说明，定义首个真实 artifact job 的 checksum 输出字段。
- [x] 在 release workflow 中补充 release-ci-gate 占位 job，记录真实 artifact 前必须关联 `main` CI 成功结果。
- [x] 在 release workflow 中补充 release summary job，输出当前 placeholder 发布状态和后续 artifact 门禁。
- [x] 在 release workflow 中补充 workflow_dispatch 版本输入与触发 ref 记录，确保 summary 输出发布来源。
- [x] 在 release workflow 中补充版本格式与触发来源一致性 policy gate，防止 placeholder release 使用不可追踪版本。
- [x] 在 CI summary 中补充 GitHub Step Summary 表格，汇总项目检测开关与关键 job 结果。
- [x] 在 CI workflow 中补充 summary 输出项目类型检测结果，确保每次 CI 都记录 Go、Rust、Node、Swift 和 Apple 检测开关。
- [x] 在 CI summary 中补充 Go、Node、Swift 和 Apple 条件结果门禁，确保对应项目出现时 summary job 显式检查语言与平台结果。
- [x] 在 CI summary 中补充 Rust build/test 矩阵结果门禁，确保 summary job 显式检查 Rust build/test 结果。
- [x] 在 `control-runtime` 中补充 MITM gate 权限拒绝诊断顺序合同测试，覆盖 manifest 非错误诊断会在 runtime 权限拒绝诊断前输出。
- [x] 在 `control-runtime` 中补充 MITM gate manifest 错误拒绝诊断顺序合同测试，覆盖平台、证书、manifest 和 runtime 诊断按聚合顺序输出。
- [x] 在 `control-runtime` 中补充 MITM gate manifest 错误优先于权限拒绝合同测试，覆盖 manifest 错误会在缺失权限前短路并返回 manifest 错误拒绝原因。
- [x] 在 `control-runtime` 中补充 MITM gate manifest 错误拒绝证书诊断保留合同测试，覆盖证书诊断会保留在 manifest 错误拒绝决策输出中。
- [x] 在 `control-runtime` 中补充 MITM gate manifest 错误拒绝平台诊断保留合同测试，覆盖平台诊断会保留在 manifest 错误拒绝决策输出中。
- [x] 在 `control-runtime` 中补充 MITM gate manifest 错误拒绝审计合同测试，覆盖 manifest 错误拒绝 reason、审计和禁止调用插件 `load`/`handle_http_event`/`audit` 端口。
- [x] 在 `control-runtime` 中补充 MITM gate 远程脚本拒绝诊断聚合合同测试，覆盖平台诊断会保留在远程脚本拒绝决策输出中。
- [x] 在 `control-runtime` 中补充 MITM gate 证书拒绝诊断聚合合同测试，覆盖证书状态诊断会保留在证书拒绝决策输出中。
- [x] 在 `control-runtime` 中补充 MITM gate 权限拒绝诊断聚合合同测试，覆盖 manifest 非错误诊断会保留在权限拒绝决策输出中。
- [x] 在 `control-runtime` 中补充 MITM gate 平台诊断拒绝路径合同测试，覆盖平台能力诊断会保留在平台拒绝决策输出中。
- [x] 在 `control-runtime` 中补充 MITM gate 平台诊断聚合合同测试，覆盖平台能力与证书诊断会进入允许决策输出。
- [x] 在 `control-runtime` 中补充 MITM gate 插件结果诊断聚合合同测试，覆盖插件执行返回 warning/info 诊断会进入允许决策输出。
- [x] 在 `control-runtime` 中补充 MITM gate manifest 警告诊断放行合同测试，覆盖 warning/info 诊断不会阻断插件执行且会聚合到输出。
- [x] 在 `control-runtime` 中补充 MITM gate 权限拒绝审计合同测试，覆盖缺失权限的审计 reason 和禁止调用插件 load/handle/audit 端口。
- [x] 在 `control-runtime` 中补充 MITM gate 远程脚本未知状态合同测试，覆盖未知状态拒绝原因和禁止调用插件端口。
- [x] 在 `control-runtime` 中补充 MITM gate 证书状态拒绝矩阵合同测试，覆盖证书未安装、已撤销和未知状态。
- [x] 在 `control-runtime` 中补充 MITM gate 平台 MITM 不可用合同测试，覆盖平台拒绝原因和禁止调用插件端口。
- [x] 在 `control-runtime` 中补充 MITM gate 审计事件聚合合同测试，覆盖 gate 审计、插件结果审计和 `audit` 端口审计的输出边界。
- [x] 在 `control-runtime` 中补充 MITM gate manifest validation 合同测试，覆盖 manifest 诊断拒绝路径。
- [x] 在 `control-runtime` 的 MITM gate 中补充远程脚本禁用边界和插件端口错误传播用例。
- [x] 在 `control-runtime` 中补充 MITM gate 用例，覆盖证书未信任和权限拒绝路径。
- [x] 创建最小 `control-runtime` crate，依赖 `control-domain` 并实现运行层编排的首批纯用例与测试替身。
- [x] 在创建 `control-runtime` crate 前补充运行层编排设计文档。
- [x] 在 `control-domain` 中补充平台能力状态和 MITM 证书状态的领域类型。
- [x] 在 release workflow 中加入真实平台产物前，先完成发布策略文档。
- [x] 评估 iOS Network Extension、证书安装、插件脚本权限和 App Review 风险。
- [x] 补齐 Rust dependency/security scan workflow，并通过 GitHub Actions 验证。
- [x] 设计可插拔代理执行内核适配接口，保留 `sing-box`、`xray-core`、`mihomo` 适配空间。
- [x] 创建最小 Rust workspace 与 `control-domain` crate 骨架，并通过 GitHub Actions 激活 Rust format、lint、test、build。
- [x] 为配置模型、订阅解析、策略路由、DNS、MITM 插件和控制 API 建立文档化接口草案。
- [x] 明确首个源码栈选择及对应 GitHub Actions 验证策略。
- [x] 编写 P1 领域与架构规格，先定义统一控制内核的模块边界。

## 维护规则

- 每轮迭代最多完成一个最小可验证增量。
- 新增源码前必须先有对应规格或设计说明。
- 完成项应在同一变更中同步更新 [CHANGELOG.md](CHANGELOG.md)。
- 需要人工处理的外部事项必须记录到 [docs/manual-intervention.md](docs/manual-intervention.md)。
