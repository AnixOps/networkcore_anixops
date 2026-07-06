# Changelog

本文件记录项目可审计变更。格式遵循轻量级 `Keep a Changelog` 风格，但所有验证结论以 GitHub Actions 为准。

## Unreleased

### Added

- 新增 Linux CLI entrypoint 设计文档，明确首个 `networkcore-linux` 入口的命令、配置加载、启动/停止、状态查询、输出和退出码边界。
- 新增 Linux platform adapter 设计文档，定义 TUN、权限、DNS、服务管理、证书和诊断探测边界。
- 新增 Linux artifact 发布前设计文档，明确首个平台产物的源码、packaging、checksum、签名/证明和回滚前置条件。
- 补充 release rollback contract 占位 job，定义真实 artifact 发布说明必须输出的回滚字段。
- 补充 release signing/attestation contract 占位 job，定义真实平台 artifact 发布前的签名或证明进入条件。
- 补充 release artifact checksum contract 占位 job，定义首个真实 artifact job 的 checksum 输出字段。
- 补充 release-ci-gate 占位 job，记录真实 artifact 前必须关联 `main` CI 成功结果。
- 补充 release workflow summary job，输出 placeholder 发布状态和后续 artifact 门禁。
- 补充 release workflow 发布来源 summary，记录 workflow_dispatch 版本输入、触发事件、ref、commit SHA 和 actor。
- 补充 release workflow 版本格式与触发来源一致性 policy gate，约束手动 placeholder release 来源和 tag 版本。
- 补充 CI summary GitHub Step Summary 表格，汇总项目类型检测开关和关键 job 结果。
- 补充 CI summary 项目类型检测输出，每次记录 Go、Rust、Node、Swift 和 Apple 检测开关。
- 补强 CI summary Go、Node、Swift 和 Apple 条件门禁，显式输出并在对应项目出现时检查语言与平台 job 结果。
- 补强 CI summary Rust 门禁，显式输出并检查 Rust build/test 矩阵结果和 Rust dependency security audit 结果。
- 补充 `control-runtime` MITM gate 权限拒绝诊断顺序合同测试，覆盖平台、证书、manifest 非错误诊断和 runtime 权限拒绝诊断按聚合顺序输出。
- 补充 `control-runtime` MITM gate manifest 错误拒绝诊断顺序合同测试，覆盖平台、证书、manifest 和 runtime 诊断按聚合顺序输出。
- 补充 `control-runtime` MITM gate manifest 错误优先于权限拒绝合同测试，覆盖 manifest 错误会在缺失权限前短路并返回 manifest 错误拒绝原因。
- 补充 `control-runtime` MITM gate manifest 错误拒绝证书诊断保留合同测试，覆盖证书诊断会保留在 manifest 错误拒绝决策输出中。
- 补充 `control-runtime` MITM gate manifest 错误拒绝平台诊断保留合同测试，覆盖平台诊断会保留在 manifest 错误拒绝决策输出中。
- 补充 `control-runtime` MITM gate manifest 错误拒绝审计合同测试，覆盖 manifest 错误拒绝 reason、审计和禁止调用插件 `load`/`handle_http_event`/`audit` 端口。
- 补充 `control-runtime` MITM gate 远程脚本拒绝诊断聚合合同测试，覆盖平台诊断会保留在远程脚本拒绝决策输出中。
- 补充 `control-runtime` MITM gate 证书拒绝诊断聚合合同测试，覆盖证书状态诊断会保留在证书拒绝决策输出中。
- 补充 `control-runtime` MITM gate 权限拒绝诊断聚合合同测试，覆盖 manifest 非错误诊断会保留在权限拒绝决策输出中。
- 补充 `control-runtime` MITM gate 平台诊断拒绝路径合同测试，覆盖平台能力诊断会保留在平台拒绝决策输出中。
- 补充 `control-runtime` MITM gate 平台诊断聚合合同测试，覆盖平台能力与证书诊断会进入允许决策输出。
- 补充 `control-runtime` MITM gate 插件结果诊断聚合合同测试，覆盖插件执行返回 warning/info 诊断会进入允许决策输出。
- 补充 `control-runtime` MITM gate manifest 警告诊断放行合同测试，覆盖 warning/info 诊断不会阻断插件执行且会聚合到输出。
- 补充 `control-runtime` MITM gate 权限拒绝审计合同测试，覆盖缺失权限 reason 和禁止调用插件 `load`/`handle_http_event`/`audit` 端口。
- 补充 `control-runtime` MITM gate 远程脚本未知状态合同测试，覆盖未知状态拒绝原因、诊断、审计和禁止调用插件端口。
- 补充 `control-runtime` MITM gate 证书状态拒绝矩阵合同测试，覆盖证书未安装、已安装未信任、已撤销和未知状态，并确认拒绝路径不会调用插件端口。
- 补充 `control-runtime` MITM gate 平台 MITM 不可用合同测试，覆盖平台拒绝原因和禁止调用插件端口。
- 补充 `control-runtime` MITM gate 审计事件聚合合同测试，覆盖 gate 审计、插件结果审计和 `audit` 端口审计的输出边界。
- 补充 `control-runtime` MITM gate manifest validation 合同测试，覆盖 manifest 诊断拒绝路径。
- 扩展 `control-runtime` MITM gate，新增远程脚本执行禁用拒绝路径，并覆盖插件加载与事件处理端口错误传播。
- 新增 `control-runtime` MITM gate 初始用例，组合平台能力与 MITM 插件端口，并覆盖证书未信任、权限拒绝和授权通过路径。
- 新增最小 `control-runtime` crate，组合配置、平台能力和代理引擎领域端口，并覆盖启动成功、平台拒绝和引擎错误传播路径。
- 新增运行层编排设计文档，定义 `control-runtime` 的职责、生命周期、端口组合和首个源码增量验收条件。
- 在 `control-domain` 中新增平台能力状态、MITM 证书状态和 `PlatformCapabilityService` 领域端口。
- 新增发布策略文档，定义真实平台产物进入 release workflow 前的门禁、矩阵和回滚路径。
- 新增 iOS 平台风险评估，覆盖 Network Extension、证书信任、插件脚本权限和 App Review 门禁。
- 新增 Rust dependency/security scan CI job，在 GitHub Actions 中生成 lockfile 并执行 `cargo audit`。
- 新增可插拔代理执行内核适配接口规格，并在 `control-domain` 中加入 `ProxyEngineService` 领域端口。
- 新增最小 Rust workspace 与 `control-domain` crate，提供领域共享类型、端口 trait、单元测试和集成测试。
- 新增控制内核接口草案，覆盖配置、订阅、策略路由、DNS、MITM 插件和控制 API 的首批契约。
- 新增 ADR 0001，选择 Rust 作为首个统一控制内核实现栈，并记录后续 CI/CD 验证策略。
- 新增统一控制内核领域与架构规格，定义首批上下文、端口和后续源码骨架验收条件。
- 建立 `ROADMAP.md`，明确 bootstrap、架构规格、内核骨架、运行能力和客户端集成阶段。
- 建立 `TODO.md`，记录当前最小增量待办和维护规则。
- 将规划治理文件纳入 README 与 CI policy 约束。

## 2026-07-06

### Added

- 建立 bootstrap 阶段的代理规范、贡献规则、CI/CD policy、GitHub Actions skeleton 和人工介入记录。
