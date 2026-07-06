# Changelog

本文件记录项目可审计变更。格式遵循轻量级 `Keep a Changelog` 风格，但所有验证结论以 GitHub Actions 为准。

## Unreleased

### Added

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
