# TODO

本文件记录当前最小增量级待办。长期方向见 [ROADMAP.md](ROADMAP.md)，所有验证规则见 [docs/ci-cd-policy.md](docs/ci-cd-policy.md)。

## 当前

- [ ] 在 `control-runtime` 中补充 MITM gate manifest 警告诊断放行合同测试，覆盖 warning/info 诊断不会阻断插件执行且会聚合到输出。

## 已完成

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
