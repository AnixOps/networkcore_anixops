# TODO

本文件记录当前最小增量级待办。长期方向见 [ROADMAP.md](ROADMAP.md)，所有验证规则见 [docs/ci-cd-policy.md](docs/ci-cd-policy.md)。

## 当前

- [ ] 编写 P1 领域与架构规格，先定义统一控制内核的模块边界。
- [ ] 明确首个源码栈选择及对应 GitHub Actions 验证策略。
- [ ] 为配置模型、订阅解析、策略路由、DNS、MITM 插件和控制 API 建立文档化接口草案。

## 后续

- [ ] 创建最小内核源码骨架，并在 CI 中启用对应语言的构建与测试。
- [ ] 设计可插拔代理执行内核适配接口，保留 `sing-box`、`xray-core`、`mihomo` 适配空间。
- [ ] 评估 iOS Network Extension、证书安装、插件脚本权限和 App Review 风险。
- [ ] 在 release workflow 中加入真实平台产物前，先完成发布策略文档。

## 维护规则

- 每轮迭代最多完成一个最小可验证增量。
- 新增源码前必须先有对应规格或设计说明。
- 完成项应在同一变更中同步更新 [CHANGELOG.md](CHANGELOG.md)。
- 需要人工处理的外部事项必须记录到 [docs/manual-intervention.md](docs/manual-intervention.md)。
