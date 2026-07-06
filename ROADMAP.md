# Roadmap

本路线图用于把 `networkcore_AnixOps` 从 bootstrap 仓库逐步推进为可验证、可维护的全平台网络内核与客户端体系。所有阶段都必须遵守 [AGENT.md](AGENT.md) 和 [docs/ci-cd-policy.md](docs/ci-cd-policy.md)：本机只编辑文件，验证只在 GitHub Actions 中运行。

## 当前阶段：P0 Bootstrap Governance

目标是建立后续代码落地前必须稳定存在的协作、CI/CD 和规划基线。

完成标准：

- 代理与贡献规范清晰，且多工具入口一致指向主规范。
- CI/CD policy 明确本地与 GitHub Actions 的职责边界。
- CI workflow 能检查治理文件并在多平台 runner 上完成基础工作区验证。
- Roadmap、TODO、CHANGELOG 成为每轮迭代的固定记录入口。

## P1 Domain And Architecture Specification

目标是先定义稳定边界，再选择具体技术栈和实现顺序。

预期产物：

- 统一控制内核的领域模型说明。
- 配置、订阅、策略路由、DNS、MITM 插件、跨平台控制 API 的边界文档。
- 插件权限模型和 iOS 审核风险初评。
- 首个可验证源码栈的 CI 设计。

当前规格：

- [Control Kernel Domain Specification](docs/architecture/control-kernel-domain.md)
- [ADR 0001: Initial Core Stack](docs/architecture/adr-0001-initial-core-stack.md)

## P2 Core Kernel Skeleton

目标是创建最小可编译、可测试、可回滚的内核骨架。

预期产物：

- 内核仓库结构和模块边界。
- 配置模型与订阅解析的最小接口。
- GitHub Actions 中对应语言的 build、test、lint 或等效验证。
- README、TODO、CHANGELOG 与设计文档同步更新。

## P3 Runtime Capabilities

目标是逐步实现可组合的网络控制能力。

预期方向：

- 策略路由与规则匹配。
- DNS 策略和缓存模型。
- MITM 插件运行时的高频 Loon 子集兼容。
- 可插拔代理执行内核适配接口。

## P4 Client And Platform Integration

目标是在不破坏内核边界的前提下推进全平台客户端。

预期方向：

- Linux、macOS、Windows 客户端控制入口。
- iOS Network Extension 可行性验证。
- 证书安装、权限提示、插件脚本边界和 App Review 风险治理。
- 发布 workflow 的平台产物矩阵。

## 迭代选择规则

每轮只选择一个最小可验证增量。优先级按以下顺序判断：

1. 修复会阻断 CI/CD、协作或回滚能力的问题。
2. 补齐下一步实现前缺失的规范、设计和接口。
3. 添加最小源码骨架及其 GitHub Actions 验证。
4. 扩展功能前先补齐测试、文档和风险记录。
