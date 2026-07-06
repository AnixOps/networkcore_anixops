# networkcore_AnixOps

`networkcore_AnixOps` 是面向全平台网络内核、MITM 插件兼容和客户端体系的规划与实现仓库。

## 目标

- 构建 Linux、macOS、Windows、iOS 可用的统一网络控制内核。
- 优先支持本仓库内核，同时保留 `sing-box`、`xray-core`、`mihomo` 等多内核适配能力。
- 支持类似 Loon、Quantumult X 的 MITM 插件系统，优先兼容 Loon 插件格式的高频子集。
- 建设全平台客户端，重点验证 iOS Network Extension、MITM、插件脚本、App Review 的可操作性。

## 工作方式

本仓库执行严格的 CI/CD 优先策略：

- 本机只写代码和文档。
- 所有测试、构建、编译、打包、发布验证均由 GitHub Actions 完成。
- 本地不运行构建或测试命令。
- GitHub Actions 未打通前，需要人工介入的事项记录在 `docs/manual-intervention.md`。

详细规则见：

- [AGENT.md](AGENT.md)
- [docs/ci-cd-policy.md](docs/ci-cd-policy.md)
- [docs/release-strategy.md](docs/release-strategy.md)
- [docs/architecture/control-kernel-domain.md](docs/architecture/control-kernel-domain.md)
- [docs/architecture/control-kernel-interfaces.md](docs/architecture/control-kernel-interfaces.md)
- [docs/architecture/proxy-engine-adapter.md](docs/architecture/proxy-engine-adapter.md)
- [docs/architecture/ios-platform-risk-assessment.md](docs/architecture/ios-platform-risk-assessment.md)
- [docs/architecture/adr-0001-initial-core-stack.md](docs/architecture/adr-0001-initial-core-stack.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [ROADMAP.md](ROADMAP.md)
- [TODO.md](TODO.md)
- [CHANGELOG.md](CHANGELOG.md)

## 当前状态

当前仓库处于 P2 初始内核骨架阶段，已建立协作规范、规划治理入口、架构规格、发布策略、iOS 平台风险评估、Rust 首选栈决策、最小 `control-domain` crate、平台能力状态类型和 Rust 依赖安全扫描 CI。后续实现必须先补齐对应规格或设计说明，并通过 CI/CD 验证。

## 源码布局

- [crates/control-domain](crates/control-domain)：统一控制内核的首批领域类型与端口 trait。
