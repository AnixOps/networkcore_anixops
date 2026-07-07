# Roadmap

本路线图用于把 `networkcore_AnixOps` 从 bootstrap 仓库逐步推进为可验证、可维护的全平台网络内核与客户端体系。所有阶段都必须遵守 [AGENT.md](AGENT.md) 和 [docs/ci-cd-policy.md](docs/ci-cd-policy.md)：本机只编辑文件，验证只在 GitHub Actions 中运行。

## 当前阶段：P0 Bootstrap Governance

目标是建立后续代码落地前必须稳定存在的协作、CI/CD 和规划基线。

完成标准：

- 代理与贡献规范清晰，且多工具入口一致指向主规范。
- CI/CD policy 明确本地与 GitHub Actions 的职责边界。
- CI workflow 能检查治理文件并在多平台 runner 上完成基础工作区验证。
- Roadmap、TODO、CHANGELOG 成为每轮迭代的固定记录入口。
- Release strategy 明确真实平台产物进入 release workflow 前的门禁、矩阵和回滚路径。

## P1 Domain And Architecture Specification

目标是先定义稳定边界，再选择具体技术栈和实现顺序。

预期产物：

- 统一控制内核的领域模型说明。
- 配置、订阅、策略路由、DNS、MITM 插件、跨平台控制 API 的边界文档。
- 插件权限模型和 iOS 审核风险初评。
- 首个可验证源码栈的 CI 设计。

当前规格：

- [Control Kernel Domain Specification](docs/architecture/control-kernel-domain.md)
- [Control Kernel Interface Draft](docs/architecture/control-kernel-interfaces.md)
- [iOS Platform Risk Assessment](docs/architecture/ios-platform-risk-assessment.md)
- [iOS Network Extension Design](docs/architecture/ios-network-extension-design.md)
- [iOS Platform Adapter Source Contract](docs/architecture/ios-platform-adapter-source-contract.md)
- [iOS Swift Network Extension Bridge Design](docs/architecture/ios-swift-network-extension-bridge-design.md)
- [iOS Swift Xcode Bridge Source Contract](docs/architecture/ios-swift-xcode-bridge-source-contract.md)
- [iOS Embedded Runtime FFI Boundary Design](docs/architecture/ios-embedded-runtime-ffi-boundary-design.md)
- [ADR 0001: Initial Core Stack](docs/architecture/adr-0001-initial-core-stack.md)

## P2 Core Kernel Skeleton

目标是创建最小可编译、可测试、可回滚的内核骨架。

预期产物：

- 内核仓库结构和模块边界。
- 配置模型与订阅解析的最小接口。
- GitHub Actions 中对应语言的 build、test、lint 或等效验证。
- README、TODO、CHANGELOG 与设计文档同步更新。

当前源码：

- [networkcore-linux](apps/linux-cli)
- [config-core](crates/config-core)
- [control-domain](crates/control-domain)
- [control-runtime](crates/control-runtime)
- [engine-native](crates/engine-native)
- [mitm-anixops-sys](crates/mitm-anixops-sys)
- [platform-ios](crates/platform-ios)
- [platform-linux](crates/platform-linux)

当前规格：

- [Control Runtime Orchestration Design](docs/architecture/control-runtime-orchestration.md)

## P3 Runtime Capabilities

目标是逐步实现可组合的网络控制能力。

预期方向：

- 策略路由与规则匹配。
- DNS 策略和缓存模型。
- MITM 插件运行时的高频 Loon 子集兼容。
- 可插拔代理执行内核适配接口。

当前规格：

- [Proxy Engine Adapter Interface](docs/architecture/proxy-engine-adapter.md)
- [mitm_anixops Adapter Design](docs/architecture/mitm-anixops-adapter.md)
- [Native Engine Listener And Node Config Design](docs/architecture/native-engine-listener-node-config.md)
- [Linux Native Proxy Engine Start Design](docs/architecture/linux-native-proxy-engine-start.md)

## P4 Client And Platform Integration

目标是在不破坏内核边界的前提下推进全平台客户端。

预期方向：

- Linux、macOS、Windows 客户端控制入口。
- iOS Network Extension 可行性验证。
- 证书安装、权限提示、插件脚本边界和 App Review 风险治理。
- 发布 workflow 的平台产物矩阵。

当前发布规划：

- [Release Strategy](docs/release-strategy.md)
- [iOS Network Extension Design](docs/architecture/ios-network-extension-design.md)
- [iOS Platform Adapter Source Contract](docs/architecture/ios-platform-adapter-source-contract.md)
- [iOS Swift Network Extension Bridge Design](docs/architecture/ios-swift-network-extension-bridge-design.md)
- [iOS Swift Xcode Bridge Source Contract](docs/architecture/ios-swift-xcode-bridge-source-contract.md)
- [iOS Embedded Runtime FFI Boundary Design](docs/architecture/ios-embedded-runtime-ffi-boundary-design.md)
- [Linux Artifact Pre-Release Design](docs/architecture/linux-artifact-pre-release-design.md)
- [Linux Platform Adapter Design](docs/architecture/linux-platform-adapter.md)
- [Linux CLI Entrypoint Design](docs/architecture/linux-cli-entrypoint.md)
- [Linux CLI Runtime Wiring Design](docs/architecture/linux-cli-runtime-wiring.md)
- [Native Engine Listener And Node Config Design](docs/architecture/native-engine-listener-node-config.md)
- [Linux Native Proxy Engine Start Design](docs/architecture/linux-native-proxy-engine-start.md)
- [Linux CLI Artifact Installation And Rollback Design](docs/architecture/linux-cli-artifact-installation-rollback.md)
- [Linux Package Artifact Manifest Design](docs/architecture/linux-package-artifact-manifest.md)
- [Linux Artifact License Notice Confirmation Design](docs/architecture/linux-artifact-license-notice-confirmation.md)
- [Linux Package License Notice Transition Validation Contract](docs/architecture/linux-package-license-notice-transition-validation-contract.md)
- [Release CI Success Source Contract](docs/architecture/release-ci-success-source-contract.md)
- [Linux Package Release CI Gate Activation Validation Contract](docs/architecture/linux-package-release-ci-gate-activation-validation-contract.md)
- [Release CI Gate Execution Validation Contract](docs/architecture/release-ci-gate-execution-validation-contract.md)
- [Release CI Gate API Implementation Plan](docs/architecture/release-ci-gate-api-implementation-plan.md)
- [Linux Package Artifact Job Preflight Validation Contract](docs/architecture/linux-package-artifact-job-preflight-validation-contract.md)
- [Linux Package Artifact Build Command Validation Contract](docs/architecture/linux-package-artifact-build-command-validation-contract.md)
- [Linux Package Artifact Staging File Validation Contract](docs/architecture/linux-package-artifact-staging-file-validation-contract.md)
- [Linux Package Artifact Archive Creation Validation Contract](docs/architecture/linux-package-artifact-archive-creation-validation-contract.md)
- [Linux Package Artifact Checksum Execution Validation Contract](docs/architecture/linux-package-artifact-checksum-execution-validation-contract.md)
- [Linux Package Artifact Manifest Generation Validation Contract](docs/architecture/linux-package-artifact-manifest-generation-validation-contract.md)
- [Linux Package Artifact Manifest Checksum Validation Contract](docs/architecture/linux-package-artifact-manifest-checksum-validation-contract.md)
- [Linux Package Workflow Artifact Bundle Upload Validation Contract](docs/architecture/linux-package-workflow-artifact-bundle-upload-validation-contract.md)
- [Linux Package Artifact Attestation Execution Validation Contract](docs/architecture/linux-package-artifact-attestation-execution-validation-contract.md)
- [Linux Package Release Notes Rollback Execution Validation Contract](docs/architecture/linux-package-release-notes-rollback-execution-validation-contract.md)
- [Linux Package Publish Eligibility Execution Validation Contract](docs/architecture/linux-package-publish-eligibility-execution-validation-contract.md)
- [Linux Package Runner Toolchain Target Contract](docs/architecture/linux-package-runner-toolchain-target-contract.md)
- [Linux Package Archive Staging Contract](docs/architecture/linux-package-archive-staging-contract.md)
- [Linux Package Checksum Manifest Contract](docs/architecture/linux-package-checksum-manifest-contract.md)
- [Linux Package Publish Upload Boundary Contract](docs/architecture/linux-package-publish-upload-boundary-contract.md)
- [Linux Package Signing Attestation Policy Binding Contract](docs/architecture/linux-package-signing-attestation-policy-binding-contract.md)
- [Linux Package Release Notes Rollback Policy Binding Contract](docs/architecture/linux-package-release-notes-rollback-policy-binding-contract.md)
- [Linux Package Publish Eligibility Aggregate Contract](docs/architecture/linux-package-publish-eligibility-aggregate-contract.md)

## 迭代选择规则

每轮只选择一个最小可验证增量。优先级按以下顺序判断：

1. 修复会阻断 CI/CD、协作或回滚能力的问题。
2. 补齐下一步实现前缺失的规范、设计和接口。
3. 添加最小源码骨架及其 GitHub Actions 验证。
4. 扩展功能前先补齐测试、文档和风险记录。
