# Roadmap

本路线图用于把 `networkcore_AnixOps` 从 bootstrap 仓库逐步推进为可验证、可维护的全平台网络内核与客户端体系。所有阶段都必须遵守 [AGENT.md](AGENT.md) 和 [docs/ci-cd-policy.md](docs/ci-cd-policy.md)：本机只编辑文件，验证只在 GitHub Actions 中运行。

## 当前阶段：P4 Client And Platform Integration

P0 Bootstrap Governance、P1 Domain And Architecture Specification、P2 Core Kernel Skeleton 和 P3 Runtime Capability Baseline 已完成。当前工作进入客户端、平台和发布集成阶段：Linux CLI 已有 GitHub Actions 生成的预发布二进制，iOS 仍处于 source-tree/upload gates，运行层继续通过 public engine adapter 和后续 MITM gates 增量补齐能力。

阶段判断以本节为准：P3 是已完成 baseline，当前仓库不再处于 P3。

## P0 Bootstrap Governance (Completed)

目标是建立后续代码落地前必须稳定存在的协作、CI/CD 和规划基线。

完成标准：

- 代理与贡献规范清晰，且多工具入口一致指向主规范。
- CI/CD policy 明确本地与 GitHub Actions 的职责边界。
- CI workflow 能检查治理文件并在多平台 runner 上完成基础工作区验证。
- Roadmap、TODO、CHANGELOG 成为每轮迭代的固定记录入口。
- Release strategy 明确真实平台产物进入 release workflow 前的门禁、矩阵和回滚路径。

## P1 Domain And Architecture Specification (Completed)

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
- [iOS MITM Certificate Lifecycle Design](docs/architecture/ios-mitm-certificate-lifecycle-design.md)
- [iOS Entitlement Provisioning Source Contract](docs/architecture/ios-entitlement-provisioning-source-contract.md)
- [iOS App Review Privacy Release Readiness Design](docs/architecture/ios-app-review-privacy-release-readiness-design.md)
- [iOS Privacy Manifest Source Contract](docs/architecture/ios-privacy-manifest-source-contract.md)
- [iOS App Review Manual Confirmation Source Contract](docs/architecture/ios-app-review-manual-confirmation-source-contract.md)
- [iOS TestFlight App Store Connect Upload Workflow Source Contract](docs/architecture/ios-testflight-app-store-connect-upload-workflow-source-contract.md)
- [iOS Upload Workflow Activation Validation Contract](docs/architecture/ios-upload-workflow-activation-validation-contract.md)
- [iOS Swift Xcode Source Tree Activation Preflight Contract](docs/architecture/ios-swift-xcode-source-tree-activation-preflight-contract.md)
- [iOS Package.swift Source Ownership Activation Preflight Contract](docs/architecture/ios-package-swift-source-ownership-activation-preflight-contract.md)
- [iOS Package.swift Manifest-Only Activation Validation Contract](docs/architecture/ios-package-swift-manifest-only-activation-validation-contract.md)
- [ADR 0001: Initial Core Stack](docs/architecture/adr-0001-initial-core-stack.md)

## P2 Core Kernel Skeleton (Completed)

目标是创建最小可编译、可测试、可回滚的内核骨架。

完成产物：

- 内核仓库结构和模块边界。
- 配置模型与订阅解析的最小接口和源码合同。
- GitHub Actions 中对应语言的 build、test、lint 或等效验证。
- README、TODO、CHANGELOG 与设计文档同步更新。

当前源码：

- [networkcore-linux](apps/linux-cli)
- [config-core](crates/config-core)（`CoreConfigurationService` 与 `CoreSubscriptionService`）
- [control-domain](crates/control-domain)
- [control-runtime](crates/control-runtime)
- [engine-native](crates/engine-native)
- [engine-singbox](crates/engine-singbox)
- [mitm-anixops-sys](crates/mitm-anixops-sys)
- [mitm-policy](crates/mitm-policy)
- [apps/ios](apps/ios)（source tree governance placeholder，仅 README，不含 Swift/Xcode）
- [platform-ios](crates/platform-ios)
- [platform-linux](crates/platform-linux)

当前规格：

- [Control Runtime Orchestration Design](docs/architecture/control-runtime-orchestration.md)

## P3 Runtime Capability Baseline (Completed)

目标是逐步实现可组合的网络控制能力。本阶段已采用公有执行内核 adapter 优先策略：
先固化 NetworkCore 控制层、执行内核 adapter 层和公有执行内核层的三层维护框架，
优先接入 `sing-box`，再按需要评估 `xray-core`、`mihomo`；`engine-native` 保留为自研执行内核实验线，
但 VLESS、Shadowsocks、Trojan、VMess、Hysteria 等私有协议实现暂缓，直到公有内核 adapter 暴露出明确无法覆盖的产品缺口。

预期方向：

- 策略路由与规则匹配。
- DNS 策略和缓存模型。
- MITM 插件运行时的高频 Loon 子集兼容。
- 可插拔代理执行内核适配接口。
- 公有执行内核 adapter，优先 `sing-box`，并通过统一配置、生命周期、状态、日志和回滚边界维护。
- 自研执行内核只保留小步可审计增量，不以协议兼容追平作为当前目标。

当前规格：

- [Proxy Engine Adapter Interface](docs/architecture/proxy-engine-adapter.md)
- [ADR 0002: Public Engine Adapter First](docs/architecture/adr-0002-public-engine-adapter-first.md)
- [sing-box Public Engine Adapter Source Contract](docs/architecture/sing-box-public-engine-adapter-source-contract.md)
- [Subscription URL To sing-box Run Source Contract](docs/architecture/subscription-url-to-sing-box-run-source-contract.md)
- [mitm_anixops Adapter Design](docs/architecture/mitm-anixops-adapter.md)
- [MITM Policy Ad Block Plugin Source Contract](docs/architecture/mitm-policy-ad-block-plugin-source-contract.md)
- [Third-Party Plugin Onboarding Process](docs/architecture/third-party-plugin-onboarding-process.md)
- [Subscription Catalog Runtime Orchestration Design](docs/architecture/subscription-catalog-runtime-orchestration.md)
- [Native Engine Listener And Node Config Design](docs/architecture/native-engine-listener-node-config.md)
- [Linux Native Proxy Engine Start Design](docs/architecture/linux-native-proxy-engine-start.md)

已完成 baseline 源码状态：`control-runtime` 已具备显式 inline subscription catalog runtime gate，可把 `NodeCatalog.nodes` 编排进 `RuntimeConfigRequest.nodes`，拒绝重复 node id，并保持 `NodeCatalog.rules` deferred；`networkcore-linux run-url` 现在可消费单条 Shadowsocks URL、明文 `ss://` 链接列表或 base64 链接列表，经 `NodeCatalog` 渲染 sing-box 本地 `mixed` inbound 配置，并以前台 `sing-box run -c <config>` 暴露默认 `127.0.0.1:7890` 本地代理。`mitm_anixops` 已固定到 `v0.45.10-alpha`，`mitm-policy` 已提供 safe wrapper、`AnixOpsMitmPluginService`、内置 `networkcore.adblock` alpha 去广告插件包以及 rewrite plan/header/body chain/script/JQ guard wrapper 合同；`networkcore-linux mitm status`、`networkcore-linux mitm diagnostics`、`networkcore-linux mitm certificate-plan`、`networkcore-linux mitm browser-plan` 和 `networkcore-linux mitm browser-capture plan/launch-plan/launch/apply/rollback/verify` 已作为 `MITM_CLI_COMMAND_GATE` 的 status/diagnostics/certificate-plan/browser-plan/browser-capture report 增量接入，当前 marker 为 `mitm-cli-command-gate-status=partial-active`。`MITM_CERTIFICATE_LIFECYCLE_GATE` 当前为 plan-only，只输出 `certificate_plan`、当前证书状态、计划步骤、blocked operations 和 `mutation_ready=false`；`MITM_BROWSER_CAPTURE_GATE` 当前为 plan-only/mutation-blocked，输出 `browser_plan`、默认显式代理计划 `127.0.0.1:7890`、计划步骤、blocked operations、`mutation_ready=false`、`browser_capture` blocked report、不写系统状态的 manual dedicated-profile launch-plan、显式授权后启动 dedicated browser profile 的 `launch_report`，以及显式授权后探测计划本地代理端点的 `verify_report`；真实 request/response mutation、CA 生成/安装/信任 mutation 路径、HTTP/TLS 解密改写数据面、浏览器真实流量验证和浏览器/系统代理捕获 mutation 仍 deferred/blocked。第三方 plugin/parser/runtime 后续必须先经过 source contract、pinned source、license/NOTICE、permission、safe wrapper、CI governance 和 upgrade procedure 的固定接入流程。`networkcore-linux start` 仍不消费持久 subscription catalog。后续 runtime 缺口会在 P4 集成阶段继续推进：VLESS/VMess/Trojan/Clash/sing-box JSON 等订阅格式、节点选择、持久订阅、managed status/events/logs/reload/rollback，以及通过 `MITM_CLI_COMMAND_GATE`、`MITM_CERTIFICATE_LIFECYCLE_GATE`、`MITM_HTTP_TLS_DATA_PLANE_GATE` 和 `MITM_BROWSER_CAPTURE_GATE` 补齐 MITM 真实流量支持。

## P4 Client And Platform Integration

目标是在不破坏内核边界的前提下推进全平台客户端。

预期方向：

- Linux、macOS、Windows 客户端控制入口。
- iOS Network Extension 可行性验证。
- 证书安装、权限提示、插件脚本边界和 App Review 风险治理。
- 发布 workflow 的平台产物矩阵。

当前 P4 状态：Linux CLI artifact 已通过 tag release workflow 发布到 GitHub Release，最新已发布版本为 `v0.1.0-alpha.7`，并包含 tarball、sha256、manifest 和 manifest sha256；Linux artifact release-state consistency marker 为 `linux-artifact-release-state=confirmed-release-path`，license/NOTICE 已 confirmed，但后续 tag release 仍必须通过同 commit CI、checksum、manifest、attestation、release notes、rollback 和 publish eligibility gates。Linux 仍是手动解压和 foreground 运行模型，不安装 daemon/service，不修改 TUN/DNS/firewall/certificate trust store。iOS 仍只允许 `apps/ios/README.md` source tree governance placeholder 和 upload blocked gates，不包含 Swift/Xcode/Network Extension target、签名、TestFlight/App Store upload 或 iOS release asset。用户可用 live MITM 尚未启用；`MITM_CLI_COMMAND_GATE` 当前源码做到 status/diagnostics/certificate-plan/browser-plan partial-active，并已包含 `mitm browser-capture plan/launch-plan/launch/apply/rollback/verify` manual launch-plan、显式授权 dedicated-profile launch、本地代理端点 verify 与 blocked report 命令面；`launch --confirm` 已进入当前 Linux CLI artifact 边界，但只启动 dedicated browser profile，不写系统或浏览器代理状态；`verify --confirm` 只探测计划本地代理端点，不证明浏览器真实流量或 HTTPS MITM。`MITM_CERTIFICATE_LIFECYCLE_GATE` 当前为 plan-only/mutation-blocked，`MITM_BROWSER_CAPTURE_GATE` 当前为 plan-only/mutation-blocked，`MITM_HTTP_TLS_DATA_PLANE_GATE` 仍 blocked，browser hijack 仍 deferred。Linux MITM browser capture 已有 source contract 固定 `BrowserCaptureProcessRunner`、`BrowserCaptureEndpointProbe`、`LinuxBrowserCaptureLaunchRequest`、`LinuxBrowserCaptureLaunchReport`、`LinuxBrowserCaptureVerifyRequest`、`BrowserCaptureAuthorization`、`BrowserCaptureRollbackSnapshot`、launch-plan、launch、apply/rollback/verify 命令面、授权、快照和回滚边界，但真实浏览器/系统代理 mutation 仍未实现。

当前发布规划：

- [Release Strategy](docs/release-strategy.md)
- [iOS Network Extension Design](docs/architecture/ios-network-extension-design.md)
- [iOS Platform Adapter Source Contract](docs/architecture/ios-platform-adapter-source-contract.md)
- [iOS Swift Network Extension Bridge Design](docs/architecture/ios-swift-network-extension-bridge-design.md)
- [iOS Swift Xcode Bridge Source Contract](docs/architecture/ios-swift-xcode-bridge-source-contract.md)
- [iOS Embedded Runtime FFI Boundary Design](docs/architecture/ios-embedded-runtime-ffi-boundary-design.md)
- [iOS MITM Certificate Lifecycle Design](docs/architecture/ios-mitm-certificate-lifecycle-design.md)
- [iOS Entitlement Provisioning Source Contract](docs/architecture/ios-entitlement-provisioning-source-contract.md)
- [iOS App Review Privacy Release Readiness Design](docs/architecture/ios-app-review-privacy-release-readiness-design.md)
- [iOS Privacy Manifest Source Contract](docs/architecture/ios-privacy-manifest-source-contract.md)
- [iOS App Review Manual Confirmation Source Contract](docs/architecture/ios-app-review-manual-confirmation-source-contract.md)
- [iOS TestFlight App Store Connect Upload Workflow Source Contract](docs/architecture/ios-testflight-app-store-connect-upload-workflow-source-contract.md)
- [iOS Upload Workflow Activation Validation Contract](docs/architecture/ios-upload-workflow-activation-validation-contract.md)
- [iOS Swift Xcode Source Tree Activation Preflight Contract](docs/architecture/ios-swift-xcode-source-tree-activation-preflight-contract.md)
- [iOS Package.swift Source Ownership Activation Preflight Contract](docs/architecture/ios-package-swift-source-ownership-activation-preflight-contract.md)
- [iOS Package.swift Manifest-Only Activation Validation Contract](docs/architecture/ios-package-swift-manifest-only-activation-validation-contract.md)
- [Linux Artifact Pre-Release Design](docs/architecture/linux-artifact-pre-release-design.md)
- [Linux Platform Adapter Design](docs/architecture/linux-platform-adapter.md)
- [Linux CLI Entrypoint Design](docs/architecture/linux-cli-entrypoint.md)
- [Linux MITM Browser Capture Source Contract](docs/architecture/linux-mitm-browser-capture-source-contract.md)
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
