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
- [docs/architecture/mitm-anixops-adapter.md](docs/architecture/mitm-anixops-adapter.md)
- [docs/architecture/control-runtime-orchestration.md](docs/architecture/control-runtime-orchestration.md)
- [docs/architecture/subscription-catalog-runtime-orchestration.md](docs/architecture/subscription-catalog-runtime-orchestration.md)
- [docs/architecture/ios-platform-risk-assessment.md](docs/architecture/ios-platform-risk-assessment.md)
- [docs/architecture/ios-network-extension-design.md](docs/architecture/ios-network-extension-design.md)
- [docs/architecture/ios-platform-adapter-source-contract.md](docs/architecture/ios-platform-adapter-source-contract.md)
- [docs/architecture/ios-swift-network-extension-bridge-design.md](docs/architecture/ios-swift-network-extension-bridge-design.md)
- [docs/architecture/ios-swift-xcode-bridge-source-contract.md](docs/architecture/ios-swift-xcode-bridge-source-contract.md)
- [docs/architecture/ios-embedded-runtime-ffi-boundary-design.md](docs/architecture/ios-embedded-runtime-ffi-boundary-design.md)
- [docs/architecture/ios-mitm-certificate-lifecycle-design.md](docs/architecture/ios-mitm-certificate-lifecycle-design.md)
- [docs/architecture/ios-entitlement-provisioning-source-contract.md](docs/architecture/ios-entitlement-provisioning-source-contract.md)
- [docs/architecture/ios-app-review-privacy-release-readiness-design.md](docs/architecture/ios-app-review-privacy-release-readiness-design.md)
- [docs/architecture/ios-privacy-manifest-source-contract.md](docs/architecture/ios-privacy-manifest-source-contract.md)
- [docs/architecture/ios-app-review-manual-confirmation-source-contract.md](docs/architecture/ios-app-review-manual-confirmation-source-contract.md)
- [docs/architecture/ios-testflight-app-store-connect-upload-workflow-source-contract.md](docs/architecture/ios-testflight-app-store-connect-upload-workflow-source-contract.md)
- [docs/architecture/ios-upload-workflow-activation-validation-contract.md](docs/architecture/ios-upload-workflow-activation-validation-contract.md)
- [docs/architecture/ios-swift-xcode-source-tree-activation-preflight-contract.md](docs/architecture/ios-swift-xcode-source-tree-activation-preflight-contract.md)
- [docs/architecture/ios-package-swift-source-ownership-activation-preflight-contract.md](docs/architecture/ios-package-swift-source-ownership-activation-preflight-contract.md)
- [docs/architecture/ios-package-swift-manifest-only-activation-validation-contract.md](docs/architecture/ios-package-swift-manifest-only-activation-validation-contract.md)
- [docs/architecture/linux-artifact-pre-release-design.md](docs/architecture/linux-artifact-pre-release-design.md)
- [docs/architecture/linux-platform-adapter.md](docs/architecture/linux-platform-adapter.md)
- [docs/architecture/linux-cli-entrypoint.md](docs/architecture/linux-cli-entrypoint.md)
- [docs/architecture/linux-cli-runtime-wiring.md](docs/architecture/linux-cli-runtime-wiring.md)
- [docs/architecture/native-engine-listener-node-config.md](docs/architecture/native-engine-listener-node-config.md)
- [docs/architecture/linux-native-proxy-engine-start.md](docs/architecture/linux-native-proxy-engine-start.md)
- [docs/architecture/linux-cli-artifact-installation-rollback.md](docs/architecture/linux-cli-artifact-installation-rollback.md)
- [docs/architecture/linux-package-artifact-manifest.md](docs/architecture/linux-package-artifact-manifest.md)
- [docs/architecture/linux-artifact-license-notice-confirmation.md](docs/architecture/linux-artifact-license-notice-confirmation.md)
- [docs/architecture/linux-package-license-notice-transition-validation-contract.md](docs/architecture/linux-package-license-notice-transition-validation-contract.md)
- [docs/architecture/release-ci-success-source-contract.md](docs/architecture/release-ci-success-source-contract.md)
- [docs/architecture/linux-package-release-ci-gate-activation-validation-contract.md](docs/architecture/linux-package-release-ci-gate-activation-validation-contract.md)
- [docs/architecture/release-ci-gate-execution-validation-contract.md](docs/architecture/release-ci-gate-execution-validation-contract.md)
- [docs/architecture/release-ci-gate-api-implementation-plan.md](docs/architecture/release-ci-gate-api-implementation-plan.md)
- [docs/architecture/linux-package-artifact-job-preflight-validation-contract.md](docs/architecture/linux-package-artifact-job-preflight-validation-contract.md)
- [docs/architecture/linux-package-artifact-build-command-validation-contract.md](docs/architecture/linux-package-artifact-build-command-validation-contract.md)
- [docs/architecture/linux-package-artifact-staging-file-validation-contract.md](docs/architecture/linux-package-artifact-staging-file-validation-contract.md)
- [docs/architecture/linux-package-artifact-archive-creation-validation-contract.md](docs/architecture/linux-package-artifact-archive-creation-validation-contract.md)
- [docs/architecture/linux-package-artifact-checksum-execution-validation-contract.md](docs/architecture/linux-package-artifact-checksum-execution-validation-contract.md)
- [docs/architecture/linux-package-artifact-manifest-generation-validation-contract.md](docs/architecture/linux-package-artifact-manifest-generation-validation-contract.md)
- [docs/architecture/linux-package-artifact-manifest-checksum-validation-contract.md](docs/architecture/linux-package-artifact-manifest-checksum-validation-contract.md)
- [docs/architecture/linux-package-workflow-artifact-bundle-upload-validation-contract.md](docs/architecture/linux-package-workflow-artifact-bundle-upload-validation-contract.md)
- [docs/architecture/linux-package-artifact-attestation-execution-validation-contract.md](docs/architecture/linux-package-artifact-attestation-execution-validation-contract.md)
- [docs/architecture/linux-package-release-notes-rollback-execution-validation-contract.md](docs/architecture/linux-package-release-notes-rollback-execution-validation-contract.md)
- [docs/architecture/linux-package-runner-toolchain-target-contract.md](docs/architecture/linux-package-runner-toolchain-target-contract.md)
- [docs/architecture/linux-package-archive-staging-contract.md](docs/architecture/linux-package-archive-staging-contract.md)
- [docs/architecture/linux-package-checksum-manifest-contract.md](docs/architecture/linux-package-checksum-manifest-contract.md)
- [docs/architecture/linux-package-publish-upload-boundary-contract.md](docs/architecture/linux-package-publish-upload-boundary-contract.md)
- [docs/architecture/linux-package-signing-attestation-policy-binding-contract.md](docs/architecture/linux-package-signing-attestation-policy-binding-contract.md)
- [docs/architecture/linux-package-release-notes-rollback-policy-binding-contract.md](docs/architecture/linux-package-release-notes-rollback-policy-binding-contract.md)
- [docs/architecture/linux-package-publish-eligibility-aggregate-contract.md](docs/architecture/linux-package-publish-eligibility-aggregate-contract.md)
- [docs/architecture/linux-package-publish-eligibility-execution-validation-contract.md](docs/architecture/linux-package-publish-eligibility-execution-validation-contract.md)
- [docs/architecture/adr-0001-initial-core-stack.md](docs/architecture/adr-0001-initial-core-stack.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [ROADMAP.md](ROADMAP.md)
- [TODO.md](TODO.md)
- [CHANGELOG.md](CHANGELOG.md)

## 当前状态

P2 Core Kernel Skeleton 已完成，当前阶段进入 P3 Runtime Capabilities。本节后续内容是已完成源码、合同和 release gate 的详细清单；阶段判断以本段和 [ROADMAP.md](ROADMAP.md) 为准。

补充说明：`networkcore-linux start` binary 已接入 `NativeProxyEngineService` 与前台 lifecycle host；有效 listener/node 配置可让二进制入口在当前进程内启动 loopback TCP accept loop runtime 并进入前台持有路径。前台 lifecycle 已具备可注入 interruption source、Unix `SIGINT`/`SIGTERM` OS signal source、`cli.linux.start.signal_received`/`cli.linux.start.lifecycle_interrupted` 诊断、130 退出码和 interruption 后 runtime stop/release 诊断聚合合同；release readiness gate 已静态检查该 foreground stop/release 源码和合同测试，并纳入 Linux package artifact manifest 设计、license/NOTICE confirmation source contract、license/NOTICE transition validation contract、release CI gate activation validation contract、release CI gate execution validation contract、release CI gate API implementation plan、artifact job preflight validation contract、artifact build command validation contract、artifact staging file validation contract、artifact archive creation validation contract、artifact checksum execution validation contract、artifact manifest generation validation contract、artifact manifest checksum validation contract、workflow artifact bundle upload validation contract、artifact attestation execution validation contract、release notes/rollback execution validation contract 与 publish eligibility execution validation contract 检查。release placeholder 和 release summary 已输出 Linux artifact manifest output contract 字段清单、license/NOTICE source contract pending 状态、license/NOTICE transition validation blocked 状态、release CI success source contract 字段清单、release CI gate activation active 状态、release CI gate execution active 状态、release CI gate API implementation active 状态、`package-linux` artifact job preflight blocked 状态、artifact build command blocked 状态、artifact staging file blocked 状态、artifact archive creation blocked 状态、artifact checksum execution blocked 状态、artifact manifest generation blocked 状态、artifact manifest checksum blocked 状态、workflow artifact bundle upload blocked 状态、artifact attestation execution blocked 状态、release notes/rollback execution blocked 状态、publish eligibility execution blocked 状态、runner/toolchain/target 输入合同字段、archive staging/文件来源/顶层目录组装合同字段、checksum/manifest checksum 文件命名、sha256 计算顺序、manifest 交叉校验、workflow artifact retention、publish download source、release asset set、禁止覆盖策略、Linux signing policy、attestation/provenance policy、release notes/rollback policy、withdrawal/replacement policy、publish eligibility aggregate status 和未启用 blocked 字段；但 `stop` 与后台 `status` 继续保持无 daemon/control socket 边界，Linux artifact 发布仍受 `package-linux`、license/NOTICE pending marker、artifact job preflight placeholder、artifact build command placeholder、artifact staging file placeholder、artifact archive creation placeholder、artifact checksum execution placeholder、artifact manifest generation placeholder、artifact manifest checksum placeholder、workflow artifact bundle upload placeholder、artifact attestation execution placeholder、release notes/rollback execution placeholder、publish eligibility execution placeholder 和综合发布资格门禁阻止。

P2 Core Kernel Skeleton 已完成，当前仓库进入 P3 Runtime Capabilities 阶段，已建立协作规范、规划治理入口、架构规格、运行层编排设计、发布策略、iOS 平台风险评估、Linux artifact 发布前设计、Linux platform adapter 设计、Linux CLI entrypoint 设计、Linux CLI runtime wiring 设计、Native engine listener/node 配置设计、Linux native proxy engine start 设计、Linux CLI artifact 安装/卸载/回滚设计、Linux package artifact manifest 设计、Linux artifact license/NOTICE confirmation source contract、Linux package license/NOTICE transition validation contract、release CI success source contract、Linux package release CI gate activation validation contract、release CI gate execution validation contract、release CI gate API implementation plan、Linux package artifact job preflight validation contract、Linux package artifact build command validation contract、Linux package artifact staging file validation contract、Linux package artifact archive creation validation contract、Linux package artifact checksum execution validation contract、Linux package artifact manifest generation validation contract、Linux package artifact manifest checksum validation contract、Linux package workflow artifact bundle upload validation contract、Linux package artifact attestation execution validation contract、Linux package release notes/rollback execution validation contract、Linux package publish eligibility execution validation contract、Linux package runner/toolchain/target contract、Linux package archive staging contract、Linux package checksum/manifest checksum contract、Linux package publish/upload boundary contract、Linux package signing/attestation policy binding contract、Linux package release notes/rollback policy binding contract、Linux package publish eligibility aggregate contract、Rust 首选栈决策、最小 `control-domain` crate、control-domain listener 配置领域类型、最小 `control-runtime` crate、最小 `config-core` crate、config-core listener/node/route TOML 解析、最小 `engine-native` crate、engine-native listener/node/route 图校验、engine-native native runtime handle 源码合同、engine-native loopback TCP listener 绑定/释放、engine-native runtime assembly plan 源码合同、engine-native loopback TCP accept loop 受控关闭源码合同、engine-native service-owned runtime state 与 foreground lifecycle handoff 源码合同、engine-native accepted TCP connection 协议前置关闭诊断合同、engine-native SOCKS5 greeting 版本/认证方法读取诊断合同、engine-native SOCKS5 no-auth 方法选择/unsupported auth 方法拒绝诊断合同、engine-native SOCKS5 认证方法响应写入诊断合同、engine-native SOCKS5 命令头读取/unsupported command 拒绝诊断合同、engine-native SOCKS5 CONNECT 目标地址读取、route/outbound 行为选择、SOCKS outbound CONNECT request frame 生成、SOCKS outbound TCP connection plan、SOCKS outbound TCP connection attempt、SOCKS outbound CONNECT request write、SOCKS outbound CONNECT response read、SOCKS outbound CONNECT response decision、SOCKS outbound CONNECT relay readiness、SOCKS outbound CONNECT data relay plan、SOCKS outbound CONNECT data relay execution、SOCKS outbound CONNECT client success response readiness、SOCKS outbound CONNECT client success response write plan、SOCKS outbound CONNECT client success response write、accept loop client success response 与有限 data relay 接线、未接入拒绝与 CONNECT failure response 写入诊断合同、最小 `platform-linux` crate、最小 `networkcore-linux` CLI crate、MITM gate 初始门禁用例、平台 MITM 不可用拒绝路径、证书状态拒绝矩阵、证书诊断拒绝保留路径、manifest 诊断拒绝路径、manifest 错误拒绝审计边界、manifest 错误优先于权限拒绝路径、manifest 错误拒绝平台诊断保留路径、manifest 错误拒绝证书诊断保留路径、manifest 错误拒绝诊断顺序路径、manifest 非错误诊断聚合路径、manifest 诊断权限拒绝保留路径、权限拒绝诊断顺序路径、插件结果诊断聚合路径、平台诊断聚合路径、平台诊断拒绝保留路径、远程脚本执行拒绝路径、远程脚本诊断拒绝保留路径、远程脚本未知状态拒绝路径、Linux 诊断映射合同测试、Linux 只读平台探测服务、Linux CLI 只读平台探测接线、Linux CLI `prepare-config` 运行层接线、Linux CLI 前台 lifecycle host 源码合同、Linux CLI 前台 interruption source 合同、Linux CLI Unix OS signal source 合同、Linux CLI 前台 interruption runtime stop/release 诊断聚合合同、Linux CLI 命令解析、配置读取、平台拒绝、stop/status 和 JSON 输出合同测试、权限拒绝审计边界、审计事件聚合边界、平台能力状态类型、Rust 依赖安全扫描 CI、Rust build/test summary 门禁、Go/Node/Swift/Apple 条件 summary 门禁、CI 项目类型检测输出、GitHub Step Summary 表格、Linux artifact readiness gate、Linux artifact foreground stop/release release gate、Linux artifact manifest release gate、Linux artifact manifest output summary gate、Linux artifact license/NOTICE pending marker gate、Linux artifact license/NOTICE source contract placeholder summary、Linux package license/NOTICE transition validation placeholder summary、release CI success source contract active summary、Linux package release CI gate activation validation active summary、release CI gate execution validation active summary、release CI gate API implementation active summary、Linux package artifact job preflight validation placeholder summary、Linux package artifact build command validation placeholder summary、Linux package artifact staging file validation placeholder summary、Linux package artifact archive creation validation placeholder summary、Linux package artifact checksum execution validation placeholder summary、Linux package artifact manifest generation validation placeholder summary、Linux package artifact manifest checksum validation placeholder summary、Linux package workflow artifact bundle upload validation placeholder summary、Linux package artifact attestation execution validation placeholder summary、Linux package release notes/rollback execution validation placeholder summary、Linux package publish eligibility execution validation placeholder summary、Linux package platform input contract placeholder summary、Linux package archive staging contract placeholder summary、Linux package checksum/manifest checksum contract placeholder summary、Linux package publish/upload boundary contract placeholder summary、Linux package signing/attestation policy binding contract placeholder summary、Linux package release notes/rollback policy binding contract placeholder summary、Linux package publish eligibility aggregate contract placeholder summary、release source summary、release source policy gate、release artifact checksum contract、release signing/attestation contract 和 release rollback contract。后续实现必须先补齐对应规格或设计说明，并通过 CI/CD 验证。

P3 subscription catalog runtime gate 已在 `control-runtime` 落地，`RuntimeOrchestrator::prepare_runtime_request_with_subscription_catalogs`、`start_runtime_with_subscription_catalogs` 和 `reload_runtime_with_subscription_catalogs` 可基于显式 `SubscriptionService`/`SubscriptionSource` 把 inline `NodeCatalog.nodes` 编排进 `RuntimeConfigRequest.nodes`，用 `runtime.subscription.node_id_duplicate` 拒绝与 `ConfigSnapshot.nodes`、已有 `RuntimeConfigRequest.nodes` 或其他 catalog nodes 重复的 id，并用 `runtime.subscription.rules_deferred` 保持 `NodeCatalog.rules` deferred。`networkcore-linux start` 仍未扫描默认订阅路径，也未暴露 subscription catalog 输入；远程/文件订阅、系统 DNS/TUN mutation、daemon/control socket 和 release artifact 继续 blocked。

iOS Network Extension design、iOS platform adapter source contract、首个纯 Rust `platform-ios` 映射骨架和
iOS Swift/Network Extension bridge design、iOS Swift/Xcode bridge source contract、iOS embedded runtime
FFI boundary design、iOS MITM certificate lifecycle design、iOS entitlement/provisioning source contract 和
iOS App Review/privacy release readiness design、iOS Privacy Manifest source contract 和 iOS App Review manual
confirmation source contract、iOS TestFlight/App Store Connect upload workflow source contract、iOS upload
workflow activation validation contract、iOS Swift/Xcode source tree activation preflight contract 和 iOS Package.swift
source ownership activation preflight contract、iOS Package.swift manifest-only activation validation contract 已补充；release workflow
现在只有 `ios-upload-readiness` blocked placeholder，并在 release placeholder/summary 中输出 source tree preflight、
Package.swift ownership preflight、Package.swift manifest-only activation、`apps/ios` README placeholder、`Package.swift`、
target ownership、manifest-only source scan、target list verification、source directory guard、Xcode project、Network Extension
target、`PrivacyInfo.xcprivacy`、entitlement/provisioning、Swift package validation hook、upload enabled marker、marker、
protected environment、manual approval、App Store Connect API secret status、archive/export、upload、submission 和 release asset
blocked 字段；
`.entitlements`、`PrivacyInfo.xcprivacy`、ExportOptions.plist、`.ipa`、`.xcarchive`、`.xcresult`、dSYM bundle、
真实 `apps/ios` Swift source tree、`Package.swift`、Swift source、Xcode project、Network Extension target、
Provisioning Profile、Rust FFI crate、证书安装源码、App Privacy 问卷、
隐私政策 URL、App Review Notes、demo account、review attachment、签名、App Store Connect API key、
TestFlight/App Store upload、App Review submission 和 iOS release asset 均未启用，
当前 `apps/ios/README.md` 只是 source tree governance placeholder，
后续 Apple SDK bridge、embedded runtime、certificate lifecycle、entitlement/provisioning、Privacy Manifest 源码和
App Review manual confirmation marker、真实 Swift/Xcode source tree 和 upload workflow enabled marker 必须按 source
contract、source tree preflight contract、Package.swift ownership preflight contract 与 activation validation contract 通过
GitHub Actions 验证。`ios-package-swift-manifest-only-*` 当前只记录 blocked placeholder；真实 `Package.swift` 仍未进入仓库。

## MITM adapter 接入边界

`mitm_anixops` 接入已先以 adapter 设计形式记录：该库可作为 MITM 策略/plugin 兼容 C ABI core，但完整全平台 MITM 仍需要 NetworkCore 后续补齐领域 mutation model、HTTP/TLS 数据面和各平台证书/运行时 adapter。

当前首个源码接入增量已新增 `mitm-anixops-sys` crate，通过 Git submodule 固定 `mitm_anixops` 并在 Rust CI 中编译 C core，测试 `anixops_version()` 以证明 NetworkCore 已链接该 C ABI。

## 源码布局

- [apps/ios](apps/ios)：iOS source tree governance placeholder，当前仅包含 README，定义未来 Swift package ownership、Package.swift ownership preflight、Package.swift manifest-only activation validation、source directory guard、`macos-26` source scan hook 和 no `Package.swift`/no Swift source/no Xcode project boundary。
- [apps/linux-cli](apps/linux-cli)：`networkcore-linux` CLI 入口的首批命令解析、配置读取边界、只读平台探测接线、`prepare-config` 运行层接线、`start` 原生 engine 前台接线、前台 lifecycle host/interruption source、Unix OS signal source、interruption 后 runtime stop/release 源码合同和诊断输出。
- [crates/config-core](crates/config-core)：统一控制内核的首批纯配置解析、标准化和 inline subscription parser 服务，当前覆盖 schema/profile、最小 listener/node/route TOML 子集，以及最小 subscription TOML `nodes`/`routes` 子集。
- [crates/control-domain](crates/control-domain)：统一控制内核的首批领域类型与端口 trait。
- [crates/control-runtime](crates/control-runtime)：组合领域端口的首批纯运行层编排用例；P3 subscription catalog runtime gate 已支持显式 inline `SubscriptionSource` 的 `NodeCatalog.nodes` 到 `RuntimeConfigRequest.nodes` handoff、重复 id 拒绝和 rules deferred 诊断，仍不执行远程/文件订阅或平台 mutation。
- [crates/engine-native](crates/engine-native)：原生代理执行内核的首批 adapter 合同、listener/node/route 图校验、native runtime handle 源码合同、loopback TCP listener 绑定/释放、runtime assembly plan、loopback TCP accept loop 受控关闭合同、service-owned runtime state 与 foreground lifecycle handoff 源码合同、accepted TCP connection 协议前置关闭诊断合同、SOCKS5 greeting 版本/认证方法读取诊断合同、SOCKS5 no-auth 方法选择/unsupported auth 方法拒绝诊断合同、SOCKS5 认证方法响应写入诊断合同、SOCKS5 命令头读取/unsupported command 拒绝诊断合同、SOCKS5 CONNECT 目标地址读取、route/outbound 行为选择、SOCKS outbound CONNECT request frame 生成、SOCKS outbound TCP connection plan、SOCKS outbound TCP connection attempt、SOCKS outbound CONNECT request write、SOCKS outbound CONNECT response read、SOCKS outbound CONNECT response decision、SOCKS outbound CONNECT relay readiness、SOCKS outbound CONNECT data relay plan、SOCKS outbound CONNECT data relay execution、SOCKS outbound CONNECT client success response readiness、SOCKS outbound CONNECT client success response write plan、SOCKS outbound CONNECT client success response write、accept loop client success response 与有限 data relay 接线、未接入拒绝与 CONNECT failure response 写入诊断合同、配置拒绝和生命周期诊断。
- [crates/mitm-anixops-sys](crates/mitm-anixops-sys)：`mitm_anixops` C ABI 的首个 unsafe Rust FFI crate，当前编译 vendored C core 并验证 pinned version。
- [crates/platform-ios](crates/platform-ios)：iOS 平台能力 adapter 的首批纯 Rust source contract 实现，当前提供静态 snapshot 映射、Network Extension/VPN/embedded runtime/MITM certificate/shared storage probe、稳定 `platform.ios.*` 诊断 code 和合同测试，不包含 Swift/Xcode/Network Extension target 或签名配置。
- [crates/platform-linux](crates/platform-linux)：Linux 平台能力 adapter 的首批只读诊断映射、测试替身和 host probe 服务。
