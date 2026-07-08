# networkcore_AnixOps

`networkcore_AnixOps` 是面向全平台网络内核、MITM 插件兼容和客户端体系的规划与实现仓库。

## 目标

- 构建 Linux、macOS、Windows、iOS 可用的统一网络控制内核。
- 维护三层运行架构：NetworkCore 控制层、执行内核 adapter 层、公有执行内核层；P3 优先接入 `sing-box` 等公有内核，自研私有协议栈暂缓。
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
- [docs/architecture/adr-0002-public-engine-adapter-first.md](docs/architecture/adr-0002-public-engine-adapter-first.md)
- [docs/architecture/sing-box-public-engine-adapter-source-contract.md](docs/architecture/sing-box-public-engine-adapter-source-contract.md)
- [docs/architecture/subscription-url-to-sing-box-run-source-contract.md](docs/architecture/subscription-url-to-sing-box-run-source-contract.md)
- [docs/architecture/mitm-policy-ad-block-plugin-source-contract.md](docs/architecture/mitm-policy-ad-block-plugin-source-contract.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [ROADMAP.md](ROADMAP.md)
- [TODO.md](TODO.md)
- [CHANGELOG.md](CHANGELOG.md)

## 当前状态

P2 Core Kernel Skeleton 已完成，当前阶段进入 P3 Runtime Capabilities。本节后续内容是已完成源码、合同和 release gate 的详细清单；阶段判断以本段和 [ROADMAP.md](ROADMAP.md) 为准。

Linux CLI 二进制发布路径已打通：`v0.1.0-alpha.2` 由 GitHub Actions 构建并发布
`networkcore-linux` Linux tarball、sha256、manifest 和 manifest sha256，release workflow 同时完成同 commit CI gate、
artifact checksum、manifest、GitHub artifact attestation、publish eligibility 和 GitHub Release asset 上传。

当前 P3 运行层策略已固化为公有执行内核 adapter 优先：NetworkCore 维护自己的控制层、配置/订阅/策略/DNS/MITM
意图、平台能力和审计输出；`engine-*` adapter 负责把领域模型转换成具体执行内核配置并管理生命周期；
`sing-box` 等公有执行内核先承担 VLESS、Shadowsocks、Trojan、VMess、Hysteria 等协议数据面。
`engine-native` 继续保留为自研执行内核实验线，但私有协议实现暂缓，直到 adapter 路线暴露明确缺口。

`engine-singbox` 已作为首个 public engine adapter source contract 进入 workspace；`networkcore-linux help`
现在输出命令表，`networkcore-linux install-sing-box`/`networkcore-linux sing-box install` 会从官方 GitHub latest
release 选择当前目标资产，校验 `sha256:` digest，解压缓存 `sing-box` 可执行文件，并在 JSON 中输出
`sing_box_install` 机器字段。该路径是运行时下载缓存，不把第三方 `sing-box` binary 打进 NetworkCore release
artifact。`networkcore-linux run-url <ss://url>` 现在走 `CoreSubscriptionService` 把单条 Shadowsocks URL、
明文链接列表或 base64 链接列表归一化为 `NodeCatalog`，由 `engine-singbox` 渲染本地 `mixed` inbound
配置并以前台 `sing-box run -c <config>` 启动，默认本地代理为 `127.0.0.1:7890`，JSON 输出新增
`sing_box_run` 机器字段。daemon/control socket、持久订阅、节点选择、VLESS/VMess/Trojan/Clash 等格式、
status/events/logs、reload、TUN/DNS mutation 和 MITM 真实流量处理仍是后续工作。

说明：下方历史清单中保留了 placeholder 阶段的字段名称；当前可执行状态以上面段落和 [ROADMAP.md](ROADMAP.md) 为准。

补充说明：`networkcore-linux start` binary 已接入 `NativeProxyEngineService` 与前台 lifecycle host；有效 listener/node 配置可让二进制入口在当前进程内启动 loopback TCP accept loop runtime 并进入前台持有路径。前台 lifecycle 已具备可注入 interruption source、Unix `SIGINT`/`SIGTERM` OS signal source、`cli.linux.start.signal_received`/`cli.linux.start.lifecycle_interrupted` 诊断、130 退出码和 interruption 后 runtime stop/release 诊断聚合合同。`stop` 与后台 `status` 继续保持无 daemon/control socket 边界；`engine-native` 当前仅作为原生 SOCKS skeleton，不承担 VLESS、Shadowsocks、Trojan、VMess、Hysteria 等私有协议兼容目标。

P2 Core Kernel Skeleton 已完成，当前仓库进入 P3 Runtime Capabilities 阶段，已建立协作规范、规划治理入口、架构规格、运行层编排设计、发布策略、iOS 平台风险评估、Linux artifact 发布前设计、Linux platform adapter 设计、Linux CLI entrypoint 设计、Linux CLI runtime wiring 设计、Native engine listener/node 配置设计、Linux native proxy engine start 设计、Linux CLI artifact 安装/卸载/回滚设计、Linux package artifact manifest 设计、Linux artifact license/NOTICE confirmation source contract、Linux package license/NOTICE transition validation contract、release CI success source contract、Linux package release CI gate activation validation contract、release CI gate execution validation contract、release CI gate API implementation plan、Linux package artifact job preflight validation contract、Linux package artifact build command validation contract、Linux package artifact staging file validation contract、Linux package artifact archive creation validation contract、Linux package artifact checksum execution validation contract、Linux package artifact manifest generation validation contract、Linux package artifact manifest checksum validation contract、Linux package workflow artifact bundle upload validation contract、Linux package artifact attestation execution validation contract、Linux package release notes/rollback execution validation contract、Linux package publish eligibility execution validation contract、Linux package runner/toolchain/target contract、Linux package archive staging contract、Linux package checksum/manifest checksum contract、Linux package publish/upload boundary contract、Linux package signing/attestation policy binding contract、Linux package release notes/rollback policy binding contract、Linux package publish eligibility aggregate contract、Rust 首选栈决策、最小 `control-domain` crate、control-domain listener 配置领域类型、最小 `control-runtime` crate、最小 `config-core` crate、config-core listener/node/route TOML 解析、最小 `engine-native` crate、engine-native listener/node/route 图校验、engine-native native runtime handle 源码合同、engine-native loopback TCP listener 绑定/释放、engine-native runtime assembly plan 源码合同、engine-native loopback TCP accept loop 受控关闭源码合同、engine-native service-owned runtime state 与 foreground lifecycle handoff 源码合同、engine-native accepted TCP connection 协议前置关闭诊断合同、engine-native SOCKS5 greeting 版本/认证方法读取诊断合同、engine-native SOCKS5 no-auth 方法选择/unsupported auth 方法拒绝诊断合同、engine-native SOCKS5 认证方法响应写入诊断合同、engine-native SOCKS5 命令头读取/unsupported command 拒绝诊断合同、engine-native SOCKS5 CONNECT 目标地址读取、route/outbound 行为选择、SOCKS outbound CONNECT request frame 生成、SOCKS outbound TCP connection plan、SOCKS outbound TCP connection attempt、SOCKS outbound CONNECT request write、SOCKS outbound CONNECT response read、SOCKS outbound CONNECT response decision、SOCKS outbound CONNECT relay readiness、SOCKS outbound CONNECT data relay plan、SOCKS outbound CONNECT data relay execution、SOCKS outbound CONNECT client success response readiness、SOCKS outbound CONNECT client success response write plan、SOCKS outbound CONNECT client success response write、accept loop client success response 与有限 data relay 接线、未接入拒绝与 CONNECT failure response 写入诊断合同、最小 `platform-linux` crate、最小 `networkcore-linux` CLI crate、MITM gate 初始门禁用例、平台 MITM 不可用拒绝路径、证书状态拒绝矩阵、证书诊断拒绝保留路径、manifest 诊断拒绝路径、manifest 错误拒绝审计边界、manifest 错误优先于权限拒绝路径、manifest 错误拒绝平台诊断保留路径、manifest 错误拒绝证书诊断保留路径、manifest 错误拒绝诊断顺序路径、manifest 非错误诊断聚合路径、manifest 诊断权限拒绝保留路径、权限拒绝诊断顺序路径、插件结果诊断聚合路径、平台诊断聚合路径、平台诊断拒绝保留路径、远程脚本执行拒绝路径、远程脚本诊断拒绝保留路径、远程脚本未知状态拒绝路径、Linux 诊断映射合同测试、Linux 只读平台探测服务、Linux CLI 只读平台探测接线、Linux CLI `prepare-config` 运行层接线、Linux CLI 前台 lifecycle host 源码合同、Linux CLI 前台 interruption source 合同、Linux CLI Unix OS signal source 合同、Linux CLI 前台 interruption runtime stop/release 诊断聚合合同、Linux CLI 命令解析、配置读取、平台拒绝、stop/status 和 JSON 输出合同测试、权限拒绝审计边界、审计事件聚合边界、平台能力状态类型、Rust 依赖安全扫描 CI、Rust build/test summary 门禁、Go/Node/Swift/Apple 条件 summary 门禁、CI 项目类型检测输出、GitHub Step Summary 表格、Linux artifact readiness gate、Linux artifact foreground stop/release release gate、Linux artifact manifest release gate、Linux artifact manifest output summary gate、Linux artifact license/NOTICE pending marker gate、Linux artifact license/NOTICE source contract placeholder summary、Linux package license/NOTICE transition validation placeholder summary、release CI success source contract active summary、Linux package release CI gate activation validation active summary、release CI gate execution validation active summary、release CI gate API implementation active summary、Linux package artifact job preflight validation placeholder summary、Linux package artifact build command validation placeholder summary、Linux package artifact staging file validation placeholder summary、Linux package artifact archive creation validation placeholder summary、Linux package artifact checksum execution validation placeholder summary、Linux package artifact manifest generation validation placeholder summary、Linux package artifact manifest checksum validation placeholder summary、Linux package workflow artifact bundle upload validation placeholder summary、Linux package artifact attestation execution validation placeholder summary、Linux package release notes/rollback execution validation placeholder summary、Linux package publish eligibility execution validation placeholder summary、Linux package platform input contract placeholder summary、Linux package archive staging contract placeholder summary、Linux package checksum/manifest checksum contract placeholder summary、Linux package publish/upload boundary contract placeholder summary、Linux package signing/attestation policy binding contract placeholder summary、Linux package release notes/rollback policy binding contract placeholder summary、Linux package publish eligibility aggregate contract placeholder summary、release source summary、release source policy gate、release artifact checksum contract、release signing/attestation contract 和 release rollback contract。后续实现必须先补齐对应规格或设计说明，并通过 CI/CD 验证。

P3 subscription catalog runtime gate 已在 `control-runtime` 落地，`RuntimeOrchestrator::prepare_runtime_request_with_subscription_catalogs`、`start_runtime_with_subscription_catalogs` 和 `reload_runtime_with_subscription_catalogs` 可基于显式 `SubscriptionService`/`SubscriptionSource` 把 inline `NodeCatalog.nodes` 编排进 `RuntimeConfigRequest.nodes`，用 `runtime.subscription.node_id_duplicate` 拒绝与 `ConfigSnapshot.nodes`、已有 `RuntimeConfigRequest.nodes` 或其他 catalog nodes 重复的 id，并用 `runtime.subscription.rules_deferred` 保持 `NodeCatalog.rules` deferred。`networkcore-linux run-url` 现在直接消费 URL 订阅输入并交给 `sing-box` foreground path；通用 `start` 仍未扫描默认订阅路径，也未暴露持久 subscription catalog 输入；远程/文件订阅、系统 DNS/TUN mutation、daemon/control socket 和非 Linux release artifact 继续 blocked。

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

当前源码接入增量已把 `mitm_anixops` Git submodule 固定到 `v0.41.0-alpha`
(`92285204ff07e4dcc4712af30d0b4c76a0deb4d5`)；`mitm-anixops-sys` 编译 C core
并暴露低层 FFI，`mitm-policy` 提供 safe wrapper、`AnixOpsMitmPluginService` 和
内置 `networkcore.adblock` alpha 去广告插件包。当前插件路径只返回 audit/diagnostics
和 `mitm.policy.http_event.mutation_deferred`，真实 URL/header/body 改写仍等待 mutation model
与 HTTP/TLS 数据面。

## 源码布局

- [apps/ios](apps/ios)：iOS source tree governance placeholder，当前仅包含 README，定义未来 Swift package ownership、Package.swift ownership preflight、Package.swift manifest-only activation validation、source directory guard、`macos-26` source scan hook 和 no `Package.swift`/no Swift source/no Xcode project boundary。
- [apps/linux-cli](apps/linux-cli)：`networkcore-linux` CLI 入口的首批命令解析、`help` 命令表、配置读取边界、只读平台探测接线、`prepare-config` 运行层接线、`start` 原生 engine 前台接线、`install-sing-box` latest public engine 下载接线、`run-url` Shadowsocks URL 到 sing-box foreground local proxy 接线、前台 lifecycle host/interruption source、Unix OS signal source、interruption 后 runtime stop/release 源码合同和诊断输出。
- [crates/config-core](crates/config-core)：统一控制内核的首批纯配置解析、标准化和 subscription parser 服务，当前覆盖 schema/profile、最小 listener/node/route TOML 子集、subscription TOML `nodes`/`routes` 子集、单条 `ss://`、明文 `ss://` 链接列表和 base64 链接列表。
- [crates/control-domain](crates/control-domain)：统一控制内核的首批领域类型与端口 trait。
- [crates/control-runtime](crates/control-runtime)：组合领域端口的首批纯运行层编排用例；P3 subscription catalog runtime gate 已支持显式 inline `SubscriptionSource` 的 `NodeCatalog.nodes` 到 `RuntimeConfigRequest.nodes` handoff、重复 id 拒绝和 rules deferred 诊断，仍不执行远程/文件订阅或平台 mutation。
- [crates/engine-native](crates/engine-native)：原生代理执行内核的首批 adapter 合同、listener/node/route 图校验、native runtime handle 源码合同、loopback TCP listener 绑定/释放、runtime assembly plan、loopback TCP accept loop 受控关闭合同、service-owned runtime state 与 foreground lifecycle handoff 源码合同、accepted TCP connection 协议前置关闭诊断合同、SOCKS5 greeting 版本/认证方法读取诊断合同、SOCKS5 no-auth 方法选择/unsupported auth 方法拒绝诊断合同、SOCKS5 认证方法响应写入诊断合同、SOCKS5 命令头读取/unsupported command 拒绝诊断合同、SOCKS5 CONNECT 目标地址读取、route/outbound 行为选择、SOCKS outbound CONNECT request frame 生成、SOCKS outbound TCP connection plan、SOCKS outbound TCP connection attempt、SOCKS outbound CONNECT request write、SOCKS outbound CONNECT response read、SOCKS outbound CONNECT response decision、SOCKS outbound CONNECT relay readiness、SOCKS outbound CONNECT data relay plan、SOCKS outbound CONNECT data relay execution、SOCKS outbound CONNECT client success response readiness、SOCKS outbound CONNECT client success response write plan、SOCKS outbound CONNECT client success response write、accept loop client success response 与有限 data relay 接线、未接入拒绝与 CONNECT failure response 写入诊断合同、配置拒绝和生命周期诊断。
- [crates/engine-singbox](crates/engine-singbox)：`sing-box` public engine adapter 的首个 source contract，当前覆盖 descriptor identity、官方 GitHub latest release metadata 解析、目标资产选择、`sha256:` digest 校验、`.tar.gz` 中只提取 `sing-box` 可执行文件、缓存路径、Shadowsocks node 到本地 `mixed` inbound JSON 渲染、foreground process runner 和稳定诊断；仍不提供 daemon/control socket、managed status/events/logs 或 reload。
- [crates/mitm-anixops-sys](crates/mitm-anixops-sys)：`mitm_anixops` v0.41.0-alpha C ABI 的 unsafe Rust FFI crate，当前编译 vendored C core 并验证 pinned version。
- [crates/mitm-policy](crates/mitm-policy)：`mitm_anixops` 的 safe wrapper 和 NetworkCore MITM plugin adapter，当前提供内置 `networkcore.adblock` 去广告插件包、manifest/permission gate、MITM decision/URL reject 合同测试和 deferred mutation 诊断；不直接改写真实流量。
- [crates/platform-ios](crates/platform-ios)：iOS 平台能力 adapter 的首批纯 Rust source contract 实现，当前提供静态 snapshot 映射、Network Extension/VPN/embedded runtime/MITM certificate/shared storage probe、稳定 `platform.ios.*` 诊断 code 和合同测试，不包含 Swift/Xcode/Network Extension target 或签名配置。
- [crates/platform-linux](crates/platform-linux)：Linux 平台能力 adapter 的首批只读诊断映射、测试替身和 host probe 服务。
