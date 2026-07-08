# TODO

本文件记录当前最小增量级待办。长期方向见 [ROADMAP.md](ROADMAP.md)，所有验证规则见 [docs/ci-cd-policy.md](docs/ci-cd-policy.md)。

## 当前

当前阶段是 P4 Client And Platform Integration。
P3 runtime baseline 已完成并保留后续 runtime backlog。
Linux artifact release-state consistency 已固定为 `linux-artifact-release-state=confirmed-release-path`；
license/NOTICE 已 confirmed；当前最新 GitHub Release 是 `v0.1.0-alpha.5`，后续 tag release 仍必须经过
同 commit CI、checksum、manifest、attestation、release notes、rollback 和 publish eligibility gates。
MITM CLI command gate 已进入状态/诊断/证书计划/浏览器捕获计划和 browser-capture blocked report 部分激活：
`mitm-cli-command-gate-status=partial-active`；browser hijack 仍为 deferred，浏览器捕获 mutation 仍 blocked。
Linux MITM browser capture source contract 已激活，当前源码已有 `mitm browser-capture plan/apply/rollback/verify`
blocked report 命令面和 `browser_capture` 机器字段，但只记录授权、快照、apply/rollback/verify 和 CI 边界，
不代表当前已有 live browser capture；这些 MITM CLI 增量晚于 `v0.1.0-alpha.5`，进入下载二进制需要下一次
GitHub Actions tag release。

- [ ] 扩展订阅格式和 managed lifecycle：在 `run-url` foreground 闭环基础上，继续接入 VLESS/VMess/Trojan、Clash YAML、sing-box JSON、Surge/Loon/Quantumult X 高频子集、节点选择、持久订阅、managed status/events/logs/reload/rollback，并为后续真实 MITM 数据面接入补充独立 source contract。
- [ ] 补齐用户可用 MITM 后续门禁：`MITM_CLI_COMMAND_GATE` 已有 `networkcore-linux mitm status/diagnostics/certificate-plan/browser-plan`、`networkcore-linux mitm browser-capture plan/apply/rollback/verify`、`mitm_status` JSON 字段、`certificate_plan`、`browser_plan` 和 `browser_capture` 机器字段，但仍需扩展到真正可执行的用户操作；`MITM_CERTIFICATE_LIFECYCLE_GATE` 当前为 plan-only，后续必须实现 CA 生成、安装、信任检测、撤销和回滚；`MITM_BROWSER_CAPTURE_GATE` 当前为 plan-only/mutation-blocked，且已有 [Linux MITM Browser Capture Source Contract](docs/architecture/linux-mitm-browser-capture-source-contract.md) 固定 `BrowserCaptureAuthorization`、`BrowserCaptureRollbackSnapshot`、apply/rollback/verify、授权和 snapshot 边界，后续必须实现显式授权的浏览器/系统代理配置、PAC 或其他捕获策略、验证和回滚；`MITM_HTTP_TLS_DATA_PLANE_GATE` 在 HTTP/TLS 数据面中应用 `mitm-policy` URL/header/body/script rewrite plan。当前 `mitm-policy` 和 Linux CLI 只做策略状态、证书计划、浏览器捕获计划、browser-capture blocked report、deferred mutation 诊断和 browser hijack deferred 输出，不能直接拦截或改写真实流量。

说明：已完成条目保留当时的阶段状态；当前 runtime 方向以 [ROADMAP.md](ROADMAP.md) 和 [docs/architecture/adr-0002-public-engine-adapter-first.md](docs/architecture/adr-0002-public-engine-adapter-first.md) 为准。

## 已完成

- [x] 扩展 Linux MITM browser capture blocked report 命令面：`networkcore-linux mitm browser-capture plan/apply/rollback/verify` 已输出 `browser_capture` 机器字段；`apply --confirm` 只记录 `BrowserCaptureAuthorization` 并返回 `cli.linux.mitm.browser_capture.apply.blocked`，`rollback --snapshot <path>` 只保留 `BrowserCaptureRollbackSnapshot` 路径并返回 rollback blocked，`verify` 返回 live capture probe blocked；浏览器/系统代理、PAC、TUN、DNS、firewall、CA 和 HTTP/TLS 数据面仍不执行 mutation。验证仍只通过 GitHub Actions。
- [x] 补充 Linux MITM browser capture source contract：新增 `docs/architecture/linux-mitm-browser-capture-source-contract.md`，固定 `mitm-browser-capture-source-contract-status=active`、`MITM_BROWSER_CAPTURE_GATE=plan-only/mutation-blocked`、`BrowserCaptureAuthorization`、`BrowserCaptureRollbackSnapshot`、apply/rollback/verify 命令面、显式授权、snapshot、rollback、诊断 code 和 CI governance；当前仍不执行 browser/system proxy、PAC、TUN、DNS、firewall 或 CA mutation。验证仍只通过 GitHub Actions。
- [x] 扩展 `MITM_CLI_COMMAND_GATE` 的浏览器捕获计划入口：`networkcore-linux mitm browser-plan` 已输出 `mitm_status.browser_plan` 机器字段、默认显式代理计划 `127.0.0.1:7890`、计划步骤、blocked operations、`cli.linux.mitm.browser_plan.ready` 和 `cli.linux.mitm.browser_capture_mutation.blocked` 诊断；浏览器/系统代理、PAC、TUN、DNS、firewall 写入和 live browser capture 验证仍不执行 mutation，HTTP/TLS data plane 和 browser hijack 仍 blocked/deferred。验证仍只通过 GitHub Actions。
- [x] 扩展 `MITM_CLI_COMMAND_GATE` 的证书计划入口：`networkcore-linux mitm certificate-plan` 已输出 `mitm_status.certificate_plan` 机器字段、当前证书状态、计划步骤、blocked operations、`cli.linux.mitm.certificate_plan.ready` 和 `cli.linux.mitm.certificate_mutation.blocked` 诊断；CA 生成/安装/信任/撤销/回滚仍不执行 mutation，HTTP/TLS data plane 和 browser hijack 仍 blocked/deferred。验证仍只通过 GitHub Actions。
- [x] 激活 `MITM_CLI_COMMAND_GATE` 的 status/diagnostics 最小入口：`networkcore-linux mitm status`、`networkcore-linux mitm diagnostics`、`mitm_status` JSON 机器字段、内置 `networkcore.adblock` policy load 诊断和 `mitm-cli-command-gate-status=partial-active` marker 已进入 Linux CLI；该条目已由后续 `certificate-plan` 增量扩展，真实 HTTP/TLS data plane 和 browser hijack 仍 blocked/deferred。验证仍只通过 GitHub Actions。
- [x] 固化 Linux artifact release-state consistency gate：README、ROADMAP、TODO、CHANGELOG、Release Strategy、Linux license/NOTICE confirmation contract、transition validation contract、pre-release design、manual intervention marker、CI governance 和 release readiness 现在统一使用 `linux-artifact-release-state=confirmed-release-path`；license/NOTICE confirmed 只解除人工门禁，Linux tag release 仍必须通过同 commit CI、checksum、manifest、attestation、release notes、rollback 和 publish eligibility gates。
- [x] 固化第三方插件接入流程：新增 Third-Party Plugin Onboarding Process，要求后续 plugin、plugin parser、script runtime 或兼容核心先建立 source contract、固定 upstream source、确认 license/NOTICE、定义 permission/safe wrapper/CI governance 和 upgrade procedure；CI governance 已纳入该流程和现有 `networkcore.adblock` source contract anchor。验证仍只通过 GitHub Actions。
- [x] 接入 `mitm_anixops v0.45.10-alpha` 并新增 `mitm-policy`：子模块固定到 `a3ee0fca6376ddccc333bdfe06ac5b5e75ed23e0`，`mitm-anixops-sys` 扩展低层 FFI，`mitm-policy` 提供 safe wrapper、`AnixOpsMitmPluginService`、manifest/permission gate、内置 `networkcore.adblock` alpha 去广告插件包、rewrite plan/header/body chain/script/JQ guard wrapper 合同和 deferred mutation 诊断；真实 HTTP/TLS 改写仍等待 mutation model 与数据面。验证仍只通过 GitHub Actions。
- [x] 新增 `run-url` Shadowsocks foreground 闭环：`CoreSubscriptionService` 支持单条 `ss://`、明文 `ss://` 链接列表、base64 链接列表和既有 subscription TOML，`NodeDescriptor.metadata` 承载 Shadowsocks method/password，`engine-singbox` 渲染本地 `mixed` inbound + Shadowsocks outbound JSON，并由 `networkcore-linux run-url <ss://url>` 安装/复用 latest `sing-box`、写入 runtime config、前台执行 `sing-box run -c <config>`，JSON 输出 `sing_box_run`。
- [x] 新增 `engine-singbox` public engine adapter source contract 和 CLI 下载入口：`networkcore-linux help` 输出命令表，`install-sing-box`/`sing-box install` 从官方 GitHub latest release 动态选择当前目标资产、校验 `sha256:` digest、解压缓存 `sing-box` 可执行文件，并输出 `sing_box_install` JSON 字段；仍不把 `sing-box` binary 打进 NetworkCore release artifact，managed daemon/status/logs/reload 继续留给后续 lifecycle 增量。
- [x] 固化公有执行内核 adapter 优先策略和三层维护框架：新增 ADR 0002，明确 NetworkCore 控制层、执行内核 adapter 层、公有执行内核层的职责，优先 `sing-box`，暂缓 `engine-native` 私有协议实现，后续只有在 adapter 路线暴露明确缺口时再扩展自研协议。
- [x] Linux CLI 二进制发布路径从 `v0.1.0-alpha.2` 打通，当前最新 GitHub Release 为 `v0.1.0-alpha.5`：release workflow 已在 GitHub Actions 中完成 `package-linux`、checksum、manifest、attestation、publish eligibility 和 tag release asset 上传，GitHub Release 已包含 Linux CLI tarball、sha256、manifest 和 manifest sha256；未运行本地构建、测试或打包。
- [x] 补充 iOS `Package.swift` manifest-only activation validation contract，定义未来独立提交引入 `apps/ios/Package.swift` 时的 manifest-only source scan、target list verification、no Swift source before source gate、Xcode project 继续 blocked、upload workflow enabled marker 继续 blocked、`ios-package-swift-manifest-only-*` release blocked 输出和 `macos-26` GitHub Actions 验证入口；本轮仍不得引入真实 `Package.swift`、Swift source、Swift/Xcode project、`PrivacyInfo.xcprivacy`、Network Extension target、ExportOptions.plist、`.ipa`、`.xcarchive`、`.xcresult`、dSYM bundle、真实签名、TestFlight 上传或 iOS release asset。Linux artifact 继续等待 license/NOTICE confirmed marker，期间不得定义 `package-linux` 或发布 release asset。
- [x] 实现 P3 subscription catalog runtime gate 源码合同，新增 `RuntimeOrchestrator::prepare_runtime_request_with_subscription_catalogs`、`start_runtime_with_subscription_catalogs` 和 `reload_runtime_with_subscription_catalogs`，基于显式 `SubscriptionService`/`SubscriptionSource` 把 inline `NodeCatalog.nodes` 编排进 `RuntimeConfigRequest.nodes`，用 `runtime.subscription.node_id_duplicate` 拒绝与 `ConfigSnapshot.nodes`、已有 `RuntimeConfigRequest.nodes` 或其他 catalog nodes 重复的 id，并用 `runtime.subscription.rules_deferred` 保持 `NodeCatalog.rules` deferred；`networkcore-linux start` 仍不扫描或消费 subscription catalog。验证仍只通过 GitHub Actions。
- [x] 补充 P3 subscription catalog runtime orchestration design，定义 `CoreSubscriptionService` 产出的 `NodeCatalog` 如何进入 `RuntimeConfigRequest.nodes`、如何与本地 `ConfigSnapshot.nodes` 去重、如何在策略路由和 DNS 接入前保持诊断稳定；CI governance 静态检查该设计的 `NodeCatalog`、`RuntimeConfigRequest.nodes`、`ConfigSnapshot.nodes`、`ProxyEngineConfig.nodes`、重复 id、rules deferred、no remote/file subscription、no DNS/TUN mutation 和 no daemon/control socket anchors。验证仍只通过 GitHub Actions。
- [x] 完成 P2 Core Kernel Skeleton 收口：新增 `CoreSubscriptionService` 最小 inline subscription parser，把最小 subscription TOML `nodes`/`routes` 子集解析为 `SubscriptionDocument` 并归一化为 `NodeCatalog`；补充 `control-domain` subscription port 合同测试、`config-core` subscription parser 合同测试、CI governance 静态检查，并把 ROADMAP/README/TODO/CHANGELOG 更新为 P2 completed。验证仍只通过 GitHub Actions。
- [x] 补充 iOS `Package.swift` source ownership activation preflight contract，定义 `apps/ios/Package.swift` 引入前的 target ownership、source directory guard、no Swift source until package gate、`macos-26` Swift package validation hook、Xcode project 继续 blocked 和 upload workflow enabled marker 继续 blocked；仍不引入真实 `Package.swift`、Swift source、Swift/Xcode project、`PrivacyInfo.xcprivacy`、Network Extension target、ExportOptions.plist、`.ipa`、`.xcarchive`、`.xcresult`、dSYM bundle、真实签名、TestFlight 上传或 iOS release asset。Linux artifact 继续等待 license/NOTICE confirmed marker，期间不得定义 `package-linux` 或发布 release asset。
- [x] 新增 `apps/ios/README.md` source tree governance placeholder，定义未来 Swift package ownership、source directory guard、`macos-26` source scan hook、no `Package.swift`/no Swift source/no Xcode project boundary 和 upload workflow enabled marker 继续 blocked；仍不引入真实 Swift/Xcode project、Swift source、`PrivacyInfo.xcprivacy`、Network Extension target、ExportOptions.plist、`.ipa`、`.xcarchive`、`.xcresult`、dSYM bundle、真实签名、TestFlight 上传或 iOS release asset。Linux artifact 继续等待 license/NOTICE confirmed marker，期间不得定义 `package-linux` 或发布 release asset。
- [x] 补充 iOS Swift/Xcode source tree activation preflight contract，定义真实 `apps/ios` source tree、`Package.swift`/Xcode project 引入前的目录布局、`macos-26` source scan、Network Extension target gate、`PrivacyInfo.xcprivacy` gate、entitlement/provisioning gate、upload workflow enabled marker 前置条件和 release/upload blocked 输出；仍不引入真实 Swift/Xcode project、`PrivacyInfo.xcprivacy`、Network Extension target、ExportOptions.plist、`.ipa`、`.xcarchive`、`.xcresult`、dSYM bundle、真实签名、TestFlight 上传或 iOS release asset。Linux artifact 继续等待 license/NOTICE confirmed marker，期间不得定义 `package-linux` 或发布 release asset。
- [x] 补充 iOS upload workflow activation validation contract，定义 release workflow placeholder summary、`ios-upload-workflow` marker 读取、protected environment/manual approval 检查、App Store Connect API secret present/missing 状态、archive/export/upload/submission blocked 输出和 GitHub Actions 静态门禁；仍不引入 Swift/Xcode project、`PrivacyInfo.xcprivacy`、Network Extension target、ExportOptions.plist、`.ipa`、`.xcarchive`、`.xcresult`、dSYM bundle、真实签名、TestFlight 上传或 iOS release asset。Linux artifact 继续等待 license/NOTICE confirmed marker，期间不得定义 `package-linux` 或发布 release asset。
- [x] 补充 iOS TestFlight/App Store Connect upload workflow source contract，定义 archive/export、App Store Connect API、TestFlight group、manual approval、App Review submission gate、GitHub Actions `macos-26` 验证入口、`docs/manual-intervention.md` marker 和 release/upload 阻断；仍不引入 Swift/Xcode project、`PrivacyInfo.xcprivacy`、Network Extension target、ExportOptions.plist、`.ipa`、`.xcarchive`、`.xcresult`、dSYM bundle、真实签名、TestFlight 上传、App Store 上传、App Review submission 或 iOS release asset。
- [x] 补充 iOS App Review Notes/manual confirmation source contract，定义 App Privacy answers、privacy policy URL、demo account、review attachment、VPN compliance marker、TestFlight group、App Store Connect app record、export compliance、beta app review 和 App Review submission 人工确认的机器可读 marker 与 GitHub Actions 静态门禁；仍不引入 Swift/Xcode project、`PrivacyInfo.xcprivacy`、Network Extension target、真实签名、TestFlight 上传或 iOS release asset。
- [x] 补充 iOS Privacy Manifest source contract，定义后续 `PrivacyInfo.xcprivacy` 文件位置、`NSPrivacyCollectedDataTypes`/`NSPrivacyAccessedAPITypes` 字段、Required Reason API 审查、App Store Connect App Privacy 答案来源和 GitHub Actions `macos-26` 静态验证入口；仍不引入 Swift/Xcode project、`PrivacyInfo.xcprivacy`、Network Extension target、真实签名、TestFlight 上传或 iOS release asset。
- [x] 补充 iOS App Review/privacy release readiness design，定义后续 Privacy Manifest、隐私政策、App Review Notes、VPN 合规材料、TestFlight/App Store Connect 人工确认和 GitHub Actions 静态门禁；仍不引入 Swift/Xcode project、Network Extension target、真实签名、TestFlight 上传或 iOS release asset。
- [x] 补充 iOS entitlement/provisioning source contract，定义后续 `.entitlements`、App ID、Network Extension capability、Provisioning Profile、GitHub Secrets、signing asset redaction 和 GitHub Actions `macos-26` 验证入口；仍不引入 Swift/Xcode project、Network Extension target、真实签名、TestFlight 上传或 iOS release asset。
- [x] 补充 iOS MITM certificate lifecycle design，定义后续 CA 生成、安装提示、用户信任确认、fingerprint 校验、撤销/过期检测、`CertificateTrustState` 映射和 GitHub Actions `macos-26` 验证入口；仍不引入 Swift/Xcode project、Network Extension target、签名、TestFlight 上传或 iOS release asset。
- [x] 补充 iOS embedded runtime FFI boundary design，定义后续 Rust staticlib/XCFramework、C ABI symbol、ABI version negotiation、owned string/buffer、panic/error mapping 和 GitHub Actions `macos-26` 验证入口；仍不引入 Swift/Xcode project、Network Extension target、签名、TestFlight 上传或 iOS release asset。
- [x] 补充 iOS Swift/Xcode bridge source contract，定义后续 Swift package、Network Extension target、FFI/DTO 文件布局、GitHub Actions `macos-26` 验证入口和禁止提交 signing/provisioning secret 的源码验收条件；仍不引入 Swift/Xcode project、Network Extension target、签名、TestFlight 上传或 iOS release asset。
- [x] 补充 iOS Swift/Network Extension bridge design，定义后续 Apple SDK 层如何采集 `NEPacketTunnelProvider`、`NETunnelProviderManager`、App Group、Keychain、embedded runtime 和证书状态事实并传入 `platform-ios` 的去敏 `IosPlatformSnapshot`；CI governance 静态检查该设计，仍不引入 Swift/Xcode project、Network Extension target、签名、TestFlight 上传或 iOS release asset。
- [x] 新增最小 `platform-ios` crate 纯 Rust 映射骨架，提供 `StaticIosPlatformCapabilityService`、`IosPlatformSnapshot`、Network Extension/embedded runtime/certificate/shared storage probe、稳定 `platform.ios.*` 诊断 code 和合同测试；仍不引入 Swift/Xcode project、Network Extension target、签名、TestFlight 上传或 iOS release asset。
- [x] 补充 iOS platform adapter source contract，定义 `platform-ios` crate、`PlatformCapabilityService`/`PlatformCapabilityStatus` 映射、证书状态读取边界、Network Extension entitlement 诊断、remote script 禁用、`macos-26` GitHub Actions 验证入口和 iOS release 阻断边界。
- [x] 补充 iOS Network Extension design，定义 `NEPacketTunnelProvider`/`NETunnelProviderManager` 拓扑、配置下发、App Group/Keychain 边界、MITM 证书状态、远程脚本禁用、App Review 风险、`macos-26` GitHub Actions 验证入口和继续不在本机运行 iOS build/test 的规则。
- [x] 新增 `mitm-anixops-sys` 首个源码接入增量，通过 Git submodule 固定 `mitm_anixops`，在 Rust workspace 中编译 C core，并用一个 version FFI 测试证明 NetworkCore 已链接 `anixops_version()`。
- [x] 补充 `mitm_anixops` adapter 设计，明确该 C ABI core 在 NetworkCore 中只能先作为 MITM 策略/plugin 兼容后端接入，真实全平台 MITM 仍依赖后续领域 mutation model、HTTP/TLS 数据面、证书/信任 platform adapter 和 GitHub Actions 多平台验证。
- [x] 实现 `release-ci-gate` API read；release workflow 现在在 `release-ci-gate` job 级启用 `actions: read`，查询同 repository、同 commit、`main` completed/success CI run，校验 `CI summary` job，输出 CI source fields，并继续不定义 `package-linux`、workflow artifact 或 release asset。
- [x] 补充 release CI gate API implementation plan；新增 release CI gate API implementation plan，固定 `release-ci-gate` 启用 `actions: read` 后的 workflow runs API endpoint、workflow jobs API endpoint、same-sha/main/success run 选择规则、`CI summary` job 校验、输出字段和失败回滚边界；该计划在 API read 实现前曾用于 plan-only blocked 输出。
- [x] 完成 release CI gate execution validation contract；新增 release CI gate execution validation contract，固定 release workflow 必须自动读取同 repository、同 commit、`main` 成功 CI run 的 API 字段、`actions: read` 权限、CI summary 成功校验、manual input blocked 和失败边界；API read 实现后，`release-ci-gate`、`linux-artifact-readiness`、release placeholder 与 release summary 输出 execution active 状态，继续不定义 `package-linux` 或发布 release asset。
- [x] 完成 Linux package publish eligibility execution validation contract；新增 publish eligibility execution validation contract，固定未来 release notes/rollback execution 后必须聚合全部 required gates、校验 eligible 字段、拒绝 missing/unknown/blocked gates、阻断 publish without eligible，并让 `linux-artifact-readiness`、release placeholder 与 release summary 输出 publish eligibility execution blocked 状态，继续不定义 `publish-eligibility-gate`、`publish-github-release` 或上传 release asset。
- [x] 完成 Linux package release notes/rollback execution validation contract；新增 release notes/rollback execution validation contract，固定未来 attestation/provenance 完成后必须校验 release notes required fields、rollback required fields、withdrawal-not-overwrite、new-version-tag-required、缺失 rollback summary 阻断和 publish without release notes/rollback 阻断，并让 `linux-artifact-readiness`、release placeholder 与 release summary 输出 release notes/rollback execution blocked 状态，继续不定义 `post-release-summary`、不创建 GitHub Release 或上传 release asset。
- [x] 完成 Linux package artifact attestation execution validation contract；新增 artifact attestation execution validation contract，固定未来 `attest-linux` 从同一 release run workflow artifact bundle 下载 archive、archive checksum、manifest、manifest checksum 四文件并使用 GitHub artifact attestation/provenance、显式 subject path、required permissions、blocked action/status 和 release asset upload blocked 边界，并让 `linux-artifact-readiness`、release placeholder 与 release summary 输出 artifact attestation execution blocked 状态，继续不定义 `attest-linux`、不启用 attestation permissions、不调用 `actions/attest` 或上传 release asset。
- [x] 完成 Linux package workflow artifact bundle upload validation contract；新增 workflow artifact bundle upload validation contract，固定未来 manifest checksum sidecar 生成后校验 `dist/linux/${target}/artifacts` 中 archive、archive checksum、manifest、manifest checksum 四文件集合、同一 release run workflow artifact bundle 名称、retention days、`actions/upload-artifact` blocked 状态、失败条件和 release asset upload blocked 边界，并让 `linux-artifact-readiness`、release placeholder 与 release summary 输出 workflow artifact bundle upload blocked 状态，继续不上传 workflow artifact 或 release asset。
- [x] 完成 Linux package artifact manifest checksum validation contract；新增 manifest checksum validation contract，固定未来 manifest JSON 生成后使用 `sha256sum` 计算 `networkcore-linux-${version}-${target}.manifest.json.sha256`、校验 two-space record 格式、写 manifest checksum sidecar、失败条件和 workflow artifact/release asset upload blocked 边界，并让 `linux-artifact-readiness`、release placeholder 与 release summary 输出 manifest checksum blocked 状态，继续不生成 manifest checksum 文件或 artifact。
- [x] 完成 Linux package artifact manifest generation validation contract；新增 manifest generation validation contract，固定未来 archive checksum sidecar 写入后生成 `networkcore-linux-${version}-${target}.manifest.json`、校验 manifest 必需字段、archive/checksum 交叉引用、失败条件和 manifest checksum/upload blocked 边界，并让 `linux-artifact-readiness`、release placeholder 与 release summary 输出 manifest generation blocked 状态，继续不生成 manifest、manifest checksum 或 artifact。
- [x] 完成 Linux package artifact checksum execution validation contract；新增 checksum execution validation contract，固定未来 archive 创建后使用 `sha256sum` 计算 `networkcore-linux-${version}-${target}.tar.gz.sha256`、校验 two-space record 格式、写 archive checksum sidecar、失败条件和 manifest/upload blocked 边界，并让 `linux-artifact-readiness`、release placeholder 与 release summary 输出 checksum execution blocked 状态，继续不生成 checksum 文件、manifest 或 artifact。
- [x] 完成 Linux package artifact archive creation validation contract；新增 archive creation validation contract，固定未来 `package-linux` 的 `.tar.gz` archive name/path、`tar -czf` 命令形态、单顶层目录、required files、失败条件和 checksum/manifest/upload blocked 边界，并让 `linux-artifact-readiness`、release placeholder 与 release summary 输出 archive creation blocked 状态，继续不创建 archive 或生成 artifact。
- [x] 完成 Linux package artifact staging file validation contract；新增 staging file validation contract，固定未来 `package-linux` 的 build output、INSTALL、LICENSE/NOTICE 和 CHANGELOG 复制来源、目标路径、binary `0755` 权限、失败条件和 archive/upload blocked 边界，并让 `linux-artifact-readiness`、release placeholder 与 release summary 输出 staging file blocked 状态，继续不创建 archive 或生成 artifact。
- [x] 完成 Linux package artifact build command validation contract；新增 build command validation contract，固定未来 `package-linux` 的 `rustup target add`、`cargo build --locked --release --package networkcore-linux --bin networkcore-linux --target x86_64-unknown-linux-gnu`、binary path 校验、失败条件和当前 blocked-placeholder 状态，并让 `linux-artifact-readiness`、release placeholder 与 release summary 输出 build command blocked 状态，继续不生成 artifact。
- [x] 完成 Linux package artifact job preflight validation contract；新增 preflight validation contract，固定 `package-linux` 在 license/NOTICE 与 artifact gates 未解除前仍不定义，未来真实 job 的 `needs`、checkout、toolchain、build、staging 前置顺序、失败条件和当前 blocked-placeholder 状态，并让 `linux-artifact-readiness`、release placeholder 与 release summary 输出 preflight blocked 状态，继续不生成 artifact。
- [x] 完成 Linux package release CI gate activation validation contract；新增 activation validation contract，固定 `release-ci-gate` 从 placeholder 切换到自动读取同 commit 成功 CI 前的 `actions-read` 权限、GitHub Actions runs API 字段、失败条件和 same-release-sha 校验；API read 实现后，`release-ci-gate`、`linux-artifact-readiness`、release placeholder 与 release summary 输出 activation active 状态，继续不定义 `package-linux` 或生成 artifact。
- [x] 完成 Linux package license/NOTICE confirmed-state transition validation contract；新增 transition validation contract，固定 pending 到 confirmed 的独立人工确认提交字段、`LICENSE`/可选 `NOTICE` 文件存在性检查、release workflow future confirmed marker 校验和当前 `package-linux` 继续未定义边界，并让 `linux-artifact-readiness`、release placeholder 与 release summary 输出 blocked-pending transition 状态，继续不生成 artifact。
- [x] 完成 Linux package publish eligibility aggregate contract；新增 publish eligibility aggregate contract，汇总 license/NOTICE、同 commit CI、runner/toolchain、archive/checksum/manifest、publish/upload、signing/attestation、release notes/rollback 的 eligible/blocked 状态，并让 `linux-artifact-readiness`、release placeholder 与 release summary 输出 aggregate blocked 状态和 next action，继续不定义 `package-linux`、`publish-github-release`、`post-release-summary` 或上传 artifact。
- [x] 完成 Linux package release notes/rollback policy binding contract；新增 release notes/rollback policy binding contract，固定首个 Linux artifact 的 release notes required fields、manual-extract rollback policy、withdrawal-not-overwrite、new-version-tag replacement policy、blocked status 和 publish without rollback 阻断，并让 `linux-artifact-readiness`、release placeholder 与 release summary 输出该合同，继续不定义 `package-linux`、`publish-github-release`、`post-release-summary` 或上传 artifact。
- [x] 完成 Linux package signing/attestation policy binding contract；新增 signing/attestation policy binding contract，固定首个 Linux artifact 的 unsigned-no-detached-signature 策略、GitHub artifact attestation/provenance required 策略、attestation subjects、provenance reference、blocked status 和 publish without attestation 阻断，并让 `linux-artifact-readiness`、release placeholder 与 release summary 输出该合同，继续不定义 `package-linux`、`attest-linux`、`sign-linux`、`publish-github-release` 或上传 artifact。
- [x] 完成 Linux package publish/upload boundary 合同；新增 publish upload boundary contract，固定 future `package-linux` 的 workflow artifact bundle 名称、upload source dir、required files、retention days、publish job/download source、release asset set、禁止覆盖策略和 blocked status，并让 `linux-artifact-readiness`、release placeholder 与 release summary 输出该合同，继续不定义 `package-linux`、`publish-github-release` 或上传 artifact。
- [x] 完成 Linux package checksum/manifest checksum 合同；新增 checksum manifest contract，固定 future `package-linux` 的 archive checksum 文件名/路径、manifest 文件名/路径、manifest checksum 文件名/路径、`sha256` 计算顺序、checksum record 格式和 manifest 交叉校验字段，并让 `linux-artifact-readiness`、release placeholder 与 release summary 输出该合同，继续不定义 `package-linux` 或生成 artifact。
- [x] 完成 Linux package archive staging 合同；新增 archive staging contract，固定 future `package-linux` 的 `dist/linux/${target}`、staging root、`networkcore-linux-${version}-${target}` 顶层目录、archive output/path、`bin/networkcore-linux`、`INSTALL.md`、license/NOTICE confirmed 来源和 `CHANGELOG.md` 文件来源，并让 `linux-artifact-readiness`、release placeholder 与 release summary 输出该合同，继续不定义 `package-linux` 或生成 artifact。
- [x] 完成 Linux package runner/toolchain/target 输入合同；新增 Linux package runner/toolchain/target contract，固定首个 Linux packaging 输入为 `ubuntu-latest`、GitHub-hosted runner、Rust `stable`/`minimal`、`x86_64-unknown-linux-gnu`、`apps/linux-cli`、`networkcore-linux` 和 `tar.gz`，并让 `linux-artifact-readiness`、release placeholder 与 release summary 输出该合同，继续不定义 `package-linux` 或生成 artifact。
- [x] 补充真实 `package-linux` 前同 commit CI 成功结果读取合同；新增 Release CI success source contract，定义后续从 GitHub Actions 读取的 `ci_workflow_name`、`ci_workflow_file`、`ci_run_id`、`ci_run_attempt`、`ci_run_url`、`ci_run_status`、`ci_run_conclusion`、`ci_head_sha`、`ci_head_branch`、`ci_event`、`ci_repository` 和 `ci_checked_at` 字段，并让 `release-ci-gate` 与 release summary 输出该合同，继续不生成 `package-linux` artifact。
- [x] 在 release placeholder summary 中补充 Linux artifact license/NOTICE source contract 状态；`release-placeholder` 现在 checkout 仓库、读取 `docs/manual-intervention.md` 的 pending/blocked marker，输出 source contract、source of truth、pending 状态、`package-linux` blocked 和 release asset blocked 状态，并继续不生成 `package-linux` artifact。
- [x] 补充 Linux artifact license/NOTICE confirmation source contract，定义 `docs/manual-intervention.md` 中 pending/confirmed 机器字段、当前 `linux-artifact-license-notice-status=pending` marker、confirmed 后的最小人工确认字段和 manifest 映射边界；CI governance 与 `linux-artifact-readiness` 现在检查该合同和 pending marker，继续不生成 `package-linux` artifact。
- [x] 在 release placeholder summary 中补充 Linux artifact manifest output contract 摘要；`release-placeholder` 和 `release-summary` 现在显式列出 `artifact_manifest_name`、`artifact_manifest_path`、`artifact_manifest_checksum_file` 和 `artifact_manifest_checksum_value`，CI governance 与 `linux-artifact-readiness` 静态检查该 summary 标识，继续不生成 `package-linux` artifact，并保持 license/NOTICE 未确认时阻止 release asset。
- [x] 在不生成 artifact 的前提下，补充首个 Linux `package-linux` artifact manifest/metadata 输出合同设计；新增 sidecar `networkcore-linux-${version}-${target}.manifest.json`、manifest checksum、必需 JSON 字段、生成顺序、文件清单、release summary 门禁和禁止写入 secret/runner 本地绝对路径的边界，并纳入 CI governance 与 release readiness 静态检查。
- [x] 在 Linux artifact readiness/release gate 中纳入 `networkcore-linux start` foreground stop/release 合同检查；release readiness 现在静态检查 `handle_foreground_lifecycle_with_runtime_stop`、当前进程内 `stop_runtime` 调用、`cli.linux.start.runtime_stop_failed`、native stop/release 诊断和对应 CLI 合同测试，并显式保持 `package-linux` job 未定义。
- [x] 为 `networkcore-linux start` 前台 interruption 后的 runtime stop/release 诊断聚合补充显式合同；interruption 后通过当前进程内 `RuntimeOrchestrator::stop_runtime` 释放 `NativeProxyEngineService` runtime，聚合 `engine.native.runtime.accept_loop_stopped`/`engine.native.runtime.released` 诊断，并用 `cli.linux.start.runtime_stop_failed` 覆盖 stop 失败路径，继续保持无 daemon/control socket 边界。
- [x] 为 `CurrentProcessForegroundLifecycleHost` 接入真实 Unix OS signal/interruption source，默认监听 `SIGINT`/`SIGTERM` 并映射为前台 interruption 合同，非 Unix 继续保留 parking fallback，继续保持无 daemon/control socket 边界。
- [x] 为 `networkcore-linux start` 前台 lifecycle host 补充 signal/interruption 处理合同，新增可注入 interruption source、`cli.linux.start.lifecycle_interrupted` 诊断和 130 退出码映射，继续保持无 daemon/control socket 边界。
- [x] 将 `networkcore-linux start` binary 接入 `NativeProxyEngineService` 与前台 lifecycle host，继续保持无 daemon/control socket 边界。
- [x] 在 `engine-native` 中补充 service-owned runtime state 与 foreground lifecycle handoff 源码合同，`NativeProxyEngineService::start` 可持有 loopback TCP accept loop runtime 并返回 `Running`，`status`/`events`/`stop` 可观察和释放 runtime，继续不接入 `networkcore-linux start` binary。
- [x] 在 `engine-native` 中补充 service start readiness gate 诊断合同，确认有效 runtime assembly plan 已具备但 service-owned runtime state 与 foreground lifecycle handoff 仍阻断 `NativeProxyEngineService::start` 返回 `Running`，继续不接入 `networkcore-linux start`。
- [x] 在 `engine-native` 中补充 SOCKS5 outbound CONNECT accept loop client success response 与 data relay 接线诊断合同，继续不接入 `networkcore-linux start`。
- [x] 在 `engine-native` 中补充 SOCKS5 outbound CONNECT data relay 执行诊断合同，继续不接入 `networkcore-linux start`。
- [x] 在 `engine-native` 中补充 SOCKS5 outbound CONNECT client success response write 诊断合同，当时继续不进行双向数据转发、不接入 `networkcore-linux start`。
- [x] 在 `engine-native` 中补充 SOCKS5 outbound CONNECT client success response write plan 诊断合同，继续不写入 client success response、不进行双向数据转发、不接入 `networkcore-linux start`。
- [x] 在 `engine-native` 中补充 SOCKS5 outbound CONNECT client success response readiness 诊断合同，继续不写入 client success response、不进行双向数据转发、不接入 `networkcore-linux start`。
- [x] 在 `engine-native` 中补充 SOCKS5 outbound CONNECT data relay plan 诊断合同，继续不写入 client success response、不进行双向数据转发、不接入 `networkcore-linux start`。
- [x] 在 `engine-native` 中补充 SOCKS5 outbound CONNECT relay readiness 诊断合同，继续不写入 client success response、不进行双向数据转发、不接入 `networkcore-linux start`。
- [x] 在 `engine-native` 中补充 SOCKS5 outbound CONNECT response decision 诊断合同，继续不写入 client success response、不进行双向数据转发、不接入 `networkcore-linux start`。
- [x] 在 `engine-native` 中补充 SOCKS5 outbound CONNECT response read 诊断合同，当时继续不进行双向数据转发、不接入 `networkcore-linux start`。
- [x] 在 `engine-native` 中补充 SOCKS5 outbound CONNECT request write 诊断合同，当时继续不进行双向数据转发、不接入 `networkcore-linux start`。
- [x] 在 `engine-native` 中补充 SOCKS5 outbound TCP connection attempt 诊断合同，继续不进行数据转发、不接入 `networkcore-linux start`。
- [x] 在 `engine-native` 中补充 SOCKS5 outbound TCP connection plan 诊断合同，继续不建立真实 outbound 连接、不接入 `networkcore-linux start`。
- [x] 在 `engine-native` 中补充 SOCKS5 outbound CONNECT request frame 生成诊断合同，继续不建立真实 outbound 连接、不接入 `networkcore-linux start`。
- [x] 在 `engine-native` 中补充 SOCKS5 CONNECT route/outbound 行为选择诊断合同，继续不建立真实 outbound 连接、不接入 `networkcore-linux start`。
- [x] 在 `engine-native` 中补充 SOCKS5 route/outbound 未接入时的 CONNECT failure response 写入诊断合同，继续不接入 `networkcore-linux start`。
- [x] 在 `engine-native` 中补充 SOCKS5 CONNECT 目标地址读取与 route/outbound 未接入拒绝诊断合同，继续不接入 `networkcore-linux start`。
- [x] 在 `engine-native` 中补充 SOCKS5 命令头读取与 unsupported command 拒绝诊断合同，继续不接入 route/outbound 或 `networkcore-linux start`。
- [x] 在 `engine-native` 中补充 SOCKS5 认证方法响应写入诊断合同，继续不解析 SOCKS5 命令、不接入 route/outbound 或 `networkcore-linux start`。
- [x] 在 `engine-native` 中补充 SOCKS5 no-auth 方法选择与 unsupported auth 方法拒绝诊断合同，继续不写入 SOCKS5 方法响应、不接入 route/outbound 或 `networkcore-linux start`。
- [x] 在 `engine-native` 中补充首个 SOCKS5 greeting 版本/认证方法读取诊断合同，继续不接入 route/outbound 或 `networkcore-linux start`。
- [x] 在 `engine-native` 中补充首个 accepted TCP connection 的协议前置关闭诊断合同，明确未实现 proxy protocol 时的连接处理边界，继续不接入 `networkcore-linux start`。
- [x] 在 `engine-native` 中补充首个 loopback TCP accept loop 与受控关闭源码合同，继续不接入 `networkcore-linux start`。
- [x] 在 `engine-native` 中补充从有效配置图生成首个 native runtime assembly plan 的源码合同，选择 loopback TCP listener 与 SOCKS outbound handler，并覆盖失败释放边界，继续不接入 `networkcore-linux start`。
- [x] 在 `engine-native` 中为首个 native runtime handle 补充真实 loopback TCP listener 绑定/释放实现，继续不接入 `networkcore-linux start`。
- [x] 补充首个 native runtime handle 的最小源码合同，明确 loopback listener handle、outbound handler、失败释放、事件和前台 lifecycle handoff 边界，继续不接入 `networkcore-linux start`。
- [x] 在 `engine-native` 中为标准化 listener/node/route 配置新增结构化图校验，并明确 `ConfigSnapshot.nodes` 与运行请求 nodes 的消费边界，继续不接入 `networkcore-linux start`。
- [x] 在 `config-core` 中解析最小 listener/node/route TOML 子集，继续不接入 `networkcore-linux start`。
- [x] 在 `control-domain` 中新增 listener 配置领域类型，继续不接入 `networkcore-linux start`。
- [x] 补充原生 listener/node 配置模型设计，明确 `engine-native` 何时可以从配置拒绝推进到真实 runtime handle。
- [x] 补充 `networkcore-linux` 前台 lifecycle host 源码合同，继续不接入 `start` 到二进制入口。
- [x] 新增最小 `engine-native` crate 的纯 adapter 合同和诊断测试，但不接入 `networkcore-linux start`。
- [x] 补充原生代理执行内核源码前设计，明确首个 `ProxyEngineService` adapter、前台生命周期 host 和 `networkcore-linux start` 接线门槛。
- [x] 新增最小纯配置服务实现，先支持稳定 schema/profile 解析并将 `prepare-config` 接入二进制入口；`start` 继续保持未接线诊断。
- [x] 补充 `networkcore-linux prepare-config/start` 运行层接线前设计，明确配置服务、代理引擎服务和前台生命周期 adapter 边界。
- [x] 将 `networkcore-linux capabilities/status/diagnostics` 接入 `HostLinuxReadOnlyProbe`，通过 CLI 输出真实只读 Linux 平台诊断。
- [x] 在 `platform-linux` 中新增只读 Linux 平台探测服务，提供 TUN、权限、DNS、service 和证书状态诊断映射合同测试。
- [x] 补充 release workflow 中的 Linux artifact readiness gate，检查 CLI 源码、安装/回滚设计和 release 前置合同，继续阻止未满足门禁的 release asset。
- [x] 补充 Linux CLI artifact 安装、卸载与回滚设计，明确首个压缩包发布前置条件。
- [x] 创建最小 Linux CLI entrypoint crate，提供命令解析骨架与配置/平台诊断合同测试。
- [x] 创建最小 `platform-linux` crate，提供 `PlatformCapabilityService` 测试替身和 Linux 诊断映射合同测试。
- [x] 补充 Linux CLI entrypoint 设计文档，明确首个可运行入口、配置加载、启动/停止和状态查询边界。
- [x] 补充 Linux platform adapter 设计文档，定义 TUN、权限、DNS 与服务管理能力探测边界。
- [x] 补充 Linux artifact 发布前设计文档，明确首个平台产物的源码与 packaging 前置条件。
- [x] 在 release workflow 中补充 artifact rollback 占位说明，定义发布说明必须输出的回滚字段。
- [x] 在 release workflow 中补充 artifact signing/attestation 占位说明，定义真实 artifact 的签名或证明进入条件。
- [x] 在 release workflow 中补充 artifact checksum 占位说明，定义首个真实 artifact job 的 checksum 输出字段。
- [x] 在 release workflow 中补充 release-ci-gate 占位 job，记录真实 artifact 前必须关联 `main` CI 成功结果。
- [x] 在 release workflow 中补充 release summary job，输出当前 placeholder 发布状态和后续 artifact 门禁。
- [x] 在 release workflow 中补充 workflow_dispatch 版本输入与触发 ref 记录，确保 summary 输出发布来源。
- [x] 在 release workflow 中补充版本格式与触发来源一致性 policy gate，防止 placeholder release 使用不可追踪版本。
- [x] 在 CI summary 中补充 GitHub Step Summary 表格，汇总项目检测开关与关键 job 结果。
- [x] 在 CI workflow 中补充 summary 输出项目类型检测结果，确保每次 CI 都记录 Go、Rust、Node、Swift 和 Apple 检测开关。
- [x] 在 CI summary 中补充 Go、Node、Swift 和 Apple 条件结果门禁，确保对应项目出现时 summary job 显式检查语言与平台结果。
- [x] 在 CI summary 中补充 Rust build/test 矩阵结果门禁，确保 summary job 显式检查 Rust build/test 结果。
- [x] 在 `control-runtime` 中补充 MITM gate 权限拒绝诊断顺序合同测试，覆盖 manifest 非错误诊断会在 runtime 权限拒绝诊断前输出。
- [x] 在 `control-runtime` 中补充 MITM gate manifest 错误拒绝诊断顺序合同测试，覆盖平台、证书、manifest 和 runtime 诊断按聚合顺序输出。
- [x] 在 `control-runtime` 中补充 MITM gate manifest 错误优先于权限拒绝合同测试，覆盖 manifest 错误会在缺失权限前短路并返回 manifest 错误拒绝原因。
- [x] 在 `control-runtime` 中补充 MITM gate manifest 错误拒绝证书诊断保留合同测试，覆盖证书诊断会保留在 manifest 错误拒绝决策输出中。
- [x] 在 `control-runtime` 中补充 MITM gate manifest 错误拒绝平台诊断保留合同测试，覆盖平台诊断会保留在 manifest 错误拒绝决策输出中。
- [x] 在 `control-runtime` 中补充 MITM gate manifest 错误拒绝审计合同测试，覆盖 manifest 错误拒绝 reason、审计和禁止调用插件 `load`/`handle_http_event`/`audit` 端口。
- [x] 在 `control-runtime` 中补充 MITM gate 远程脚本拒绝诊断聚合合同测试，覆盖平台诊断会保留在远程脚本拒绝决策输出中。
- [x] 在 `control-runtime` 中补充 MITM gate 证书拒绝诊断聚合合同测试，覆盖证书状态诊断会保留在证书拒绝决策输出中。
- [x] 在 `control-runtime` 中补充 MITM gate 权限拒绝诊断聚合合同测试，覆盖 manifest 非错误诊断会保留在权限拒绝决策输出中。
- [x] 在 `control-runtime` 中补充 MITM gate 平台诊断拒绝路径合同测试，覆盖平台能力诊断会保留在平台拒绝决策输出中。
- [x] 在 `control-runtime` 中补充 MITM gate 平台诊断聚合合同测试，覆盖平台能力与证书诊断会进入允许决策输出。
- [x] 在 `control-runtime` 中补充 MITM gate 插件结果诊断聚合合同测试，覆盖插件执行返回 warning/info 诊断会进入允许决策输出。
- [x] 在 `control-runtime` 中补充 MITM gate manifest 警告诊断放行合同测试，覆盖 warning/info 诊断不会阻断插件执行且会聚合到输出。
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
