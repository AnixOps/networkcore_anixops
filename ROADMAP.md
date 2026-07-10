# Roadmap

本路线图用于把 `networkcore_AnixOps` 从 bootstrap 仓库逐步推进为可验证、可维护的全平台网络内核与客户端体系。所有阶段都必须遵守 [AGENT.md](AGENT.md) 和 [docs/ci-cd-policy.md](docs/ci-cd-policy.md)：本机只编辑文件，验证只在 GitHub Actions 中运行。

## 当前阶段：P4 Client And Platform Integration

P0 Bootstrap Governance、P1 Domain And Architecture Specification、P2 Core Kernel Skeleton 和 P3 Runtime Capability Baseline 已完成。当前工作进入客户端、平台和发布集成阶段：Linux CLI 已有 GitHub Actions 生成的预发布二进制，iOS 仍处于 source-tree/upload gates，运行层继续通过 public engine adapter 和后续 MITM gates 增量补齐能力。

阶段判断以本节为准：P3 是已完成 baseline，当前仓库不再处于 P3。当前迭代、发布说明和 source contract 的 source of truth 是 P4 backlog buckets；P3 只在 completed section、历史 TODO 或 CHANGELOG 中保留审计语境。

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
- [Persistent Subscription Catalog Source Contract](docs/architecture/subscription-catalog-persistence-source-contract.md)
- [Managed Foreground Session Status Source Contract](docs/architecture/managed-foreground-session-status-source-contract.md)
- [Managed Foreground Session Event Source Contract](docs/architecture/managed-foreground-session-event-source-contract.md)
- [Native Engine Listener And Node Config Design](docs/architecture/native-engine-listener-node-config.md)
- [Linux Native Proxy Engine Start Design](docs/architecture/linux-native-proxy-engine-start.md)

已完成 baseline 源码状态：`control-runtime` 已具备显式 inline subscription catalog runtime gate；`networkcore-linux run-url` 可消费 Shadowsocks URL/链接列表并以前台 `sing-box run -c <config>` 暴露默认 `127.0.0.1:7890` 本地代理；`mitm_anixops` 固定到 `v0.45.10-alpha`，`mitm-policy` 提供 safe wrapper 和内置 `networkcore.adblock`，`engine-native` 提供 `NativeHttpMitmPluginHook`、native SOCKS5 CONNECT plugin reject 应用路径、`NativePlainHttpMessage`、plain HTTP rewrite application 和 explicit HTTP proxy live plain HTTP data plane。

当前 P4 main 的 MITM 命令面包含 `mitm status/diagnostics/certificate-plan/browser-plan`、`mitm http-rewrite plan/preview`、`traffic-proof --confirm [--target-url <url>] [--proof-token <token>] [--proof-log <path>]`、`--proxy-scheme socks5` native plugin proxy mode、`mitm certificate apply --confirm --cert-file <path> --key-file <path> [--profile-trust-file <path>] --snapshot <path>` / `rollback --snapshot <path>` TLS CA certificate PEM/private key PEM artifact lifecycle 与 dedicated profile CA PEM copy foundation，以及 browser-capture PAC/browser policy/profile prefs artifact apply/rollback。

`MITM_CERTIFICATE_LIFECYCLE_GATE` 当前为 artifact-lifecycle-active/profile-trust-artifact-active/trust-mutation-blocked，输出 `certificate_plan`、`certificate_lifecycle`、当前证书状态、artifact lifecycle 步骤、dedicated profile trust artifact step、trust-plan blocked operations 和 `mutation_ready=false`；certificate apply 写入标准 CA certificate PEM 与 private key PEM，profile trust artifact 是同一 CA PEM 副本；不会安装或信任 CA，不写 system/browser trust store 或 profile trust state。`MITM_HTTP_TLS_DATA_PLANE_GATE` 当前为 plain-http-live-data-plane-active/tls-decryption-blocked，对 caller-provided plain HTTP preview 输入以及 explicit HTTP proxy `http://` live request/response 应用 reject、redirect、header mutation 和 body mutation；`MITM_BROWSER_CAPTURE_GATE` 当前为 pac-policy-profile-prefs-active/system-mutation-blocked。真实 request/response mutation plan 已有领域表达，CONNECT-level reject 可在 native explicit proxy 层生效，但 CA 安装/信任 mutation 路径、TLS 解密、HTTPS rewrite、script plan 执行和浏览器/系统代理捕获 mutation 仍 deferred/blocked。

第三方 plugin/parser/runtime 后续必须先经过 source contract、pinned source、license/NOTICE、permission、safe wrapper、CI governance 和 upgrade procedure 的固定接入流程。`networkcore-linux start` 仍不消费持久 subscription catalog。后续 runtime 缺口会在 P4 集成阶段继续推进：Trojan/VLESS/VMess URL parser gates、Clash YAML parser gate、sing-box JSON parser gate、Surge proxy line parser gate、Loon proxy line parser gate 和 Quantumult X proxy/server line parser gate 之后的 Hysteria 等订阅格式、VLESS/Trojan/VMess/Clash/sing-box JSON/Surge/Loon/Quantumult X runnable path、节点选择、持久订阅、managed status/events/logs/reload/rollback，以及通过 `MITM_CLI_COMMAND_GATE`、`MITM_CERTIFICATE_LIFECYCLE_GATE`、`MITM_HTTP_TLS_DATA_PLANE_GATE` 和 `MITM_BROWSER_CAPTURE_GATE` 补齐 MITM 真实流量支持。

当前 main 已完成并通过 GitHub Actions 全量 CI 的 `v0.1.2-alpha.1` persistent subscription catalog 首个 source-only `add` 切片：
`CommandSubscriptionCatalogStore::add_source` 使用显式 catalog/snapshot 路径写入 schema version 1 本地 JSON，
生成写前 rollback snapshot，拒绝重复 source id，并输出 `location_kind`/`location_redacted` 脱敏报告；
第二个 `list_sources` source-only 切片已加入显式 catalog 读取和脱敏 entry，并已通过 GitHub Actions 全量 CI；
第三个 `remove_source` source-only 切片已加入写前 snapshot、source-not-found 拒绝和脱敏 report，并已通过 GitHub Actions 全量 CI；
第四个 `select_source` source-only 切片已加入显式 catalog 读取、source-not-found 拒绝和脱敏 report，并已通过 GitHub Actions 全量 CI；
第五个 `update_source` source-only 切片已加入 location 更新、写前 snapshot、source-not-found 拒绝和脱敏 report，并已通过 GitHub Actions 全量 CI；
第六个 `rollback_catalog` source-only 切片已加入显式 snapshot 复原、snapshot 保留、snapshot-not-found 拒绝和脱敏 report，并已通过 GitHub Actions 全量 CI；
`v0.1.2-alpha.2` 的 `read_status`/`write_status`/`transition_status` source-only 切片已显式读取、初始非覆盖写入或受 expected state 保护地迁移 schema version 1 managed foreground session record；迁移保留原始 record snapshot，仅允许 `starting -> running/failed` 与 `running -> stopped/failed`；`networkcore-linux managed-status <status-record-path>` 已只读输出 recorded state，`networkcore-linux managed-status init <status-record-path> <session-id> <engine-id> <state>` 已非覆盖创建 record 并输出 `record_written=true`，`networkcore-linux managed-status transition <status-record-path> <snapshot-path> <expected-state> <next-state>` 已输出 previous/next state 和 `snapshot_written=true`，三者均固定 `liveness_verified=false`，不检查 live process、不接入 runtime control；
同一阶段的 `CommandManagedForegroundSessionStore::rollback_status` 已在 source-only 范围内恢复显式 snapshot 的原始 record：它要求 current record 的 expected state 与 snapshot 的 trim 后 session/engine identity 匹配，保留 snapshot，并输出 previous/restored state、`snapshot_retained=true` 与 `liveness_verified=false`；不提供 `managed-status` rollback CLI，不检查 live process，也不控制 runtime；
同一阶段的 `CommandManagedForegroundSessionEventStore::read_event`/`write_event` 已从显式 schema version 1 event record 读取或非覆盖写入允许的 event kind、recorded state 与 recorded_at，固定 `record_written=true`（写入）与 `liveness_verified=false`；`networkcore-linux managed-event <event-record-path>` 已只读输出 record，`networkcore-linux managed-event init <event-record-path> <session-id> <engine-id> <event-id> <event-kind> <state> <recorded-at>` 已非覆盖创建 record；不扫描 event，不接入实时 event stream 或 runtime control；
`networkcore-linux managed-event <event-record-path>` 已只读输出同一 event record，不写入、删除、列出或扫描 event，也不接入实时 event stream 或 runtime control；
默认路径、远程/file fetch、runtime startup 和 managed lifecycle 仍 blocked，
每个切片的功能完成状态以 GitHub Actions 合同测试为准。

## P4 Client And Platform Integration

目标是在不破坏内核边界的前提下推进全平台客户端。

当前 source release 切片为 `v0.1.2-alpha.3`：Linux 受控 TLS data plane 已可在显式 CA/confirm 下
终止 authority/SNI-bound CONNECT TLS、web-PKI 转发上游并改写单个有界 HTTP/1.1 exchange；显式 local
Node runner/script map 可执行受信本地脚本并 fail-open。该切片不安装 CA trust，也不修改 browser/system
proxy、TUN、DNS、firewall 或路由；用户可下载状态只以同名 tag 的 GitHub Actions release workflow 为准。

预期方向：

- Linux、macOS、Windows 客户端控制入口。
- iOS Network Extension 可行性验证。
- 证书安装、权限提示、插件脚本边界和 App Review 风险治理。
- 发布 workflow 的平台产物矩阵。

当前 P4 状态：Linux CLI artifact 已通过 tag release workflow 发布到 GitHub Release，Windows CLI manual-extract zip 已从 `v0.1.1-alpha.2` 进入 prerelease artifact；最新已发布 prerelease 为 `v0.1.1-alpha.2`，最新 stable 为 `v0.1.0`，并包含 Linux tarball、sha256、manifest、manifest sha256 以及 Windows zip、sha256、manifest、manifest sha256；所有已发布和规划 alpha/rc/stable 切片的能力边界见 [Alpha Release Feature Matrix](docs/alpha-release-feature-matrix.md)。Linux artifact release-state consistency marker 为 `linux-artifact-release-state=confirmed-release-path`，license/NOTICE 已 confirmed，但后续 tag release 仍必须通过同 commit CI、checksum、manifest、attestation、release notes、rollback 和 publish eligibility gates。

当前 main 源码已经发布 `v0.1.1-alpha.2` Windows CLI package/publish path，并开始推进 `v0.1.1-alpha.3` 订阅格式扩展：`v0.1.0` Linux-only explicit HTTPS rewrite preview 正式版能力不变，`v0.1.1-alpha.1` Windows CLI artifact source/release contract 已发布，`v0.1.1-alpha.2` 新增 `apps/windows-cli`、`platform-windows`、`package-windows`、`attest-windows`、Windows release notes/rollback gate 和 Windows publish eligibility gate，并发布 manual-extract Windows CLI zip 四件套；`v0.1.1-alpha.3` 当前源增量是 `CoreSubscriptionService` Trojan/VLESS/VMess URL parser gates、Clash YAML parser gate、sing-box JSON parser gate、Surge proxy line parser gate、Loon proxy line parser gate 和 Quantumult X proxy/server line parser gate，只把 `trojan://password@host:port?...#name`、`vless://uuid@host:port?...#name`、`vmess://base64(json)`、受支持的 Clash `proxies` 子集、sing-box JSON `outbounds` 子集、Surge/Loon `[Proxy]` line 子集以及 Quantumult X `[server_local]` line 子集归一化到 `SubscriptionDocument`/`NodeCatalog`，不启用 `run-url` Trojan/VLESS/VMess/Clash/sing-box JSON/Surge/Loon/Quantumult X 运行、节点选择、远程订阅拉取、文件订阅读取、默认路径扫描、daemon/service 或系统代理 mutation。`MITM_CLI_COMMAND_GATE` 当前做到 status/diagnostics/certificate-plan/browser-plan partial-active，marker 为 `mitm-cli-command-gate-status=partial-active`；`MITM_CERTIFICATE_LIFECYCLE_GATE` 当前为 artifact-lifecycle-active/profile-trust-artifact-active/trust-mutation-blocked，并由 [source contract](docs/architecture/linux-mitm-certificate-lifecycle-source-contract.md) 固定 `certificate_lifecycle`、TLS CA certificate PEM/private key PEM artifact apply/rollback、`--cert-file`、`--key-file`、`--profile-trust-file`、snapshot、dedicated profile CA PEM copy 和 trust mutation blocked 边界；`engine-native` 已包含 `NativeControlledTlsTerminationPlanReport`、`plan_explicit_http_connect_controlled_tls_termination`、`NativeHttpsRequestRewritePreviewReport`/`plan_and_apply_https_request_rewrite_preview` 与 `NativeHttpsResponseRewritePreviewReport`/`plan_and_apply_https_response_rewrite_preview`，用于在 controlled TLS termination plan ready 且输入为 request/response-phase `https://` message 时预览 request reject/redirect/header mutation 与 response header/body mutation。Linux CLI `http_rewrite` report/JSON 已包含 `controlled_tls_termination_plan_ready`、`downstream_tls_termination_plan_ready`、`upstream_tls_forwarding_ready`、`https_request_rewrite_preview_ready`、`https_response_rewrite_preview_ready`、`https_response_rewrite_ready=false` 和 `script_dispatch_ready=false`；rc.1 回归合同已进入正式版，继续固定 caller-provided HTTPS request preview 不声称 live TLS decryption、live CONNECT-stream rewrite 或 JavaScript script dispatch；`traffic-proof` report 包含 `proof_connect_authority`，target URL 可解析时要求同一 proof log 行绑定 token、计划 proxy URL 和 CONNECT authority，失败时返回 `binding_mismatch`，text 输出现在也显式打印 CONNECT authority，方便人工审计 proof 绑定。当前 Windows path 只生成 manual-extract CLI zip，service、driver、installer、system trust store mutation、system proxy mutation、JavaScript script dispatch 和 managed lifecycle 继续 blocked；当前仍不执行 live HTTPS decryption 或 live CONNECT 后 HTTPS request/response rewrite。

Linux 仍是手动解压和 foreground 运行模型，不安装 daemon/service，不修改 TUN/DNS/firewall/certificate trust store。完整用户可用 HTTPS MITM 尚未启用；`mitm certificate apply/rollback` 只写入或删除调用方显式指定的 NetworkCore CA certificate PEM、private key PEM、可选 dedicated profile CA PEM copy 和 snapshot，不安装或信任 CA，不写 system/browser trust store 或 profile trust state；`mitm http-rewrite preview` 可应用 plugin outcome 到 caller-provided plain HTTP input，也可在 source 层对 caller-provided request/response-phase `https://` input 预览 request reject/redirect/header mutation 和 response header/body mutation；`ListenerKind::Http` explicit proxy path 可对真实 `http://` request/response 应用 reject、redirect、header/body rewrite，并可对 explicit HTTP `CONNECT` 建立 pass-through tunnel foundation 和 bounded ClientHello/SNI observation；native SOCKS5 CONNECT plugin reject 只把插件 `Reject` 应用为 CONNECT failure，不解密 HTTPS。

`MITM_HTTP_TLS_DATA_PLANE_GATE` 当前为 plain-http-live-data-plane-active/tls-decryption-blocked，`MITM_BROWSER_CAPTURE_GATE` 当前为 pac-policy-profile-prefs-active/system-mutation-blocked，browser hijack 仍 deferred。Linux MITM HTTP rewrite 和 browser capture 仍分别由既有 source contract 固定命令面、授权、快照和回滚边界；真实浏览器/系统代理 mutation 仍未实现。iOS 仍只允许 `apps/ios/README.md` source tree governance placeholder 和 upload blocked gates，不包含 Swift/Xcode/Network Extension target、签名、TestFlight/App Store upload 或 iOS release asset。后续完整 HTTPS rewrite 仍需后续新 tag release 才会进入用户可下载 artifact。

P4 backlog buckets：

- 订阅和客户端兼容：`v0.1.1` 主线，继续把多客户端订阅格式、节点选择和 Linux/Windows CLI artifact 接入 public engine adapter 路线。
- MITM 数据面和证书生命周期：`v0.1.0` 先完成 Linux-only explicit HTTPS rewrite preview；`v0.1.2` alpha 再相继推出 JavaScript script dispatch、system trust store mutation 和 system proxy mutation。
- 浏览器捕获用户闭环：从 dedicated-profile launch、proxy route verify、proof-log-token traffic proof 和 PAC/browser policy artifact apply/rollback 推进到完整 live browser traffic proof 自动化、显式代理/system PAC 或系统 mutation、snapshot 和 rollback；完整 managed session 编排归入 `v0.1.2`。

已拍板版本节奏：

- `v0.1.0`：Linux-only explicit HTTPS rewrite preview。alpha.14 已发布 plain HTTP live data plane，alpha.15 已发布 TLS MITM readiness，alpha.16 已发布 controlled TLS termination foundation，alpha.17 已发布 HTTPS request rewrite preview，alpha.18 已发布 HTTPS response rewrite preview，alpha.19 已发布 traffic-proof token/proxy/CONNECT authority 绑定 hardening，alpha.20 已发布 release hardening，rc.1 已发布回归冻结合同，正式版已发布 Linux-only artifact；不包含 Windows artifact、JavaScript script dispatch、system trust store mutation、system proxy mutation、daemon/service、TUN、DNS 或 firewall mutation。
- `v0.1.1`：正式引入 Windows 版本，并把订阅兼容作为主线。Windows 首期目标是 CLI artifact 和 release path，不默认包含 Windows service、driver、installer 或系统代理 mutation；订阅侧已推进 Trojan/VLESS/VMess、Clash YAML、sing-box JSON、Surge proxy line、Loon proxy line 和 Quantumult X proxy/server line parser gates，后续推进 VLESS/Trojan/VMess/Clash/sing-box JSON/Surge/Loon/Quantumult X runnable path、节点选择和 cross-platform run plan。
- `v0.1.2`：managed lifecycle 版本。新增 persistent subscription catalog、managed foreground status/events/logs/reload/rollback，并在 alpha 切片中相继推出 JavaScript script dispatch、system trust store mutation、system proxy mutation 和 managed MITM session orchestration；所有高风险 mutation 必须显式授权、可检测、可回滚。

当前发布规划：

- [Release Strategy](docs/release-strategy.md)
- [Alpha Release Feature Matrix](docs/alpha-release-feature-matrix.md)
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
- [Linux MITM HTTP Rewrite Source Contract](docs/architecture/linux-mitm-http-rewrite-source-contract.md)
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
