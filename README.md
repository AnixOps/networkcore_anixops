# networkcore_AnixOps

`networkcore_AnixOps` 是面向全平台网络内核、MITM 插件兼容和客户端体系的规划与实现仓库。

## 目标

- 构建 Linux、macOS、Windows、iOS 可用的统一网络控制内核。
- 维护三层运行架构：NetworkCore 控制层、执行内核 adapter 层、公有执行内核层；runtime baseline 已优先接入 `sing-box` 等公有内核，自研私有协议栈暂缓。
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
- [docs/alpha-release-feature-matrix.md](docs/alpha-release-feature-matrix.md)
- [docs/architecture/control-kernel-domain.md](docs/architecture/control-kernel-domain.md)
- [docs/architecture/control-kernel-interfaces.md](docs/architecture/control-kernel-interfaces.md)
- [docs/architecture/proxy-engine-adapter.md](docs/architecture/proxy-engine-adapter.md)
- [docs/architecture/mitm-anixops-adapter.md](docs/architecture/mitm-anixops-adapter.md)
- [docs/architecture/control-runtime-orchestration.md](docs/architecture/control-runtime-orchestration.md)
- [docs/architecture/subscription-catalog-runtime-orchestration.md](docs/architecture/subscription-catalog-runtime-orchestration.md)
- [docs/architecture/subscription-catalog-persistence-source-contract.md](docs/architecture/subscription-catalog-persistence-source-contract.md)
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
- [docs/architecture/linux-mitm-browser-capture-source-contract.md](docs/architecture/linux-mitm-browser-capture-source-contract.md)
- [docs/architecture/linux-mitm-http-rewrite-source-contract.md](docs/architecture/linux-mitm-http-rewrite-source-contract.md)
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
- [docs/architecture/windows-cli-artifact-source-release-contract.md](docs/architecture/windows-cli-artifact-source-release-contract.md)
- [docs/architecture/adr-0001-initial-core-stack.md](docs/architecture/adr-0001-initial-core-stack.md)
- [docs/architecture/adr-0002-public-engine-adapter-first.md](docs/architecture/adr-0002-public-engine-adapter-first.md)
- [docs/architecture/sing-box-public-engine-adapter-source-contract.md](docs/architecture/sing-box-public-engine-adapter-source-contract.md)
- [docs/architecture/subscription-url-to-sing-box-run-source-contract.md](docs/architecture/subscription-url-to-sing-box-run-source-contract.md)
- [docs/architecture/mitm-policy-ad-block-plugin-source-contract.md](docs/architecture/mitm-policy-ad-block-plugin-source-contract.md)
- [docs/architecture/third-party-plugin-onboarding-process.md](docs/architecture/third-party-plugin-onboarding-process.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [ROADMAP.md](ROADMAP.md)
- [TODO.md](TODO.md)
- [CHANGELOG.md](CHANGELOG.md)

## 当前状态

P2 Core Kernel Skeleton 和 P3 Runtime Capability Baseline 已完成，当前阶段进入 P4 Client And Platform Integration。本节后续内容是已完成源码、合同和 release gate 的详细清单；阶段判断以本段和 [ROADMAP.md](ROADMAP.md) 为准。

阶段状态速查：

- 当前阶段源：P4 Client And Platform Integration。
- P3 是已完成历史基线，不再作为当前仓库阶段描述；后续迭代、TODO、release 说明和架构合同都按 P4 backlog 推进。
- 当前最新 stable artifact：`v0.1.0` GitHub Release 中的 Linux CLI tarball、sha256、manifest 和 manifest sha256；最新 prerelease/tag release 是 `v0.1.1-alpha.2`，它由 GitHub Actions 发布 Linux CLI 四件套和 Windows manual-extract CLI zip、sha256、manifest、manifest sha256。Linux 二进制可用 `help` 命令表、`install-sing-box`、`run-url <ss://url>` foreground local proxy、MITM status/diagnostics/certificate-plan/browser-plan policy-only 命令面、`mitm certificate apply/rollback` certificate artifact lifecycle、TLS 可消费 CA certificate PEM/private key PEM、dedicated profile CA PEM copy、`mitm browser-capture plan/launch-plan/session-plan/launch/apply/rollback/verify/traffic-proof` 的 explicit proxy browser capture 切片、`mitm http-rewrite plan/preview` 的 caller-provided plain HTTP rewrite foundation、explicit HTTP proxy `http://` live request/response rewrite、explicit HTTP `CONNECT` pass-through tunnel foundation、bounded ClientHello/SNI observation、controlled downstream TLS termination plan/report、caller-provided HTTPS request reject/redirect/header mutation preview、caller-provided HTTPS response header/body mutation preview、`traffic-proof` 的 proof token/proxy/CONNECT authority 绑定 hardening，以及 traffic-proof text CONNECT authority 输出。各 alpha/rc/stable 版本能力边界见 [Alpha Release Feature Matrix](docs/alpha-release-feature-matrix.md)。
- 当前 main 源码状态：`v0.1.1-alpha.2` Windows CLI package/publish path 已发布；`apps/windows-cli` source identity、`platform-windows` 只读/blocked capability boundary，release workflow `package-windows`、`attest-windows`、Windows release notes/rollback gate 和 Windows publish eligibility gate 已进入 tag release 路径。`v0.1.1-alpha.3` 订阅格式扩展已开始，当前源增量是 `CoreSubscriptionService` Trojan/VLESS/VMess URL parser gates、Clash YAML parser gate、sing-box JSON parser gate、Surge proxy line parser gate、Loon proxy line parser gate 和 Quantumult X proxy/server line parser gate，把 `trojan://password@host:port?...#name`、`vless://uuid@host:port?...#name`、`vmess://base64(json)`、受支持的 Clash `proxies` 子集、sing-box JSON `outbounds` 子集、Surge/Loon `[Proxy]` line 子集以及 Quantumult X `[server_local]` line 子集归一化到 `SubscriptionDocument`/`NodeCatalog`，不启用 `run-url` Trojan/VLESS/VMess/Clash/sing-box JSON/Surge/Loon/Quantumult X 运行、节点选择、远程订阅拉取、文件订阅读取、默认路径扫描、daemon/service 或系统代理 mutation。Windows artifact 仍只是 `networkcore-windows` manual-extract zip，不启用 Windows service、driver、installer、system proxy mutation、system trust store mutation、JavaScript script dispatch 或 managed lifecycle。`MITM_HTTP_TLS_DATA_PLANE_GATE` 仍为 `plain-http-live-data-plane-active/tls-decryption-blocked`，`http_rewrite` report 中 `live_traffic_ready=true`、`controlled_tls_termination_plan_ready=true`、`downstream_tls_termination_plan_ready=true`、`upstream_tls_forwarding_ready=true`、`https_request_rewrite_preview_ready=true`、`https_response_rewrite_preview_ready=true`、`https_response_rewrite_ready=false`、`script_dispatch_ready=false`、`tls_decryption_ready=false`。
- 当前未启用：完整 live MITM、browser hijack、浏览器/系统代理配置 mutation、CA 安装/信任 mutation、profile trust state mutation、HTTPS 解密、live TLS termination、live CONNECT 后 HTTPS request/response rewrite、完整 live HTTPS response rewrite、daemon/service、TUN/DNS/firewall mutation。当前 main 只允许写 operator-provided TLS CA certificate PEM、private key PEM、dedicated profile CA PEM copy、PAC artifact、可选 Chromium/Chrome managed proxy policy artifact 和 rollback snapshot，并允许显式 caller-provided plain HTTP preview、显式 caller-provided HTTPS request/response rewrite preview、显式 HTTP proxy listener 的 `http://` live path 应用 rewrite outcome、explicit HTTP proxy `CONNECT` 建立 pass-through tunnel 和 bounded ClientHello/SNI 观察，以及 controlled downstream TLS termination plan/report；不安装或信任 CA，不安装系统 PAC 或浏览器 policy，不解析 live CONNECT 后 HTTPS request/response。native SOCKS5 hook 仍只能在显式 SOCKS5 CONNECT 层应用插件 `Reject` 为 CONNECT failure，不解密 HTTPS。

v0.1.2-alpha.1 的首个 source-only 增量已完成并通过 GitHub Actions 全量 CI：`CommandSubscriptionCatalogStore::add_source` 使用显式 catalog/snapshot 路径写入 schema version 1 的本地 JSON catalog，生成不可覆盖的写前 rollback snapshot，拒绝重复 source id，并以 `location_kind`/`location_redacted` 输出脱敏报告；该切片不执行默认路径扫描、远程或文件订阅读取，也不接入 `start`、节点选择或 managed lifecycle。第二个 `list_sources` source-only 切片也已完成并通过 GitHub Actions 全量 CI，读取显式 catalog、输出脱敏 entry 且不修改文件。第三个 `remove_source` source-only 切片已加入写前 snapshot、source-not-found 拒绝和脱敏 report，完成状态以 GitHub Actions 为准。边界见 [Persistent Subscription Catalog Source Contract](docs/architecture/subscription-catalog-persistence-source-contract.md)。

当前文档判定规则：如果后续章节、TODO 已完成项或 CHANGELOG 中出现 P3，只表示当时完成的 runtime baseline 或历史源码合同；不得把这些历史条目解释为当前阶段、当前发布状态或当前开发优先级。

P4 backlog buckets：

- 订阅和客户端兼容：在 `run-url <ss://url>` foreground 闭环、当前 Trojan/VLESS/VMess URL parser gates、Clash YAML、sing-box JSON、Surge proxy line、Loon proxy line 和 Quantumult X proxy/server line catalog import gates 上继续补 VLESS/Trojan/VMess/Clash/sing-box JSON/Surge/Loon/Quantumult X runnable path、节点选择、持久订阅和 managed lifecycle。
- MITM 数据面和证书生命周期：在已具备 certificate artifact lifecycle 和 explicit plain HTTP live data plane 的基础上补齐 CA 安装/信任/撤销/trust-store 回滚、TLS decryption、HTTPS request/response rewrite 和 script runtime；当前已输出状态、证书/浏览器计划、`certificate_lifecycle` artifact report、rich mutation plan，可在 native SOCKS5 CONNECT 前置点应用插件 `Reject` 为 CONNECT failure，并可在 explicit HTTP proxy `http://` 路径应用 reject、redirect、header/body rewrite。
- 浏览器捕获用户闭环：在 dedicated-profile launch、local proxy endpoint verify、target route verify、proof-log-token traffic proof 和 PAC/browser policy artifact apply/rollback 之后，继续补完整 live browser traffic proof 自动化、显式 browser/system proxy 配置、系统 PAC 或其他捕获策略，以及安全授权和回滚边界。

已拍板版本节奏：

- `v0.1.0`：Linux-only explicit HTTPS rewrite preview。alpha.14 已发布 plain HTTP live data plane，alpha.15 已发布 TLS MITM readiness，alpha.16 已发布 controlled TLS termination foundation，alpha.17 已发布 HTTPS request rewrite preview，alpha.18 已发布 HTTPS response rewrite preview，alpha.19 已发布 traffic-proof token/proxy/CONNECT authority binding hardening，alpha.20 已发布 release hardening，rc.1 已发布回归冻结合同，正式版已发布 Linux-only artifact；不包含 Windows artifact、JavaScript script dispatch、system trust store mutation、system proxy mutation、daemon/service、TUN、DNS 或 firewall mutation。
- `v0.1.1`：正式引入 Windows 版本，并把订阅兼容作为主线。Windows 首期目标是 CLI artifact 和 release path，不默认包含 Windows service、driver、installer 或系统代理 mutation；订阅侧已推进 Trojan/VLESS/VMess、Clash YAML、sing-box JSON、Surge proxy line、Loon proxy line 和 Quantumult X proxy/server line parser gates，后续推进 VLESS/Trojan/VMess/Clash/sing-box JSON/Surge/Loon/Quantumult X runnable path、节点选择和 cross-platform run plan。
- `v0.1.2`：managed lifecycle 版本。新增 persistent subscription catalog、managed foreground status/events/logs/reload/rollback，并在 alpha 切片中相继推出 JavaScript script dispatch、system trust store mutation、system proxy mutation 和 managed MITM session orchestration；所有高风险 mutation 必须显式授权、可检测、可回滚。

Linux/Windows CLI 二进制发布路径已打通：Linux 首个真实发布路径从 `v0.1.0-alpha.2` 开始，Windows 首个真实 CLI artifact 从 `v0.1.1-alpha.2` 开始；当前最新 GitHub Release 是
`v0.1.1-alpha.2` prerelease，最新 stable 是 `v0.1.0`。`v0.1.1-alpha.2` 由 GitHub Actions 构建并发布
`networkcore-linux` Linux tarball、sha256、manifest、manifest sha256，以及 `networkcore-windows` manual-extract zip、sha256、manifest、manifest sha256，release workflow 同时完成
同 commit CI gate、artifact checksum、manifest、GitHub artifact attestation、publish eligibility 和
GitHub Release asset 上传。
当前 Linux artifact release-state consistency marker 为
`linux-artifact-release-state=confirmed-release-path`：`docs/manual-intervention.md` 中的 license/NOTICE
状态已是 `confirmed`，但该状态只解除人工 license/NOTICE 门禁；后续 Linux tag release 仍必须继续通过
同 commit CI、checksum、manifest、attestation、release notes、rollback 和 publish eligibility gates。

已完成的 runtime baseline 已固化为公有执行内核 adapter 优先：NetworkCore 维护自己的控制层、配置/订阅/策略/DNS/MITM
意图、平台能力和审计输出；`engine-*` adapter 负责把领域模型转换成具体执行内核配置并管理生命周期；
`sing-box` 等公有执行内核先承担 VLESS、Shadowsocks、Trojan、VMess、Hysteria 等协议数据面。
`engine-native` 继续保留为自研执行内核实验线，但私有协议实现暂缓，直到 adapter 路线暴露明确缺口。

当前 P4 状态：Linux CLI artifact 已经通过 GitHub Actions tag release workflow 发布到 GitHub Release，
最新已发布 prerelease 是 `v0.1.1-alpha.2`，最新 stable 是 `v0.1.0`；
Linux 和 Windows 仍是手动解压和 foreground/CLI 运行模型，不安装 daemon/service，不修改 TUN/DNS/firewall/certificate trust store。
iOS 仍只允许 `apps/ios/README.md` source tree governance placeholder 和 upload blocked gates，
不包含 Swift/Xcode/Network Extension target、签名、TestFlight/App Store upload 或 iOS release asset。
Linux MITM browser capture 已新增
[Linux MITM Browser Capture Source Contract](docs/architecture/linux-mitm-browser-capture-source-contract.md)，
用于固定后续 `BrowserCaptureAuthorization`、`BrowserCaptureRollbackSnapshot`、apply/rollback/verify 命令面、
manual dedicated-profile launch-plan、脱敏 session-plan、可选 target URL、proof target URL、显式授权 launch、授权、PAC/browser policy artifact、快照和回滚边界；当前 Linux CLI artifact 已提供
`mitm browser-capture plan/launch-plan/session-plan/launch/apply/rollback/verify/traffic-proof` 的 manual launch-plan、订阅到本地代理/浏览器/verify/traffic-proof 会话计划、可选 `--target-url` 目标页面、dedicated-profile launch、本地代理端点/target route verify、proof log binding、blocked report
命令面和 `browser_capture` 机器字段，并包含 `session-plan`/`launch --confirm` 的 `proof_target_url`/`proof_connect_authority`/`networkcore_proof_token`/`traffic_proof_command` 绑定、`--proxy-scheme socks5` native plugin proxy mode，以及 `apply --confirm --pac-file <path> [--policy-file <path>] [--profile-prefs-file <path>] --snapshot <path>` 的 NetworkCore PAC/browser policy artifact 与 Firefox dedicated profile prefs 写入/回滚路径，report 输出 `profile_prefs_file_path` 和 `profile_prefs_content`。`MITM_BROWSER_CAPTURE_GATE` 现在是
pac-policy-profile-prefs-active/system-mutation-blocked，仍不执行真实系统代理或浏览器配置 mutation。
Linux MITM HTTP rewrite 已新增
[Linux MITM HTTP Rewrite Source Contract](docs/architecture/linux-mitm-http-rewrite-source-contract.md)，
用于固定 `MITM_HTTP_TLS_DATA_PLANE_GATE=plain-http-live-data-plane-active/tls-decryption-blocked`、
`NativePlainHttpMessage`、`NativePlainHttpRewriteReport`、`NativeExplicitHttpProxyRequest`、`LinuxMitmHttpRewriteReport`、`http_rewrite`
report、`mitm http-rewrite plan/preview`、explicit HTTP proxy live plain HTTP data plane、explicit HTTP CONNECT tunnel foundation、显式授权和 blocked operations 边界；当前可对 caller-provided
plain HTTP preview 输入和 explicit HTTP proxy `http://` live request/response 应用插件 outcome，也可对 explicit HTTP proxy `CONNECT` 建立 pass-through tunnel；仍不解密 TLS，不修改 browser/system proxy、system PAC、TUN、DNS、firewall 或 CA trust。

`engine-singbox` 已作为首个 public engine adapter source contract 进入 workspace；`networkcore-linux help`
现在输出命令表，`networkcore-linux install-sing-box`/`networkcore-linux sing-box install` 会从官方 GitHub latest
release 选择当前目标资产，校验 `sha256:` digest，解压缓存 `sing-box` 可执行文件，并在 JSON 中输出
`sing_box_install` 机器字段。该路径是运行时下载缓存，不把第三方 `sing-box` binary 打进 NetworkCore release
artifact。`networkcore-linux run-url <ss://url>` 现在走 `CoreSubscriptionService` 把单条 Shadowsocks URL、
明文链接列表或 base64 链接列表归一化为 `NodeCatalog`，由 `engine-singbox` 渲染本地 `mixed` inbound
配置并以前台 `sing-box run -c <config>` 启动，默认本地代理为 `127.0.0.1:7890`，JSON 输出新增
`sing_box_run` 机器字段。Clash YAML、sing-box JSON、Surge proxy line、Loon proxy line 和 Quantumult X proxy/server line catalog import parser gates 已进入 current main；Clash/sing-box JSON/Surge/Loon/Quantumult X run/render、daemon/control socket、持久订阅、节点选择、VLESS/Trojan/VMess runnable path、status/events/logs、reload、TUN/DNS mutation 和 MITM 真实流量处理仍是后续工作。

`MITM_CLI_COMMAND_GATE` 已进入 status/diagnostics/certificate-plan/browser-plan 部分激活状态：
`mitm-cli-command-gate-status=partial-active`。`networkcore-linux mitm status`、
`networkcore-linux mitm diagnostics`、`networkcore-linux mitm certificate-plan` 和
`networkcore-linux mitm browser-plan` 会通过
`mitm-policy` 加载内置 `networkcore.adblock` 策略包，输出 `mitm_status` JSON 机器字段；
其中 `certificate_plan` 固定当前证书状态、artifact lifecycle 步骤、trust mutation blocked operations 和
`mutation_ready=false`，`mitm certificate apply --confirm --cert-file <path> --key-file <path> [--profile-trust-file <path>] --snapshot <path>` / `mitm certificate rollback --snapshot <path>` 可写入或删除 NetworkCore-owned CA certificate PEM、private key PEM、可选 dedicated profile CA PEM copy 和 rollback snapshot，并输出 `certificate_lifecycle` JSON report；`browser_plan` 固定浏览器捕获计划、默认显式代理目标
`127.0.0.1:7890`、blocked operations 和 `mutation_ready=false`。`MITM_BROWSER_CAPTURE_GATE`
当前为 pac-policy-profile-prefs-active/system-mutation-blocked，并明确报告 browser hijack 为 `deferred`。证书入口只写调用方指定的 PEM artifact 和 snapshot，不安装或信任 CA，不写 profile trust state，
不解密 HTTPS，不修改浏览器/系统代理、系统 PAC、TUN、DNS 或 firewall，也不把 rewrite plan 应用到真实流量。
`networkcore-linux mitm browser-capture plan/launch-plan/session-plan/launch/apply/rollback/verify/traffic-proof` 现在输出 `browser_capture` 机器字段；
`launch-plan` 输出绑定已加载 `networkcore.adblock` 插件元数据和计划代理 URL 的手动 dedicated-profile 浏览器启动命令模板，但不启动浏览器、不写 profile 或系统状态；
`session-plan <ss://url>` 解析单条订阅链接，输出脱敏 URL 来源、选中节点、本地代理地址、`run-url <subscription-url>` 启动命令模板、dedicated 浏览器命令、可选 `--target-url <url>` 目标页面、带 `networkcore_proof_token` 的 `proof_target_url`、继承 target URL 的 `verify --confirm` 命令、`traffic_proof_command` 和 `networkcore.adblock` 插件元数据；可用 `--proxy-scheme socks5` 把计划绑定为 `socks5://127.0.0.1:7890` 以显式走 native CONNECT hook；该路径不下载或启动 `sing-box`，不启动浏览器，不写系统代理、浏览器 policy、system PAC、TUN、DNS、firewall 或 CA 状态；
`launch --confirm` 通过注入的 `BrowserCaptureProcessRunner` 启动一个带显式代理参数的 dedicated browser profile；传入 `--target-url <url>` 时会把带 proof token 的 proof target URL 作为浏览器参数打开，并输出 `launch_report`、pid、profile、`proxy_scheme`、proxy、target URL、proof target URL、proof token/log、traffic-proof 命令、命令参数和插件元数据；`--proxy-scheme socks5` 会传入 `--proxy-server=socks5://127.0.0.1:7890`；该路径不写系统代理、浏览器 policy、system PAC、TUN、DNS、firewall 或 CA 状态，也不验证 live MITM；
`apply --confirm --pac-file <path> [--policy-file <path>] [--profile-prefs-file <path>] --snapshot <path>` 在 current main 中写入 operator-provided NetworkCore PAC 文件、可选 Chromium/Chrome managed proxy policy artifact、可选 Firefox dedicated profile `user.js` prefs 和 rollback snapshot，PAC/policy/profile prefs 内容只指向计划本地代理 `127.0.0.1:7890`，并在 report 中输出 `profile_prefs_file_path` 和 `profile_prefs_content`，不会安装系统 PAC 或浏览器 policy；缺少 `--pac-file` 或 `--snapshot` 时返回 config missing；`rollback --snapshot <path>` 读取 NetworkCore snapshot 并删除对应 PAC/policy artifact，且在 profile prefs 未被外部修改时恢复或删除对应 `user.js`，
`verify --confirm` 通过注入的 `BrowserCaptureEndpointProbe` 检查计划本地代理端点 `http://127.0.0.1:7890` 是否可达；传入 `--target-url <url>` 时会对目标 host:port 发起 HTTP CONNECT 探测，并输出 `verify_report`、proxy URL、target URL、probe 类型和插件元数据；该路径只验证本地代理端点或目标代理通路，不验证浏览器真实流量、HTTPS MITM 或 rewrite 应用。
`traffic-proof --confirm [--target-url <url>] [--proof-token <token>] [--proof-log <path>] [--proxy-scheme http|socks5]` 通过注入的 `BrowserCaptureTrafficProofProbe` 读取 operator-provided proof log，输出 `traffic_proof_report`、`proof-log-token`、`proxy_scheme`、proxy URL、target URL、`proof_connect_authority`、proof target URL、proof token、proof log path 和插件元数据；未传 proof token/log 时会使用和 `session-plan`/`launch` 相同的默认 proof 绑定，默认 token 由 CONNECT endpoint 与 proxy URL 派生，native SOCKS5 CONNECT hook 会在启动日志诊断中输出同一 token。target URL 可解析时，proof log 必须有一行同时绑定 token、计划 proxy URL 和 CONNECT authority；否则返回 `binding_mismatch`。该路径只证明 proof log 中观察到同一显式代理会话 proof 绑定，不写系统代理、浏览器 policy、system PAC、TUN、DNS、firewall 或 CA 状态，也不证明 HTTPS MITM 解密或 rewrite 已应用。
上述 `launch --confirm`、`verify --confirm`、`traffic-proof --confirm`、proof target URL 绑定、PAC/browser policy/profile prefs artifact apply/rollback 和后续 browser-capture blocked report 已纳入当前 Linux CLI 源码边界；它们只启动 dedicated browser profile、探测本地代理端点、把 proof token 传给目标 URL、检查同一 proof 会话的 proof log binding、写入可回滚 PAC/policy/profile prefs artifact 或返回 blocked report，不代表已启用 live MITM。

说明：下方历史清单中保留了 placeholder 阶段的字段名称；当前可执行状态以上面段落和 [ROADMAP.md](ROADMAP.md) 为准。

补充说明：`networkcore-linux start` binary 已接入 `NativeProxyEngineService` 与前台 lifecycle host；有效 listener/node 配置可让二进制入口在当前进程内启动 loopback TCP accept loop runtime 并进入前台持有路径。前台 lifecycle 已具备可注入 interruption source、Unix `SIGINT`/`SIGTERM` OS signal source、`cli.linux.start.signal_received`/`cli.linux.start.lifecycle_interrupted` 诊断、130 退出码和 interruption 后 runtime stop/release 诊断聚合合同。`stop` 与后台 `status` 继续保持无 daemon/control socket 边界；`engine-native` 当前仅作为原生 SOCKS skeleton，不承担 VLESS、Shadowsocks、Trojan、VMess、Hysteria 等私有协议兼容目标。

当前仓库处于 P4 Client And Platform Integration 阶段，已建立协作规范、规划治理入口、架构规格、运行层编排设计、发布策略、iOS 平台风险评估、Linux artifact 发布前设计、Linux platform adapter 设计、Linux CLI entrypoint 设计、Linux CLI runtime wiring 设计、Native engine listener/node 配置设计、Linux native proxy engine start 设计、Linux CLI artifact 安装/卸载/回滚设计、Linux package artifact manifest 设计、Linux artifact license/NOTICE confirmation source contract、Linux package license/NOTICE transition validation contract、release CI success source contract、Linux package release CI gate activation validation contract、release CI gate execution validation contract、release CI gate API implementation plan、Linux package artifact job preflight validation contract、Linux package artifact build command validation contract、Linux package artifact staging file validation contract、Linux package artifact archive creation validation contract、Linux package artifact checksum execution validation contract、Linux package artifact manifest generation validation contract、Linux package artifact manifest checksum validation contract、Linux package workflow artifact bundle upload validation contract、Linux package artifact attestation execution validation contract、Linux package release notes/rollback execution validation contract、Linux package publish eligibility execution validation contract、Linux package runner/toolchain/target contract、Linux package archive staging contract、Linux package checksum/manifest checksum contract、Linux package publish/upload boundary contract、Linux package signing/attestation policy binding contract、Linux package release notes/rollback policy binding contract、Linux package publish eligibility aggregate contract、Rust 首选栈决策、最小 `control-domain` crate、control-domain listener 配置领域类型、最小 `control-runtime` crate、最小 `config-core` crate、config-core listener/node/route TOML 解析、最小 `engine-native` crate、engine-native listener/node/route 图校验、engine-native native runtime handle 源码合同、engine-native loopback TCP listener 绑定/释放、engine-native runtime assembly plan 源码合同、engine-native loopback TCP accept loop 受控关闭源码合同、engine-native service-owned runtime state 与 foreground lifecycle handoff 源码合同、engine-native accepted TCP connection 协议前置关闭诊断合同、engine-native SOCKS5 greeting 版本/认证方法读取诊断合同、engine-native SOCKS5 no-auth 方法选择/unsupported auth 方法拒绝诊断合同、engine-native SOCKS5 认证方法响应写入诊断合同、engine-native SOCKS5 命令头读取/unsupported command 拒绝诊断合同、engine-native SOCKS5 CONNECT 目标地址读取、route/outbound 行为选择、SOCKS outbound CONNECT request frame 生成、SOCKS outbound TCP connection plan、SOCKS outbound TCP connection attempt、SOCKS outbound CONNECT request write、SOCKS outbound CONNECT response read、SOCKS outbound CONNECT response decision、SOCKS outbound CONNECT relay readiness、SOCKS outbound CONNECT data relay plan、SOCKS outbound CONNECT data relay execution、SOCKS outbound CONNECT client success response readiness、SOCKS outbound CONNECT client success response write plan、SOCKS outbound CONNECT client success response write、accept loop client success response 与有限 data relay 接线、未接入拒绝与 CONNECT failure response 写入诊断合同、最小 `platform-linux` crate、最小 `networkcore-linux` CLI crate、MITM gate 初始门禁用例、平台 MITM 不可用拒绝路径、证书状态拒绝矩阵、证书诊断拒绝保留路径、manifest 诊断拒绝路径、manifest 错误拒绝审计边界、manifest 错误优先于权限拒绝路径、manifest 错误拒绝平台诊断保留路径、manifest 错误拒绝证书诊断保留路径、manifest 错误拒绝诊断顺序路径、manifest 非错误诊断聚合路径、manifest 诊断权限拒绝保留路径、权限拒绝诊断顺序路径、插件结果诊断聚合路径、平台诊断聚合路径、平台诊断拒绝路径、远程脚本执行拒绝路径、远程脚本诊断拒绝保留路径、远程脚本未知状态拒绝路径、Linux 诊断映射合同测试、Linux 只读平台探测服务、Linux CLI 只读平台探测接线、Linux CLI `prepare-config` 运行层接线、Linux CLI 前台 lifecycle host 源码合同、Linux CLI 前台 interruption source 合同、Linux CLI Unix OS signal source 合同、Linux CLI 前台 interruption runtime stop/release 诊断聚合合同、Linux CLI 命令解析、配置读取、平台拒绝、stop/status 和 JSON 输出合同测试、权限拒绝审计边界、审计事件聚合边界、平台能力状态类型、Rust 依赖安全扫描 CI、Rust build/test summary 门禁、Go/Node/Swift/Apple 条件 summary 门禁、CI 项目类型检测输出、GitHub Step Summary 表格、Linux artifact readiness gate、Linux artifact foreground stop/release release gate、Linux artifact manifest release gate、Linux artifact manifest output summary gate、Linux artifact license/NOTICE confirmed marker gate、Linux artifact release-state consistency gate、Linux artifact license/NOTICE source contract confirmed summary、Linux package license/NOTICE transition validation confirmed summary、release CI success source contract active summary、Linux package release CI gate activation validation active summary、release CI gate execution validation active summary、release CI gate API implementation active summary、Linux package artifact job preflight validation active summary、Linux package artifact build command validation active summary、Linux package artifact staging file validation active summary、Linux package artifact archive creation validation active summary、Linux package artifact checksum execution validation active summary、Linux package artifact manifest generation validation active summary、Linux package artifact manifest checksum validation active summary、Linux package workflow artifact bundle upload active summary、Linux package artifact attestation execution active summary、Linux package release notes/rollback execution active summary、Linux package publish eligibility execution active summary、Linux package platform input contract active summary、Linux package archive staging contract active summary、Linux package checksum/manifest checksum contract active summary、Linux package publish/upload boundary contract active summary、Linux package signing/attestation policy binding contract active summary、Linux package release notes/rollback policy binding contract active summary、Linux package publish eligibility aggregate contract active summary、release source summary、release source policy gate、release artifact checksum contract、release signing/attestation contract 和 release rollback contract。后续实现必须先补齐对应规格或设计说明，并通过 CI/CD 验证。

Subscription catalog runtime gate 已在 `control-runtime` 落地，`RuntimeOrchestrator::prepare_runtime_request_with_subscription_catalogs`、`start_runtime_with_subscription_catalogs` 和 `reload_runtime_with_subscription_catalogs` 可基于显式 `SubscriptionService`/`SubscriptionSource` 把 inline `NodeCatalog.nodes` 编排进 `RuntimeConfigRequest.nodes`，用 `runtime.subscription.node_id_duplicate` 拒绝与 `ConfigSnapshot.nodes`、已有 `RuntimeConfigRequest.nodes` 或其他 catalog nodes 重复的 id，并用 `runtime.subscription.rules_deferred` 保持 `NodeCatalog.rules` deferred。`networkcore-linux run-url` 现在直接消费 URL 订阅输入并交给 `sing-box` foreground path；通用 `start` 仍未扫描默认订阅路径，也未暴露持久 subscription catalog 输入；远程/文件订阅、系统 DNS/TUN mutation、daemon/control socket 和非 Linux release artifact 继续 blocked。

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

`mitm_anixops` 接入已先以 adapter 设计形式记录：该库可作为 MITM 策略/plugin 兼容 C ABI core；当前 main 已补齐首版领域 mutation plan，但完整全平台 MITM 仍需要 NetworkCore 后续补齐 HTTP/TLS 数据面和各平台证书/运行时 adapter。

后续第三方 plugin、plugin parser、script runtime 或兼容核心必须先走
[Third-Party Plugin Onboarding Process](docs/architecture/third-party-plugin-onboarding-process.md)：
先建立 source contract、固定 upstream source、明确 license/NOTICE 和 permission gate，再进入 raw binding、
safe wrapper、runtime/domain integration、CI governance 和 release gate。

当前源码接入增量已把 `mitm_anixops` Git submodule 固定到 `v0.45.10-alpha`
(`a3ee0fca6376ddccc333bdfe06ac5b5e75ed23e0`)；`mitm-anixops-sys` 编译 C core
并暴露低层 FFI，`mitm-policy` 提供 safe wrapper、`AnixOpsMitmPluginService` 和
内置 `networkcore.adblock` alpha 去广告插件包。safe wrapper 现在覆盖 URL rewrite、
named header rewrite、bounded header-list application、body rewrite chain、script dispatch、
JQ max-input guard 和 aggregated rewrite plan 合同；当前插件路径保留旧
`handle_http_event` audit/diagnostics 和 `mitm.policy.http_event.mutation_deferred`，
同时新增 rich `handle_http_mitm_event`，可输出 `HttpMitmOutcome` URL/header/body/script
policy plan。`engine-native` 现在有 `NativeHttpMitmPluginHook` 和
`plan_socks5_connect_http_mitm`，可把 SOCKS5 CONNECT target 映射成 rich
MITM event 并取得插件 plan；`networkcore-linux start` 会把内置
`networkcore.adblock` hook 注入 native engine，插件返回 `Reject` 时会在
CONNECT 进入 outbound 前写 SOCKS5 general failure response。真实
redirect/header/body/script 改写仍等待 HTTP/TLS 数据面应用该 plan。

当前仓库源码已有用户可见的 MITM 状态、诊断、证书计划、证书 artifact apply/rollback、浏览器捕获计划、PAC/browser policy artifact apply/rollback、browser-capture blocked report 入口、caller-provided plain HTTP rewrite preview 和 explicit HTTP proxy live plain HTTP data plane，但没有用户可启用的 HTTPS MITM 功能：
`networkcore-linux mitm status`、`networkcore-linux mitm diagnostics` 和
`networkcore-linux mitm certificate-plan`、`networkcore-linux mitm browser-plan` 输出 policy-only 状态、
`mitm_status` 机器字段、`certificate_plan` 和 `browser_plan` 计划字段以及 deferred/blocked gate 诊断；`networkcore-linux mitm certificate apply --confirm --cert-file <path> --key-file <path> [--profile-trust-file <path>] --snapshot <path>` / `rollback --snapshot <path>` 只写入或删除 NetworkCore CA certificate PEM、private key PEM、可选 dedicated profile CA PEM copy 和 snapshot，输出 `certificate_lifecycle` report，并由 [Linux MITM Certificate Lifecycle Source Contract](docs/architecture/linux-mitm-certificate-lifecycle-source-contract.md) 固定边界；
`networkcore-linux mitm browser-capture plan/launch-plan/session-plan/launch/apply/rollback/verify/traffic-proof` 额外输出 `browser_capture` manual launch-plan、脱敏 session-plan、可选 target URL、proof target URL、dedicated-profile launch report、`proxy_scheme`、本地代理端点 verify report、带默认 proof 绑定的 traffic proof report、PAC/browser policy artifact report 和 blocked report；
`networkcore-linux mitm http-rewrite plan/preview` 输出 `http_rewrite` report，并由 [Linux MITM HTTP Rewrite Source Contract](docs/architecture/linux-mitm-http-rewrite-source-contract.md) 固定 caller-provided plain HTTP rewrite preview 和 explicit HTTP proxy `http://` live request/response rewrite 边界；
不会安装或信任 CA，不会修改 system trust store、browser trust store 或 profile trust state，不会解密 HTTPS，不会修改浏览器/系统代理、system PAC、TUN/DNS/firewall；`engine-native`
只能在显式 SOCKS5 CONNECT 层应用插件 `Reject` 为 CONNECT failure，不会把 `mitm-policy`
的 redirect/header/body/script rewrite plan 应用到 HTTPS request/response、browser/system captured traffic 或 script runtime。后续必须继续补齐四个门禁：
`MITM_CLI_COMMAND_GATE` 从 partial-active 扩展到可操作命令面；
`MITM_CERTIFICATE_LIFECYCLE_GATE` 当前为 artifact-lifecycle-active/profile-trust-artifact-active/trust-mutation-blocked，后续再从 artifact lifecycle 扩展到 CA 安装、信任检测、撤销和 trust-store 回滚；
`MITM_HTTP_TLS_DATA_PLANE_GATE` 当前为 plain-http-live-data-plane-active/tls-decryption-blocked，main 源码已具备 explicit HTTP CONNECT tunnel foundation、controlled TLS termination plan、caller-provided HTTPS request rewrite preview 和 caller-provided HTTPS response rewrite preview，后续再把 live TLS decryption、live HTTPS response rewrite 和 script runtime 接到 HTTP/TLS 数据面；
`MITM_BROWSER_CAPTURE_GATE` 从 pac-policy-profile-prefs-active/system-mutation-blocked 扩展到显式授权的浏览器/系统代理配置、验证和回滚。

## 源码布局

- [apps/ios](apps/ios)：iOS source tree governance placeholder，当前仅包含 README，定义未来 Swift package ownership、Package.swift ownership preflight、Package.swift manifest-only activation validation、source directory guard、`macos-26` source scan hook 和 no `Package.swift`/no Swift source/no Xcode project boundary。
- [apps/linux-cli](apps/linux-cli)：`networkcore-linux` CLI 入口的首批命令解析、`help` 命令表、配置读取边界、只读平台探测接线、`prepare-config` 运行层接线、`start` 原生 engine 前台接线和内置 `networkcore.adblock` MITM hook 注入、`install-sing-box` latest public engine 下载接线、`run-url` Shadowsocks URL 到 sing-box foreground local proxy 接线、`mitm status/diagnostics/certificate-plan/browser-plan` policy-only 状态、证书计划和浏览器捕获计划输出、`mitm certificate apply/rollback` certificate artifact lifecycle、`certificate_lifecycle` report、`mitm http-rewrite plan/preview` caller-provided plain HTTP rewrite preview、`http_rewrite` report、`mitm browser-capture plan/launch-plan/session-plan/launch/apply/rollback/verify/traffic-proof` manual launch-plan、脱敏会话计划、可选 `--target-url` dedicated profile 打开页面、proof target URL/traffic-proof command/default proof binding、`--proxy-scheme socks5` native plugin proxy mode、dedicated-profile launch、本地代理端点 verify、proof-log-token traffic proof 与 blocked report、前台 lifecycle host/interruption source、Unix OS signal source、interruption 后 runtime stop/release 源码合同和诊断输出。
- [crates/config-core](crates/config-core)：统一控制内核的首批纯配置解析、标准化和 subscription parser 服务，当前覆盖 schema/profile、最小 listener/node/route TOML 子集、subscription TOML `nodes`/`routes` 子集、单条 `ss://`、单条 `trojan://`/`vless://`/`vmess://` parser gates、Clash YAML `proxies` catalog import gate、sing-box JSON `outbounds` catalog import gate、Surge `[Proxy]` line catalog import gate、Loon `[Proxy]` line catalog import gate、Quantumult X `[server_local]` line catalog import gate、明文 proxy 链接列表和 base64 proxy 链接列表；Trojan/VLESS/VMess/Clash/sing-box JSON/Surge/Loon/Quantumult X 目前只进入 `SubscriptionDocument`/`NodeCatalog`，不代表 `run-url` 已支持 Trojan/VLESS/VMess/Clash/sing-box JSON/Surge/Loon/Quantumult X 运行。
- [crates/control-domain](crates/control-domain)：统一控制内核的首批领域类型与端口 trait。
- [crates/control-runtime](crates/control-runtime)：组合领域端口的首批纯运行层编排用例；subscription catalog runtime gate 已支持显式 inline `SubscriptionSource` 的 `NodeCatalog.nodes` 到 `RuntimeConfigRequest.nodes` handoff、重复 id 拒绝和 rules deferred 诊断，仍不执行远程/文件订阅或平台 mutation。
- [crates/engine-native](crates/engine-native)：原生代理执行内核的首批 adapter 合同、listener/node/route 图校验、native runtime handle 源码合同、loopback TCP listener 绑定/释放、runtime assembly plan、loopback TCP accept loop 受控关闭合同、service-owned runtime state 与 foreground lifecycle handoff 源码合同、accepted TCP connection 协议前置关闭诊断合同、SOCKS5 greeting 版本/认证方法读取诊断合同、SOCKS5 no-auth 方法选择/unsupported auth 方法拒绝诊断合同、SOCKS5 认证方法响应写入诊断合同、SOCKS5 命令头读取/unsupported command 拒绝诊断合同、SOCKS5 CONNECT 目标地址读取、CONNECT 到 rich MITM plugin plan 的 hook、browser capture CONNECT proof token 诊断、插件 `Reject` 到 SOCKS5 CONNECT failure 的应用、route/outbound 行为选择、SOCKS outbound CONNECT request frame 生成、SOCKS outbound TCP connection plan、SOCKS outbound TCP connection attempt、SOCKS outbound CONNECT request write、SOCKS outbound CONNECT response read、SOCKS outbound CONNECT response decision、SOCKS outbound CONNECT relay readiness、SOCKS outbound CONNECT data relay plan、SOCKS outbound CONNECT data relay execution、SOCKS outbound CONNECT client success response readiness、SOCKS outbound CONNECT client success response write plan、SOCKS outbound CONNECT client success response write、accept loop client success response 与有限 data relay 接线、未接入拒绝与 CONNECT failure response 写入诊断合同、配置拒绝和生命周期诊断。
- [crates/engine-singbox](crates/engine-singbox)：`sing-box` public engine adapter 的首个 source contract，当前覆盖 descriptor identity、官方 GitHub latest release metadata 解析、目标资产选择、`sha256:` digest 校验、`.tar.gz` 中只提取 `sing-box` 可执行文件、缓存路径、Shadowsocks node 到本地 `mixed` inbound JSON 渲染、foreground process runner 和稳定诊断；仍不提供 daemon/control socket、managed status/events/logs 或 reload。
- [crates/mitm-anixops-sys](crates/mitm-anixops-sys)：`mitm_anixops` v0.45.10-alpha C ABI 的 unsafe Rust FFI crate，当前编译 vendored C core 并验证 pinned version。
- [crates/mitm-policy](crates/mitm-policy)：`mitm_anixops` 的 safe wrapper 和 NetworkCore MITM plugin adapter，当前提供内置 `networkcore.adblock` 去广告插件包、manifest/permission gate、MITM decision、URL reject、rewrite plan、header/body/script/JQ guard 合同测试和 deferred mutation 诊断；Linux CLI 只通过 `mitm status/diagnostics/certificate-plan/browser-plan` 暴露 policy-only 状态、证书计划和浏览器捕获计划，不直接改写真实流量，也不提供 CA 安装、HTTPS 解密或浏览器/系统代理写入路径。
- [crates/platform-ios](crates/platform-ios)：iOS 平台能力 adapter 的首批纯 Rust source contract 实现，当前提供静态 snapshot 映射、Network Extension/VPN/embedded runtime/MITM certificate/shared storage probe、稳定 `platform.ios.*` 诊断 code 和合同测试，不包含 Swift/Xcode/Network Extension target 或签名配置。
- [crates/platform-linux](crates/platform-linux)：Linux 平台能力 adapter 的首批只读诊断映射、测试替身和 host probe 服务。
