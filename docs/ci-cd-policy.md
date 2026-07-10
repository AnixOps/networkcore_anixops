# CI/CD Policy

## 总原则

本仓库采用 GitHub Actions 作为唯一测试、构建、编译、打包、发布验证环境。

本地环境的职责是：

- 编写代码
- 编写文档
- 修改配置
- 查看差异
- 提交和推送
- 触发和观察 GitHub Actions

本地环境不承担：

- 单元测试
- 集成测试
- 编译
- 打包
- 发布
- 任何形式的构建验证

## Workflow 分工

### CI

`.github/workflows/ci.yml` 是主验证入口。

它应覆盖：

- 治理文件存在性检查
- Roadmap、TODO、CHANGELOG 等规划治理文件检查
- 当前阶段 source of truth 检查，确保 README、ROADMAP、TODO 和架构文档把当前阶段固定为 P4 Client And Platform Integration，且 P3 只作为 completed baseline 或历史条目保留
- P4 backlog buckets 检查，确保订阅/客户端兼容、MITM 数据面和证书生命周期、浏览器捕获用户闭环三块待补能力在 README、ROADMAP、TODO、Linux CLI README、`mitm-policy` README 和相关 source contract 中保持同步
- 关键架构规格与接口草案文件检查
- 可插拔代理执行内核适配接口检查
- 公有执行内核优先与三层维护框架 ADR 检查
- `mitm_anixops` adapter 设计文件检查
- subscription catalog runtime orchestration design 检查
- subscription catalog runtime gate source contract 检查
- persistent subscription catalog source contract、schema version、explicit path、snapshot、redacted add/list/remove/select/update/rollback report、`CommandSubscriptionCatalogStore::add_source`/`list_sources`/`remove_source`/`select_source`/`update_source`/`rollback_catalog` and contract tests、以及 no default/remote/file fetch boundary 检查
- managed foreground session status source contract、schema version、explicit status record、recorded state、`liveness_verified=false`、`CommandManagedForegroundSessionStore::read_status` and contract test、以及 no PID/port/socket liveness、no daemon/control socket、no CLI/runtime control boundary 检查
- `mitm-anixops-sys` crate、submodule 固定和 Rust FFI version 测试检查
- `mitm-policy` safe wrapper、`networkcore.adblock` 内置去广告插件、`control-domain` `HttpMitmEvent`/`HttpMitmOutcome` rich mutation plan、`MitmPluginService::handle_http_mitm_event`、`engine-native` `NativeHttpMitmPluginHook`、native SOCKS5 CONNECT plugin reject 应用、native SOCKS5 CONNECT browser proof 诊断、plain HTTP live data plane、Linux CLI `native_proxy_engine_service_with_builtin_mitm_plugin`、Linux CLI `mitm_status`、`certificate_plan`、`certificate_lifecycle`、TLS CA certificate PEM/private key PEM artifact、`http_rewrite`、`browser_plan` 与 `browser_capture` 机器字段、manual launch-plan output、redacted session-plan output、dedicated-profile launch report、dedicated profile target URL、target URL proxy route verify、proof-log-token traffic proof、`--proxy-scheme socks5` native plugin proxy mode、MITM certificate artifact apply/rollback、dedicated profile CA PEM copy apply/rollback、MITM HTTP rewrite plan/preview、PAC/browser policy/profile prefs apply/rollback、planned/deferred mutation 诊断、当前用户可用性边界、`MITM_CLI_COMMAND_GATE` partial-active、`MITM_CERTIFICATE_LIFECYCLE_GATE` artifact-lifecycle-active/profile-trust-artifact-active/trust-mutation-blocked、`MITM_BROWSER_CAPTURE_GATE` pac-policy-profile-prefs-active/system-mutation-blocked、`MITM_HTTP_TLS_DATA_PLANE_GATE` plain-http-live-data-plane-active/tls-decryption-blocked 和 Rust 合同测试检查
- Linux MITM certificate lifecycle source contract、`LinuxMitmCertificateLifecycleReport`、`LinuxMitmCertificateArtifactRequest`、`LinuxMitmCertificateArtifactApplyOutcome`、`LinuxMitmCertificateArtifactRollbackOutcome`、`LinuxMitmCertificateTrustPlan`、`MitmCertificateArtifactStore`、`CommandMitmCertificateArtifactStore`、`MitmCertificateAuthorization`、`MitmCertificateRollbackSnapshot`、`handle_entrypoint_with_certificate_lifecycle_io`、`certificate_lifecycle`、`--cert-file`、`--key-file`、`--profile-trust-file`、`profile_trust_file_path`、`profile_trust_content`、`profile_trust_fingerprint`、`cli.linux.mitm.certificate.material.failed`、CA certificate PEM、private key PEM、dedicated profile CA PEM copy、certificate artifact snapshot、rollback、apply/rollback diagnostics 和 `MITM_CERTIFICATE_LIFECYCLE_GATE` artifact-lifecycle-active/profile-trust-artifact-active/trust-mutation-blocked 检查
- Linux MITM browser capture source contract、`LinuxBrowserCaptureManualLaunch`、`LinuxBrowserCaptureSessionPlanRequest`、`LinuxBrowserCaptureSessionPlanReport`、`LinuxBrowserCaptureLaunchRequest`、`LinuxBrowserCaptureLaunchReport`、`LinuxBrowserCaptureVerifyRequest`、`LinuxBrowserCaptureVerifyReport`、`LinuxBrowserCaptureTrafficProofRequest`、`LinuxBrowserCaptureTrafficProofReport`、`LinuxBrowserCapturePacRequest`、`LinuxBrowserCapturePacApplyOutcome`、`LinuxBrowserCapturePacRollbackOutcome`、`BrowserCaptureProcessRunner`、`BrowserCaptureEndpointProbe`、`BrowserCaptureTrafficProofProbe`、`BrowserCapturePacFileStore`、`BrowserCaptureAuthorization`、`BrowserCaptureRollbackSnapshot`、manual dedicated-profile launch-plan、redacted session-plan、可选 `--target-url` dedicated profile 打开页面、`proof_target_url`、`proof_connect_authority`、traffic-proof text CONNECT authority output、`networkcore_proof_token`、`MITM_BROWSER_CAPTURE_DEFAULT_PROOF_LOG_PATH`、`MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME`、`MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME`、`proxy_scheme`、`traffic_proof_command`、显式授权 dedicated-profile launch、显式授权 local proxy endpoint verify、target route verify、proof-log-token traffic proof、traffic-proof default proof binding、CONNECT endpoint proof token binding、proof token/proxy/CONNECT authority binding mismatch、`engine.native.runtime.http_mitm_connect_browser_proof_observed`、`--proxy-scheme socks5` native plugin proxy mode、PAC artifact snapshot、browser policy artifact、Firefox dedicated profile prefs、`--policy-file`、`--profile-prefs-file`、`profile_prefs_file_path`、`profile_prefs_content`、`cli.linux.mitm.browser_capture.policy.write_failed`、`cli.linux.mitm.browser_capture.profile_prefs.write_failed`、rollback、launch-plan ready diagnostics、session-plan ready/config diagnostics、launch authorization/started/failed diagnostics、verify authorization/proxy reachable/target reachable/proxy unreachable diagnostics、traffic-proof authorization/observed/missing/log-unreadable/binding-mismatch/blocked diagnostics、PAC apply ready/config/write diagnostics、PAC snapshot read/write diagnostics、rollback ready/failed diagnostics、apply/rollback/verify blocked diagnostics、`browser_capture` report、`traffic_proof_report` 和 `MITM_BROWSER_CAPTURE_GATE` pac-policy-profile-prefs-active/system-mutation-blocked 检查
- Linux MITM HTTP rewrite source contract、`NativePlainHttpMessage`、`NativePlainHttpRewriteApplication`、`NativePlainHttpRewriteReport`、`NativeExplicitHttpProxyRequest`、`NativePlainHttpProxyResponse`、`NativeTlsMitmFoundationReport`、`NativeTlsClientHelloObservationReport`、`NativeControlledTlsTerminationPlanReport`、`NativeHttpsRequestRewritePreviewReport`、`NativeHttpsResponseRewritePreviewReport`、`read_explicit_http_proxy_request`、`apply_http_mitm_outcome_to_live_plain_http_request`、`serialize_explicit_http_proxy_request_for_upstream`、`plan_explicit_http_connect_tls_mitm_foundation`、`observe_explicit_http_connect_tls_client_hello`、`plan_explicit_http_connect_controlled_tls_termination`、`plan_and_apply_https_request_rewrite_preview`、`plan_and_apply_https_response_rewrite_preview`、`write_http_connect_established_response`、`plan_and_apply_plain_http_mitm`、`apply_http_mitm_outcome_to_plain_http_message`、explicit HTTP proxy live plain HTTP request/response header/body/terminal action application、explicit HTTP CONNECT tunnel foundation、bounded TLS ClientHello/SNI observation、controlled TLS termination plan、caller-provided HTTPS request/response rewrite preview、content-type/body-size/buffering guard、script dispatch deferred、`ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_FOUNDATION_READY_CODE`、`ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CLIENT_HELLO_OBSERVED_CODE`、`ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CONNECT_TUNNEL_ESTABLISHED_CODE`、`ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_TERMINATION_PLAN_READY_CODE`、`ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_TERMINATION_DEFERRED_CODE`、`ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_REQUEST_REWRITE_PREVIEW_READY_CODE`、`ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_REQUEST_REWRITE_PREVIEW_DEFERRED_CODE`、`ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_REQUEST_REWRITE_SCRIPT_DEFERRED_CODE`、`ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_RESPONSE_REWRITE_PREVIEW_READY_CODE`、`ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_RESPONSE_REWRITE_PREVIEW_DEFERRED_CODE`、`ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_RESPONSE_REWRITE_SCRIPT_DEFERRED_CODE`、`LinuxMitmHttpRewriteReport`、`controlled_tls_termination_plan_ready`、`downstream_tls_termination_plan_ready`、`upstream_tls_forwarding_ready`、`https_request_rewrite_preview_ready`、`https_response_rewrite_preview_ready`、`https_response_rewrite_ready`、`content_type_guard_ready`、`body_size_limit_bytes`、`body_buffering_guard_ready`、`script_dispatch_ready`、`LinuxMitmHttpRewriteRequest`、`LinuxMitmHttpRewriteOutcomeReport`、`LinuxMitmHttpRewriteAuthorization`、`handle_mitm_http_rewrite_plan`、`handle_mitm_http_rewrite_preview`、`http_rewrite` report、`--url`、`--method`、`--phase`、`--status-code`、`--header`、`--body`、authorization/config/TLS blocked diagnostics、JSON/text output、`MITM_HTTP_TLS_DATA_PLANE_GATE` plain-http-live-data-plane-active/tls-decryption-blocked 检查
- third-party plugin onboarding process、source contract、pinned source、license/NOTICE、permission、safe wrapper、CI governance 和 upgrade procedure 检查
- 运行层编排设计文件检查
- iOS Network Extension design 检查
- iOS platform adapter source contract 检查
- iOS platform adapter crate README、workspace、源码类型和合同测试检查
- iOS Swift/Network Extension bridge design 检查
- iOS Swift/Xcode bridge source contract 检查
- iOS embedded runtime FFI boundary design 检查
- iOS MITM certificate lifecycle design 检查
- iOS entitlement/provisioning source contract 检查
- iOS App Review/privacy release readiness design 检查
- iOS Privacy Manifest source contract 检查
- iOS App Review manual confirmation source contract 检查
- iOS TestFlight/App Store Connect upload workflow source contract 检查
- iOS upload workflow activation validation contract 检查
- iOS Swift/Xcode source tree activation preflight contract 检查
- iOS Package.swift source ownership activation preflight contract 检查
- iOS Package.swift manifest-only activation validation contract 检查
- Linux artifact 发布前设计文件检查
- Linux platform adapter 设计文件检查
- Linux platform adapter crate README 和 Rust workspace 覆盖检查
- Linux CLI entrypoint 设计文件检查
- Linux CLI runtime wiring 设计文件检查
- Native engine listener/node 配置设计文件检查
- Linux native proxy engine start 设计文件检查
- config-core crate README、subscription parser source contract、Trojan/VLESS/VMess URL parser gates、Clash YAML parser gate、sing-box JSON parser gate、Surge proxy line parser gate、Loon proxy line parser gate、Quantumult X proxy/server line parser gate 和 Rust workspace 覆盖检查
- engine-native crate README 和 Rust workspace 覆盖检查
- engine-singbox crate README、latest release download source contract、checksum/extraction diagnostics、subscription URL to sing-box run source contract、Linux CLI `install-sing-box`/`run-url`/`help` 覆盖检查
- Linux CLI crate README 和 Rust workspace 覆盖检查
- Linux CLI artifact 安装、卸载与回滚设计文件检查
- Linux package artifact manifest 设计文件检查
- Linux artifact license/NOTICE confirmation source contract 检查
- Linux artifact release state consistency 检查，确保 README、ROADMAP、TODO、CHANGELOG、
  release strategy、license/NOTICE contracts、manual marker、CI governance 和 release workflow
  都保持 `linux-artifact-release-state=confirmed-release-path`
- Alpha Release Feature Matrix 检查，确保 README、ROADMAP、TODO、Release Strategy 和 alpha/rc/stable
  版本能力索引同步记录已发布 `v0.1.0-alpha.1` 到 `v0.1.0-alpha.20`、`v0.1.0-rc.1`、`v0.1.0` 以及
  `v0.1.1-alpha.1`、`v0.1.1-alpha.2`、`v0.1.1-alpha.3` Trojan/VLESS/VMess URL parser gates、
  Clash YAML parser gate、sing-box JSON parser gate、Surge proxy line parser gate、Loon proxy line parser gate
  和 Quantumult X proxy/server line parser gate，以及已拍板的
  `v0.1.0` Linux-only explicit HTTPS rewrite preview、`v0.1.1` Windows CLI artifact/订阅兼容、
  `v0.1.2` managed lifecycle、JavaScript script dispatch、system trust store mutation 和
  system proxy mutation 规划边界
- Release CI success source contract 检查
- Linux package runner/toolchain/target contract 检查
- Linux package archive staging contract 检查
- Linux package checksum/manifest checksum contract 检查
- Linux package publish/upload boundary contract 检查
- Linux package signing/attestation policy binding contract 检查
- Linux package release notes/rollback policy binding contract 检查
- Linux package publish eligibility aggregate contract 检查
- Linux package license/NOTICE transition validation contract 检查
- Linux package release CI gate activation validation contract 检查
- Release CI gate execution validation contract 检查
- Release CI gate API implementation plan 检查
- Linux package artifact job preflight validation contract 检查
- Linux package artifact build command validation contract 检查
- Linux package artifact staging file validation contract 检查
- Linux package artifact archive creation validation contract 检查
- Linux package artifact checksum execution validation contract 检查
- Linux package artifact manifest generation validation contract 检查
- Linux package artifact manifest checksum validation contract 检查
- Linux package workflow artifact bundle upload validation contract 检查
- Linux package artifact attestation execution validation contract 检查
- Linux package release notes/rollback execution validation contract 检查
- Linux package publish eligibility execution validation contract 检查
- Release workflow Linux artifact readiness gate 检查
- Release workflow Windows CLI artifact package/publish gate 检查，确保 `windows-cli-artifact-readiness`
  验证 `apps/windows-cli` source identity、`package-windows`、`attest-windows`、Windows release notes/rollback
  gate、Windows publish eligibility gate 和 system mutation blocked marker，且 service、driver、installer、
  system proxy mutation、system trust store mutation、JavaScript script dispatch 和 managed lifecycle 仍 blocked
- Release workflow Linux artifact manifest output summary 检查
- Alpha placeholder release version policy、Windows manual smoke 测试清单、confirmed marker 与 release placeholder/summary 输出检查
- 架构决策记录检查
- Linux、macOS、Windows 基础工作区检查
- Go 代码出现后的 Go 构建与测试
- Rust 代码出现后的 Rust 构建与测试
- Rust 代码出现后的依赖安全扫描
- Node 代码出现后的 Node 构建与测试
- Swift、Xcode 或 iOS 代码出现后的 Apple 平台验证

CI summary job 必须显式输出 Go、Rust、Node、Swift、Apple 项目检测开关，写入 GitHub Step Summary 表格，并门禁已启用的关键结果；当检测到 Rust workspace 时，summary 必须同时检查 Rust build/test 矩阵和 Rust dependency security audit；当检测到 Go、Node、Swift 或 Apple 项目时，summary 必须检查对应语言或平台 job。

### Release

`.github/workflows/release.yml` 是发布入口。

发布规则：

- 只能通过 tag 或 `workflow_dispatch` 触发。
- 不允许在本机打包 release artifact。
- 产物必须由 GitHub-hosted runner 或后续配置的受控 runner 生成。
- 真实平台产物加入前必须满足 [Release Strategy](release-strategy.md) 中定义的门禁、矩阵和回滚策略。
- 首个 Linux CLI artifact 加入前必须满足安装、卸载与回滚设计，且继续由 GitHub Actions 生成、校验和发布。
- release policy job 必须检查版本格式与触发来源一致性；允许稳定版本、`alpha.N` 和 `rc.N` 预发布版本；`workflow_dispatch` placeholder release 必须从 `main` 分支发起，tag release 的版本必须与 tag 名一致。
- release workflow 必须包含 `release-ci-gate` job，使用 `actions: read` 自动读取 `main` 上同 commit 的成功 CI 结果，校验 `CI summary` job，并输出 CI run/source 字段合同、release CI gate activation validation contract、release CI gate execution validation contract 和 release CI gate API implementation active 字段。
- `package-linux`、`package-windows`、`attest-linux`、`attest-windows`、`post-release-summary`、`windows-release-summary`、`publish-eligibility-gate`、`windows-publish-eligibility-gate` 和 `publish-github-release` 可以在 workflow 中定义，但必须全部受 GitHub Actions gates 约束：`linux-artifact-readiness` 必须在 `docs/manual-intervention.md` 的 license/NOTICE marker 为 `confirmed` 前失败，`windows-cli-artifact-readiness` 必须验证 `apps/windows-cli` source identity 和 system mutation blocked marker，`publish-github-release` 只能在 tag 触发、同 commit CI 成功、checksum/manifest/attestation/release notes/rollback/publish eligibility 全部通过后上传 release assets。
- placeholder 阶段必须包含 `release-artifact-contract` job，记录首个真实 artifact job 的 checksum 算法和输出字段契约。
- placeholder 阶段必须包含 `release-signing-contract` job，记录真实平台 artifact 发布前必须声明签名或 attestation 策略。
- placeholder 阶段必须包含 `release-rollback-contract` job，记录真实 artifact 发布说明必须输出的回滚字段。
- `linux-artifact-readiness` job 必须检查 Linux CLI 源码、platform adapter、native listener/node 配置设计、foreground stop/release 源码与合同测试、artifact manifest 合同设计、license/NOTICE confirmation source contract、Linux package license/NOTICE transition validation contract、release CI success source contract、Linux package release CI gate activation validation contract、release CI gate execution validation contract、release CI gate API implementation plan、Linux package artifact job preflight validation contract、Linux package artifact build command validation contract、Linux package artifact staging file validation contract、Linux package artifact archive creation validation contract、Linux package artifact checksum execution validation contract、Linux package artifact manifest generation validation contract、Linux package artifact manifest checksum validation contract、Linux package workflow artifact bundle upload validation contract、Linux package artifact attestation execution validation contract、Linux package release notes/rollback execution validation contract、Linux package publish eligibility execution validation contract、Linux package runner/toolchain/target contract、Linux package archive staging contract、Linux package checksum/manifest checksum contract、Linux package publish/upload boundary contract、Linux package signing/attestation policy binding contract、Linux package release notes/rollback policy binding contract、Linux package publish eligibility aggregate contract、安装/回滚设计和 license/NOTICE 人工确认记录；若 marker 仍为 pending，必须失败且不得进入构建、打包、上传或发布。
- `package-linux` 必须在 GitHub Actions 中安装 Rust stable/minimal toolchain、生成 lockfile、使用 `cargo build --locked --release --package networkcore-linux --bin networkcore-linux --target x86_64-unknown-linux-gnu` 构建 Linux CLI，生成单顶层目录 tarball、archive sha256、manifest JSON 和 manifest sha256，并通过 `actions/upload-artifact` 上传仅包含这四个文件的同 run bundle。
- `attest-linux` 必须从同一 run 的 workflow artifact bundle 下载四个文件，重新校验 checksum，并使用 GitHub artifact attestation 证明 archive、archive checksum、manifest 和 manifest checksum；job 权限必须包含 `contents: read`、`id-token: write` 和 `attestations: write`。
- `publish-eligibility-gate` 必须聚合 license/NOTICE、同 commit CI、runner/toolchain、archive staging、checksum/manifest、artifact manifest、publish/upload、signing/attestation 和 release notes/rollback；只有输出 `package_publish_eligibility_status=eligible` 后，tag 触发的 `publish-github-release` 才能创建 GitHub Release 并上传 Linux assets。
- placeholder 阶段必须包含 `ios-upload-readiness` job，检查 iOS upload workflow activation validation contract、iOS Swift/Xcode source tree activation preflight contract、iOS Package.swift source ownership activation preflight contract、iOS Package.swift manifest-only activation validation contract、`apps/ios/README.md` governance placeholder、`ios-upload-workflow` pending/blocked marker、protected environment/manual approval blocked 状态、App Store Connect API secret status not-read-blocked、source tree preflight、Package.swift ownership preflight、Package.swift manifest-only activation blocked 输出、archive/export/upload/submission blocked 输出，且不得读取 secret、定义真实 iOS upload job 或生成 iOS release asset。
- placeholder 阶段必须通过 release placeholder 和 release summary job 显式输出发布来源、policy、release-ci-gate、release CI success source contract、release CI gate activation validation contract、release CI gate execution validation contract、release CI gate API implementation plan、Linux package artifact job preflight validation contract、Linux package artifact build command validation contract、Linux package artifact staging file validation contract、Linux package artifact archive creation validation contract、Linux package artifact checksum execution validation contract、Linux package artifact manifest generation validation contract、Linux package artifact manifest checksum validation contract、Linux package workflow artifact bundle upload validation contract、Linux package artifact attestation execution validation contract、Linux package release notes/rollback execution validation contract、Linux package publish eligibility execution validation contract、artifact contract、signing contract、rollback contract、Linux artifact readiness、Linux foreground stop/release contract、Linux artifact manifest contract、Linux artifact manifest output fields、Linux package runner/toolchain/target contract、Linux package archive staging contract、Linux package checksum/manifest checksum contract、Linux package publish/upload boundary contract、Linux package signing/attestation policy binding contract、Linux package release notes/rollback policy binding contract、Linux package publish eligibility aggregate contract、Linux package license/NOTICE transition validation contract、Linux artifact license/NOTICE source contract 与 status、Alpha Windows manual smoke 测试清单与 confirmed 状态、placeholder、artifact 状态和后续 artifact 门禁。
- 同一 release placeholder 和 release summary 还必须输出 iOS Swift/Xcode source tree activation preflight contract、iOS Package.swift source ownership activation preflight contract、iOS Package.swift manifest-only activation validation contract、`apps/ios` README placeholder、`Package.swift`、Package.swift target ownership、manifest-only source scan、target list verification、source directory guard、Xcode project、Network Extension target、`PrivacyInfo.xcprivacy`、entitlement/provisioning、`macos-26` source scan、Swift package validation hook、upload workflow enabled marker、iOS upload workflow activation validation contract、manual marker、protected environment、manual approval、App Store Connect API secret status、archive/export、TestFlight upload、App Store upload、App Review submission、build processing check 和 iOS release asset 的 blocked placeholder 状态。

## 多平台目标

首期 CI/CD 目标平台：

- `ubuntu-latest`
- `macos-26`
- `windows-latest`

iOS Apple SDK、Swift/Xcode、archive/export、签名、TestFlight、App Store Connect 和 App Review submission 验证只允许在 macOS runner 中执行。纯文档、manual marker 和 release placeholder 的 repository governance static gate 可以在 `ubuntu-latest` 执行，但不得读取 secret、运行 Apple 工具链或生成 iOS artifact。为优先支持最新 Apple 平台能力，真实 Apple 平台验证默认使用 `macos-26`；如 GitHub hosted runner 暂不可用或特定工具链存在兼容问题，必须在 GitHub Actions 日志中确认后再调整。涉及签名、证书、Provisioning Profile 的内容必须使用 GitHub Secrets 或 Apple 官方流程，不得写入仓库。

iOS Network Extension 当前只允许先做 design、source contract 和 static governance 检查；Swift/Network
Extension bridge design 只定义 Apple SDK 事实如何去敏后传入 `platform-ios` snapshot，Swift/Xcode bridge
source contract 只定义后续 Swift package、Network Extension target、FFI/DTO 文件布局、`macos-26` 验证入口
和 signing/provisioning secret 禁止提交规则，embedded runtime FFI boundary design 只定义后续 Rust
staticlib/XCFramework、C ABI symbol、ABI version negotiation、owned string/buffer、panic/error mapping 和
`macos-26` 验证入口，MITM certificate lifecycle design 只定义后续 CA generation、installation prompt、
user trust confirmation、fingerprint/expiration/revocation 检测、`CertificateTrustState` 映射和
`macos-26` 验证入口，entitlement/provisioning source contract 只定义后续 `.entitlements`、App ID、
Network Extension capability、Provisioning Profile、GitHub Secrets、signing asset redaction 和 `macos-26`
验证入口，App Review/privacy release readiness design 只定义后续 Privacy Manifest、`PrivacyInfo.xcprivacy`、
App Privacy disclosure、privacy policy、App Review Notes、VPN compliance、TestFlight/App Store Connect
manual intervention 和 `macos-26` 静态门禁，Privacy Manifest source contract 只定义后续 `PrivacyInfo.xcprivacy`、
`NSPrivacyCollectedDataTypes`、`NSPrivacyAccessedAPITypes`、Required Reason API、App Privacy answer source、
third-party SDK privacy manifest、SDK signature 和 `macos-26` 静态验证入口，App Review manual confirmation
source contract 只定义 App Privacy answers、privacy policy URL、App Review Notes、demo account、review attachment、
VPN compliance marker、TestFlight group、App Store Connect app record、export compliance、beta app review、
App Review submission、manual confirmation marker 和 `macos-26` 静态门禁，TestFlight/App Store Connect upload
workflow source contract 只定义 archive/export、App Store Connect API、TestFlight group、manual approval、
App Review submission gate、protected environment、build processing status 和 `macos-26` 静态门禁，iOS upload workflow
activation validation contract 只定义 release workflow `ios-upload-readiness` blocked placeholder、release placeholder/summary
字段、manual marker 读取、protected environment/manual approval blocked 状态、App Store Connect API secret status
not-read-blocked、archive/export/upload/submission blocked 输出和 GitHub Actions 静态门禁，iOS Swift/Xcode source tree
activation preflight contract 当前只允许 `apps/ios/README.md` governance placeholder，并定义未来 `apps/ios` layout、
`Package.swift`/Xcode project、Network Extension target、`PrivacyInfo.xcprivacy`、entitlement/provisioning、
`macos-26` source scan、upload workflow enabled marker 前置条件和 release/upload blocked 输出，不引入 Rust FFI crate、
Swift/Xcode project、Network Extension target、configuration profile、CA certificate、private key、真实 entitlement、
PrivacyInfo.xcprivacy、ExportOptions.plist、`.ipa`、`.xcarchive`、`.xcresult`、dSYM bundle、签名、
TestFlight upload、App Store upload、App Review submission 或 release asset。Package.swift source ownership activation
preflight contract 当前只定义 `apps/ios/Package.swift` 引入前的 target ownership、
source directory guard、no Swift source until package gate、`macos-26` Swift package validation hook、Xcode project blocked、
upload workflow enabled marker blocked 和 release/upload blocked 输出，不引入真实 `Package.swift`、Swift source、
Swift/Xcode project、Network Extension target、签名、archive/export、upload 或 iOS release asset。Package.swift manifest-only
activation validation contract 当前只定义未来独立提交引入 `apps/ios/Package.swift` 前的 manifest-only source scan、
target list verification、no Swift source before source gate、`macos-26` Swift package validation hook、Xcode project blocked、
upload workflow enabled marker blocked 和 `ios-package-swift-manifest-only-*` blocked 输出，不引入真实 `Package.swift`、
Swift source、Swift/Xcode project、Network Extension target、签名、archive/export、upload 或 iOS release asset。出现 Swift、Xcode project、
Network Extension target、FFI runtime、certificate lifecycle source、entitlement/provisioning source、
Privacy Manifest source、App Review manual confirmation source、iOS upload workflow activation source 或签名验证后，
相关 `cargo build`、`swift build`、`swift test`、`xcodebuild`、archive/export、签名、TestFlight、App Store Connect
或 App Review submission 验证仍只能在 GitHub Actions 或 Apple 官方平台执行。

## 内核与客户端演进

后续出现具体代码栈时，应把验证规则加入 GitHub Actions：

- Go 内核：`go test ./...`、`go build ./...`
- Rust 内核：`cargo fmt --all -- --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace --all-targets`、`cargo build --workspace --all-targets`、`cargo generate-lockfile`、`cargo audit`
- Node 或 Web 客户端：`npm test`、`npm run build`
- Swift 或 iOS 客户端：`swift test`、`swift build`、`xcodebuild`

这些命令只能在 GitHub Actions 中运行。

## 人工介入边界

允许人工介入的事项：

- 首次创建 GitHub 仓库或配置远端
- 首次推送 bootstrap 文件
- GitHub CLI 登录或授权
- Apple Developer 账号、证书、Provisioning Profile、App Store Connect 配置
- App Store Connect App Privacy 问卷、Privacy Manifest/Required Reason API review、隐私政策 URL、App Review Notes、TestFlight group 和 VPN compliance 材料
- iOS archive/export、App Store Connect API、protected environment、manual approval、build processing 和 App Review submission gate 确认
- GitHub Secrets 配置
- 第一次确认 GitHub Actions 权限
- Linux artifact license/NOTICE 文本确认

人工完成后，应继续由 CI/CD 自动推进。
