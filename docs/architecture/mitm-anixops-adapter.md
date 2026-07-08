# mitm_anixops Adapter Design

本文件定义 `networkcore_AnixOps` 接入
`https://github.com/AnixOps/mitm_anixops` 的首版 adapter 边界。

评估时间：2026-07-08。

参考 `mitm_anixops` 版本：`v0.45.10-alpha`
(`a3ee0fca6376ddccc333bdfe06ac5b5e75ed23e0`)。

## 结论

`mitm_anixops` 可以作为 NetworkCore 的可移植 MITM 策略和插件兼容核心接入，但不能被描述为完整全平台网络引擎。

它当前提供的是 C ABI：

- 解析 AnixOps/Loon 风格 MITM、rewrite、script、argument 子集。
- 返回 MITM allow/deny/QUIC reject 决策。
- 返回 URL rewrite、header rewrite、body rewrite 和 script dispatch 结构化结果。
- 返回稳定 status message 和 last-error diagnostic。
- 保持 TLS、证书安装、HTTP 解析、压缩/chunk/body framing、JavaScript runtime 在 embedding adapter 之外。

因此 NetworkCore 的接入目标分两层：

- 短期：把 `mitm_anixops` 作为 `MitmPluginService` 的后端，验证插件配置、规则命中和诊断。
- 中期：等 `engine-native` 具备 HTTP/TLS MITM 数据面后，把 rewrite/script 结果接入真实请求/响应处理。

## 当前 NetworkCore 边界

当前可直接复用的 NetworkCore 边界：

- `control_domain::MitmPluginService`
- `control_runtime::MitmGateOrchestrator`
- `PlatformCapabilityStatus`
- `MitmCertificateStatus`
- `Diagnostic`
- `AuditEvent`

当前不能直接承载完整 rewrite 的边界：

- `PluginResult` 只有 `audits` 和 `diagnostics`，没有 request/response mutation 输出。
- `HttpEvent` 只有 `request_id`、`headers` 和 `body`，缺少 URL、method、phase、status、host、scheme 等 MITM rule matching 所需字段。
- `engine-native` runtime 当前 listener 只支持 `LocalTcp` 和 `Socks`。
- `engine-native` runtime 当前 outbound 只支持 `Protocol::Socks`。
- `platform-linux` 当前是只读探测服务，不安装或信任 MITM CA。
- macOS、Windows、iOS platform adapter 尚未落地。

## 仓库接入形态

源码接入前，应先固定 vendoring 策略。推荐路径：

```text
third_party/mitm_anixops
```

可选来源：

- git submodule，适合早期 review 和升级。
- git subtree，适合希望 CI 不依赖 submodule checkout 的阶段。
- release source archive，适合发布链路稳定后复现构建。

初期推荐 git submodule，但 CI 必须显式 checkout submodule。若不想修改 checkout 策略，应使用 subtree 或 source archive。

## Rust Crate 规划

后续源码增量应新增两个 crate：

```text
crates/mitm-anixops-sys
crates/mitm-policy
```

`crates/mitm-anixops-sys` 负责：

- 用 `cc` crate 编译 `third_party/mitm_anixops/src/mitm_anixops.c`。
- include `third_party/mitm_anixops/include`。
- 定义 `ANIXOPS_STATIC`。
- 暴露 unsafe `extern "C"` 绑定。
- 对照 `third_party/mitm_anixops/ci/abi_exports.txt` 维护 ABI allowlist 验证。

`crates/mitm-policy` 负责：

- 用 RAII wrapper 持有 opaque `anixops_engine_t`。
- 将 `anixops_status_t`、last error、line diagnostic 映射为 `DomainError` 和 `Diagnostic`。
- 将 certificate state 映射到 `MitmCertificateStatus`。
- 将 MITM、rewrite、header、body 和 script result 映射到 NetworkCore 领域类型。
- 实现 NetworkCore 的 MITM plugin adapter。

`Engine` wrapper 不得实现 `Sync`。`mitm_anixops` engine 内部不加锁，运行时共享必须由 adapter 通过 `Mutex`、per-worker engine 或 immutable snapshot 控制。

当前源码增量已新增 `crates/mitm-anixops-sys` 和 `crates/mitm-policy`：
前者通过 Git submodule 固定 `third_party/mitm_anixops` 到 `v0.45.10-alpha`
并暴露低层 C ABI；后者用 RAII wrapper 加载 `PluginPackage.source`，
实现 `AnixOpsMitmPluginService`，提供内置
`networkcore.adblock` alpha 去广告插件包，并把 0.45.10 的 URL rewrite、
named header rewrite、bounded header-list application、body rewrite chain、
script dispatch、JQ max-input guard 和 aggregated rewrite plan 映射为
NetworkCore stable Rust 类型。当前 `MitmPluginService` 仍只返回
audit/diagnostics，真实 request/response mutation 继续等待领域 mutation model
和 HTTP/TLS 数据面。

## Domain Model 变更门槛

在真实 rewrite 接入前，`control-domain` 需要新增 mutation 输出模型。

建议新增或扩展类型：

- `HttpMitmPhase`
- `HttpRequestContext`
- `HttpResponseContext`
- `MitmMutation`
- `UrlRewriteMutation`
- `HeaderMutation`
- `BodyMutation`
- `ScriptDispatch`
- `MitmPluginOutcome`

最低字段要求：

- URL、scheme、host、path、method。
- request/response phase。
- response status。
- headers。
- buffered body。
- body 是否已解压、是否可改写、是否截断。
- script tag、script path、argument、requires body。

`PluginResult` 继续保留 audit/diagnostics，但真实处理结果不能只靠 audit/diagnostics 表达。

## Runtime 接线阶段

说明：以下 Phase 1/2/3 是 MITM 接线内部阶段，不是 ROADMAP 的当前项目阶段。ROADMAP 当前阶段是
P4 Client And Platform Integration；P3 Runtime Capability Baseline 已完成。

### Phase 1: 领域 adapter 验证

目标：证明 `mitm_anixops` 能被 NetworkCore 作为插件策略服务调用。

范围：

- 新增 `mitm-anixops-sys` 和 `mitm-policy` crate。
- 从 `PluginPackage.source` 加载插件文本。
- 通过 `anixops_engine_load_config` 校验支持的规则子集。
- 用 `anixops_engine_copy_last_error` 生成稳定 diagnostic。
- 在 `MitmPluginService` adapter 中返回 audit/diagnostics。
- 内置 `networkcore.adblock` 插件包通过 `mitm_anixops` 规则加载、MITM host
  decision 和 URL reject rewrite 合同测试。

不做：

- 不接入真实网络流量。
- 不执行 JavaScript。
- 不改写 HTTP request/response。
- 不声明全平台 MITM 可用。

### Phase 2: mutation model

目标：让领域模型能表达 request/response 改写。

范围：

- 扩展 `HttpEvent` 或新增 HTTP MITM context。
- 扩展 `PluginResult` 或新增 `MitmPluginOutcome`。
- 覆盖 URL redirect/reject、header add/replace/delete、body replace、script dispatch。

### Phase 2B: Linux CLI MITM command gate

`MITM_CLI_COMMAND_GATE`

目标：提供用户可见但受门禁约束的 MITM 命令入口。

当前状态：

```text
mitm-cli-command-gate-status=partial-active
```

`networkcore-linux mitm status`、`networkcore-linux mitm diagnostics`、
`networkcore-linux mitm certificate-plan`、`networkcore-linux mitm browser-plan` 和
`networkcore-linux mitm browser-capture plan/launch-plan/session-plan/launch/apply/rollback/verify`
已接入 Linux CLI。它们通过
`mitm-policy` 加载内置 `networkcore.adblock` policy，输出 `mitm_status`
JSON 机器字段，并显式报告 browser hijack 为 deferred、
`MITM_CERTIFICATE_LIFECYCLE_GATE` plan-only、
`MITM_BROWSER_CAPTURE_GATE` plan-only/mutation-blocked 和
`MITM_HTTP_TLS_DATA_PLANE_GATE` blocked。`certificate-plan` 额外输出
`mitm_status.certificate_plan`，包含当前证书状态、计划步骤、blocked
operations 和 `mutation_ready=false`；`browser-plan` 额外输出
`mitm_status.browser_plan`，包含当前捕获状态、默认显式代理计划
`127.0.0.1:7890`、计划步骤、blocked operations 和 `mutation_ready=false`。
`browser-capture` 额外输出 `browser_capture` 机器字段；`launch-plan` 返回手动
dedicated-profile 浏览器启动命令模板、计划代理 URL 和已加载插件元数据，不启动浏览器或写入系统状态；
`session-plan <ss://url>` 返回脱敏订阅来源、选中节点、本地代理监听、`run-url <subscription-url>` 命令模板、
dedicated 浏览器命令、`verify --confirm` 命令和已加载插件元数据，不启动 `sing-box`、不启动浏览器或写入系统状态；
`launch --confirm` 通过 `BrowserCaptureProcessRunner` 启动带显式代理参数的 dedicated browser profile，
并输出 `LinuxBrowserCaptureLaunchReport`、pid、profile、proxy、命令参数和插件元数据；
`apply --confirm` 只记录 `BrowserCaptureAuthorization` 并返回 apply blocked，
`rollback --snapshot <path>` 只保留 `BrowserCaptureRollbackSnapshot` 路径并返回 rollback blocked，
`verify --confirm` 只探测计划本地代理端点 `http://127.0.0.1:7890` 是否可达；它不证明浏览器真实流量捕获、HTTPS MITM 或 rewrite 应用。未接线 endpoint probe 或更强 live capture probe 时仍返回 blocked。
该状态只代表命令面、策略诊断入口、证书生命周期计划、浏览器捕获计划、manual launch-plan、session-plan、dedicated-profile process launch 和 browser-capture blocked report 已存在，
不代表 HTTPS MITM、证书安装、系统代理/浏览器 policy 写入或真实流量改写已可用。

范围：

- 新增并继续扩展 `networkcore-linux mitm` 命令族，至少能输出 status、diagnostics、certificate-plan、browser-plan 和 unavailable/deferred 状态。
- 明确区分 policy-only、certificate-not-ready、data-plane-not-ready 和 ready 状态。
- 命令不得在 CA 和 HTTP/TLS 数据面未完成前宣称真实 HTTPS MITM 可用。
- JSON 输出必须包含稳定机器字段，便于后续客户端复用。

### MITM Gate: engine-native HTTP/TLS 数据面

`MITM_HTTP_TLS_DATA_PLANE_GATE`

目标：把策略 adapter 放进真实流量路径。

范围：

- 在 SNI 或 HTTP host 进入时调用 `anixops_mitm_evaluate`。
- 对 `ANIXOPS_MITM_REJECT_QUIC` 返回显式诊断，并由 platform/engine 拒绝或降级 QUIC。
- 在 HTTP request 解析后调用 URL/header/request-script 评估。
- 在 response headers/body buffering 和 decompression 后调用 response-header/body/script 评估。

仍由 NetworkCore 负责：

- TLS handshake。
- 动态 leaf certificate。
- CA install/trust detection。
- HTTP/1.1 parser。
- HTTP/2 frame parser。
- compression/chunk/body framing。
- JavaScript runtime。
- stream backpressure 和 body size limit。

### MITM Gate: 浏览器捕获 adapter

`MITM_BROWSER_CAPTURE_GATE`

目标：在证书生命周期和 HTTP/TLS 数据面具备后，提供显式授权、可回滚的浏览器流量捕获入口。

当前状态：

- `networkcore-linux mitm browser-plan` 已输出 `mitm_status.browser_plan`。
- `networkcore-linux mitm browser-capture plan/launch-plan/session-plan/launch/apply/rollback/verify` 已输出
  `browser_capture` manual launch-plan、session-plan、dedicated-profile launch report、本地代理端点 verify report 和 blocked report。
- 默认计划为显式代理 `127.0.0.1:7890`，仅用于机器可读计划和后续 UI/CLI 提示。
- `launch-plan` 只输出 dedicated-profile 浏览器启动命令模板、计划代理 URL 和 `networkcore.adblock`
  插件元数据，不启动浏览器、不写 profile、不写系统状态。
- `session-plan` 只输出脱敏订阅到本地代理、dedicated 浏览器和 verify 的命令计划，不启动 `sing-box`、不启动浏览器、不写 profile、不写系统状态。
- `launch --confirm` 只启动 dedicated browser process，不写 browser policy、system proxy、PAC、TUN、DNS、firewall 或 CA。
- 当前 gate 为 plan-only/mutation-blocked，不写入 browser policy、system proxy、PAC、TUN、DNS 或 firewall。
- [Linux MITM Browser Capture Source Contract](linux-mitm-browser-capture-source-contract.md)
  已固定 `mitm-browser-capture-source-contract-status=active`、
  `LinuxBrowserCaptureManualLaunch`、`LinuxBrowserCaptureSessionPlanRequest`、`LinuxBrowserCaptureSessionPlanReport`、`LinuxBrowserCaptureLaunchRequest`、`LinuxBrowserCaptureLaunchReport`、
  `BrowserCaptureProcessRunner`、`BrowserCaptureAuthorization`、`BrowserCaptureRollbackSnapshot`、
  launch-plan、session-plan、launch、apply/rollback/verify、显式授权、snapshot 和 rollback 边界。
- live browser capture probe、真实 apply 和真实 rollback 尚未实现；当前 verify/rollback
  命令只返回 blocked report，不读取或写入系统状态。

### Phase 4: 平台 adapter

`MITM_CERTIFICATE_LIFECYCLE_GATE`

Linux：

- 证书安装和 trust 状态探测。
- 显式用户授权。
- system trust store 变更的回滚设计。

macOS：

- Keychain trust 集成。
- 签名和 notarization。

Windows：

- CurrentUser/LocalMachine certificate store 策略。
- signed binary 和安装/卸载回滚。

iOS：

- Network Extension 内嵌运行。
- 用户显式安装并信任 CA。
- 默认拒绝远程任意脚本执行。
- 遵守 App Review 风险评估。

## CI/CD 验证要求

源码接入必须按阶段由 GitHub Actions 证明：

- Phase 1A：Rust workspace 包含 `mitm-anixops-sys`，Linux/macOS/Windows runner 能编译 vendored C core，并用 version FFI test 调用 `anixops_version()`。
- Phase 1B：新增 `mitm-policy`，用 safe wrapper tests 覆盖 config diagnostic、MITM decision、URL reject rewrite、内置 ad-block plugin package、manifest/permission gate 和 `MitmPluginService` deferred mutation diagnostic。
- Phase 1C：扩展 safe wrapper tests 覆盖 header rewrite、bounded header-list application、body rewrite chain、script dispatch、JQ max-input guard 和 aggregated rewrite plan；这些结果作为 safe wrapper 合同暴露，真实 traffic mutation 仍等待 Phase 2 mutation model。
- Phase 1D：ABI allowlist 与 `mitm_anixops/ci/abi_exports.txt` 一致，CI summary 显式输出 `mitm_anixops` adapter 检测状态。

iOS 只能在 iOS platform crate 和 Network Extension 设计出现后，通过 macOS runner 增加 Swift/Xcode 或 cargo check 验证。

## Upstream Upgrade Procedure

后续 `mitm_anixops` 发布新版时，NetworkCore 按以下顺序升级：

1. 读取 upstream release notes、`include/mitm_anixops.h` 和
   `ci/abi_exports.txt`，确认 tag、commit、ABI 新增/删除和默认依赖变化。
2. 移动 `third_party/mitm_anixops` submodule 到目标 tag，并在
   `.github/workflows/ci.yml`、本文件、source contract、README、TODO、ROADMAP
   和 CHANGELOG 中同步 tag/commit。
3. 先更新 `crates/mitm-anixops-sys` 的 unsafe ABI，使 Rust struct/function
   声明与 header 对齐；新增常量、enum、struct 和 extern function 必须能在
   CI 中由 version/contract test 触达。
4. 再更新 `crates/mitm-policy` safe wrapper，把新增 C ABI 映射为
   NetworkCore-owned Rust 类型和稳定 diagnostic/error code；不得把 upstream demo
   proxy shim 当作 NetworkCore production data plane。
5. 合同测试只验证 wrapper 能加载策略、生成 rewrite plan/header/body/script/JQ
   guard 结果和 deferred mutation 诊断；真实 HTTP/TLS mutation 仍必须等
   domain mutation model、engine data plane 和 platform certificate gate 通过。
6. 提交并推送后只用 GitHub Actions 的 policy、Rust format/lint/test/build 和
   dependency audit 结果判断是否通过；本机不得运行 build/test/package/release 验证。

## 不得宣称的能力

在 `MITM_HTTP_TLS_DATA_PLANE_GATE` 和对应平台 adapter 通过 CI/CD 之前，不得宣称：

- 全平台 MITM 已可用。
- iOS MITM 已可用。
- `engine-native` 已支持 HTTP/TLS MITM。
- `mitm_anixops` 负责 TLS、证书、HTTP parser 或 JavaScript runtime。
- `PluginResult` 已能表达完整 rewrite。

可以宣称：

- `mitm_anixops` 是 NetworkCore 可接入的 MITM 策略/plugin 兼容 C ABI core。
- NetworkCore 当前具备接入该 core 的领域端口雏形。
- 完整流量接入需要后续领域 mutation model、HTTP/TLS 数据面和平台 adapter。
