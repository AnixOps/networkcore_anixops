# Linux CLI Entrypoint Design

本文件定义首个 Linux 可运行入口进入源码前必须遵守的命令、配置加载、启动/停止、状态查询和诊断边界。它承接 [Linux Platform Adapter Design](linux-platform-adapter.md)、[Control Runtime Orchestration Design](control-runtime-orchestration.md)、[Linux CLI Runtime Wiring Design](linux-cli-runtime-wiring.md) 和 [Linux Artifact Pre-Release Design](linux-artifact-pre-release-design.md)，用于约束后续 `networkcore-linux` CLI 不越过领域、运行层和平台 adapter 边界。

评估时间：2026-07-06。

P4 current stage source of truth: Linux CLI work is now P4 Client And Platform
Integration. P3 Runtime Capability Baseline is completed history. The CLI must
keep the current P4 backlog buckets visible: subscription/client compatibility,
MITM data plane plus certificate lifecycle, and browser capture user flow
completion. References to P3 in older completed entries are audit history only;
new CLI scope, release notes and source contracts must describe the repository
as P4.

## 目标

- 定义未来 `networkcore-linux` CLI 的首批命令语义和输出契约。
- 明确 CLI 如何组合 `control-runtime`、Linux platform adapter、配置端口和代理引擎端口。
- 约束配置读取、启动、停止、状态查询和诊断输出的最小边界。
- 为后续 Linux source crate 和 release artifact 提供源码前置设计。

## 非目标

- CLI 入口本身不实现会修改系统状态的 Linux 探测、daemon 控制、服务安装或 release packaging；release artifact 只能由 GitHub Actions release workflow 生成。
- 不在本机运行、构建、测试、打包或试用 CLI。
- 不定义 daemon、systemd unit、installer、shell completion、TUI、GUI 或 release asset。
- 不自动修改 TUN、路由、DNS、防火墙、证书信任或服务管理配置。

## 架构位置

CLI 作为应用入口层存在，当前首个源码边界是 `apps/linux-cli`。依赖方向必须保持：

1. CLI 依赖 `control-runtime`，调用运行层用例。
2. CLI 依赖后续 Linux adapter crate，获取 `PlatformCapabilityService` 实现。
3. CLI 依赖配置、代理引擎和 MITM 插件的 adapter 或测试替身。
4. CLI 不把 Linux 文件系统、capability、systemd、DNS 管理器或证书命令细节传入 `control-domain` 或 `control-runtime`。
5. CLI 不绕过 `RuntimeOrchestrator` 或 `MitmGateOrchestrator` 直接启动平台代理能力。

首个 CLI 源码保持单一二进制入口，优先验证配置加载、能力诊断和运行层编排，避免提前引入 daemon 或安装器复杂度。

## 命令面

首批命令按保守顺序设计：

| 命令 | 初始语义 | 首版限制 |
| --- | --- | --- |
| `networkcore-linux version` | 输出 CLI、workspace、commit 或构建元数据 | 元数据必须由 GitHub Actions 注入或从 crate 版本读取 |
| `networkcore-linux capabilities` | 输出 Linux platform adapter 的能力状态和诊断 | 只读探测，不修改系统状态 |
| `networkcore-linux prepare-config --config <path>` | 读取配置并调用 `prepare_config`，输出标准化结果或诊断 | 不写回配置文件，不迁移落盘 |
| `networkcore-linux start --config <path>` | 前台启动 runtime，用当前进程持有生命周期 | 不默认 daemonize，不安装服务，不后台运行 |
| `networkcore-linux stop` | 描述当前首版停止能力边界 | 没有 daemon/control socket 前返回稳定不可用诊断 |
| `networkcore-linux status` | 输出当前进程可见的平台、配置或 runtime 状态 | 没有 daemon/control socket 前不得假装能读取后台状态 |
| `networkcore-linux diagnostics` | 输出聚合诊断，便于 CI 日志、用户排错和后续 UI 消费 | 不读取敏感配置值，不输出密钥 |
| `networkcore-linux mitm status` / `networkcore-linux mitm diagnostics` / `networkcore-linux mitm certificate-plan` / `networkcore-linux mitm browser-plan` | 输出 MITM policy-only 状态、插件策略加载状态、证书生命周期计划、浏览器捕获计划和 deferred gate 诊断 | `mitm-cli-command-gate-status=partial-active`；`MITM_CERTIFICATE_LIFECYCLE_GATE` 仍 plan-only，`MITM_BROWSER_CAPTURE_GATE` 为 pac-artifact-active/system-mutation-blocked；不生成 CA，不解密 HTTPS，不写入浏览器/系统代理 |
| `networkcore-linux mitm browser-capture plan/launch-plan/session-plan/launch/apply/rollback/verify/traffic-proof` | 输出浏览器捕获 source contract report、manual dedicated-profile launch templates、脱敏订阅到本地代理/浏览器/verify session plan、可选 target URL、dedicated-profile launch report、本地代理端点/target route verify report、proof-log-token traffic proof report、PAC artifact apply/rollback report、显式授权记录、snapshot 路径记录和 blocked diagnostics | `session-plan <ss://url>` 只输出脱敏命令计划，可通过 `--target-url <url>` 把目标页面写入 dedicated browser command 和 verify command，不启动 `sing-box` 或浏览器；`launch --confirm` 只通过注入 runner 启动带显式代理参数的 dedicated browser profile，可把 target URL 作为浏览器参数打开；`verify --confirm` 只通过注入 endpoint probe 探测计划本地代理端点，传入 `--target-url <url>` 时只探测目标 URL 代理通路；`traffic-proof --confirm --proof-token <token> --proof-log <path>` 只通过注入 proof probe 读取 operator-provided proof log 并检查 token；`apply --confirm --pac-file <path> --snapshot <path>` 只写 operator-provided NetworkCore PAC artifact 和 rollback snapshot，`rollback --snapshot <path>` 只回滚该 PAC artifact；不写系统代理、browser policy、system PAC、TUN、DNS、firewall 或 CA 状态 |

首个源码增量已实现命令骨架和测试替身；`capabilities`、`status`、`diagnostics`、`mitm status/diagnostics/certificate-plan/browser-plan` 和 `mitm browser-capture plan/launch-plan/session-plan/launch/apply/rollback/verify/traffic-proof` 已通过 `PlatformCapabilityService` 接入 `HostLinuxReadOnlyProbe`。`certificate-plan` 只输出当前证书状态、计划步骤、blocked operations 和 `mutation_ready=false`；`browser-plan` 只输出当前捕获状态、默认显式代理计划 `127.0.0.1:7890`、计划步骤、blocked operations 和 `mutation_ready=false`；`browser-capture` 输出 `browser_capture` report、manual launch templates、`LinuxBrowserCaptureSessionPlanReport`、`LinuxBrowserCaptureLaunchReport`、`LinuxBrowserCaptureVerifyReport`、`LinuxBrowserCaptureTrafficProofRequest`、`LinuxBrowserCaptureTrafficProofReport`、`LinuxBrowserCapturePacRequest`、`BrowserCapturePacFileStore`、可选 target URL、`probe=http-connect-target` target route verify、`probe=proof-log-token` traffic proof、PAC artifact apply/rollback、`BrowserCaptureAuthorization` 和 `BrowserCaptureRollbackSnapshot` 边界。代理引擎执行、daemon/control socket、CA mutation lifecycle、browser/system proxy mutation、browser hijack、system PAC 安装和任何会修改系统状态的 Linux 能力必须等对应 adapter 设计和 CI 验证完成后再接入。

## 配置加载边界

配置加载必须显式、可诊断、可测试：

- `--config <path>` 对需要配置的命令必须显式提供，首版不隐式扫描多个系统路径。
- 允许后续增加 `--stdin`，但首版不要求支持。
- CLI 可以读取用户指定文件并传递原始内容给 `ConfigurationService`；schema 校验、迁移和标准化仍由领域/运行层端口处理。
- 不在 `prepare-config` 阶段写回文件，不自动创建默认配置，不自动迁移原文件。
- 配置错误必须输出 `Diagnostic` 和 `DomainError` 的稳定 code。
- 日志和诊断不得输出 token、密码、私钥、证书私钥或完整订阅 URL secret。

推荐 CLI 诊断：

| code | severity | 含义 |
| --- | --- | --- |
| `cli.linux.config.path_missing` | Error | 需要配置文件但未提供 `--config` |
| `cli.linux.config.read_failed` | Error | 配置文件无法读取 |
| `cli.linux.config.empty` | Error | 配置内容为空 |
| `cli.linux.config.secret_redacted` | Info | 输出中已隐藏敏感字段 |

## 启动边界

`start` 命令只允许通过运行层进入 runtime：

1. 读取配置。
2. 调用 Linux platform adapter 获取能力状态。
3. 调用 `RuntimeOrchestrator::prepare_config` 或等价用例。
4. 调用代理引擎 adapter 的配置校验。
5. 在平台、配置和引擎均允许后启动 runtime。
6. 聚合平台、配置、引擎和插件诊断。

首版 `start` 必须是前台模式：

- 不 fork、不 daemonize、不写 systemd unit。
- 不自动修改 DNS、路由、防火墙或证书信任。
- 不要求 root；如果缺少权限，返回 platform adapter 诊断并退出。
- 收到进程信号或可注入 interruption 时走当前进程内 runtime stop 用例；该路径只释放本次 `start` 持有的 runtime，不承诺后台生命周期。

推荐 CLI 诊断：

| code | severity | 含义 |
| --- | --- | --- |
| `cli.linux.start.platform_denied` | Error | 平台能力阻止启动 |
| `cli.linux.start.config_denied` | Error | 配置校验阻止启动 |
| `cli.linux.start.engine_denied` | Error | 代理引擎校验或启动阻止运行 |
| `cli.linux.start.foreground_only` | Info | 当前版本只支持前台运行 |
| `cli.linux.start.runtime_stop_failed` | Error | 前台 interruption 后当前进程内 runtime stop 失败 |

## 停止与状态边界

停止和状态查询必须避免虚假后台控制能力：

- 在没有 daemon、PID file、local socket 或 control API adapter 前，`stop` 不能声称可以停止其他进程。
- 首版 `stop` 可以返回 `cli.linux.stop.unavailable_without_daemon`，并说明当前只支持前台进程内停止。
- `status` 可以输出平台能力、配置预检结果或当前进程 runtime 状态。
- `status` 不应扫描任意系统进程并推断运行状态。
- 后续 daemon/control socket 设计完成前，不定义跨进程 stop、reload 或 status 协议。

推荐 CLI 诊断：

| code | severity | 含义 |
| --- | --- | --- |
| `cli.linux.stop.unavailable_without_daemon` | Error | 没有 daemon/control API，不能停止后台实例 |
| `cli.linux.status.no_runtime_context` | Warning | 当前命令没有可读取的 runtime 上下文 |
| `cli.linux.status.platform_only` | Info | 状态输出仅包含平台或配置预检信息 |
| `cli.linux.status.control_api_required` | Warning | 需要后续 control API adapter 才能读取后台状态 |

## 输出与退出码

CLI 输出必须适合人读和自动化：

- 默认输出可以是简洁文本；必须预留 `--format json` 输出结构化结果。
- JSON 输出必须包含 `ok`、`command`、`diagnostics`，有 runtime 结果时包含 `platform` 和 `engine_status`；MITM 状态命令必须包含 `mitm_status`，browser-capture 命令必须包含 `browser_capture`。
- 错误输出必须带稳定 code，不依赖非结构化文本判断。
- `--quiet` 和 `--verbose` 可后续加入，但不得改变退出码语义。

建议退出码：

| code | 含义 |
| --- | --- |
| `0` | 命令成功 |
| `1` | 通用失败或未知错误 |
| `2` | 参数或配置读取错误 |
| `3` | 配置校验失败 |
| `4` | 平台能力拒绝 |
| `5` | 代理引擎拒绝或运行失败 |
| `6` | 当前命令在首版不可用 |
| `130` | 前台运行被用户或平台中断 |

## GitHub Actions 验证边界

CLI 源码出现时，验证必须只在 GitHub Actions 中执行：

- Rust format、lint、test、build 和 dependency audit 必须覆盖 CLI crate。
- CLI 参数解析、配置读取失败、平台拒绝、stop 不可用、status 无 runtime 上下文和 JSON 输出必须有测试。
- 不在本机运行 CLI 命令验证行为。
- 真实 Linux artifact job 加入前，CI summary 必须能证明 CLI crate、platform adapter 和 packaging 前置 job 均通过。

## 当前源码映射

当前 `apps/linux-cli` 已提供首批源码边界：

- `networkcore-linux` package 和同名二进制入口。
- `LinuxCliCommand`、`OutputFormat`、`LinuxCliResponse` 和 exit code 映射。
- `ConfigReader` 边界，用测试替身覆盖配置路径缺失、读取失败和空配置。
- `handle_prepare_config` 与 `handle_start` 通过 `RuntimeOrchestrator` 进入运行层，不绕过领域端口。
- `ForegroundLifecycleHost`、`ForegroundLifecycleRequest`、`ForegroundLifecycleOutcome`、`ForegroundLifecycleInterruptionSource`、Unix `OsSignalForegroundLifecycleInterruptionSource`、`handle_foreground_lifecycle` 和 `handle_foreground_lifecycle_with_runtime_stop` 定义前台 lifecycle handoff/interruption/cleanup 源码合同，并通过 current-process host 接入二进制入口。
- `handle_capabilities`、`handle_status`、`handle_diagnostics`、`handle_mitm_status`、`handle_mitm_certificate_plan`、`handle_mitm_browser_plan`、`handle_mitm_browser_capture_plan`、`handle_mitm_browser_capture_launch_plan`、`handle_mitm_browser_capture_session_plan`、`handle_mitm_browser_capture_launch`、`handle_mitm_browser_capture_apply`、`handle_mitm_browser_capture_rollback`、`handle_mitm_browser_capture_verify`、`handle_mitm_browser_capture_verify_with_probe`、`handle_mitm_browser_capture_traffic_proof`、`handle_mitm_browser_capture_traffic_proof_with_probe`、`handle_stop` 和 JSON renderer 覆盖平台诊断、MITM policy-only status、certificate plan、browser plan、browser-capture session/launch/verify/traffic-proof/blocked report、无 daemon stop、无 runtime context status 和自动化输出合同。
- `handle_entrypoint` 将 `capabilities`、`status`、`diagnostics`、`mitm status/diagnostics/certificate-plan/browser-plan`、browser-capture 的 plan/launch-plan/session-plan 和 blocked apply/rollback/verify/traffic-proof 路由到注入的 `PlatformCapabilityService`；`handle_entrypoint_with_browser_capture_io` 保留 launch/verify 接线，`handle_entrypoint_with_browser_capture_all_io` 将可选 target URL 透传给 `session-plan`、`launch --confirm` 和 `verify --confirm`，将 `mitm browser-capture launch --confirm` 路由到注入的 `BrowserCaptureProcessRunner`，将 `mitm browser-capture verify --confirm` 路由到注入的 `BrowserCaptureEndpointProbe`，并将 `mitm browser-capture traffic-proof --confirm` 路由到注入的 `BrowserCaptureTrafficProofProbe`；二进制入口使用 `ReadOnlyLinuxPlatformCapabilityService<HostLinuxReadOnlyProbe>`、`CommandBrowserCaptureProcessRunner`、`CommandBrowserCaptureEndpointProbe` 和 `CommandBrowserCaptureTrafficProofProbe`。
- `handle_entrypoint_with_runtime` 继续将 `prepare-config` 路由到 `RuntimeOrchestrator`；`handle_entrypoint_with_runtime_and_lifecycle` 将 `start` 路由到 `RuntimeOrchestrator::start_runtime`、`NativeProxyEngineService` 和前台 lifecycle host。

该 crate 当前执行只读 Linux 能力探测、只读配置准备和前台 native runtime 启动，不修改系统状态、不安装 daemon。Linux artifact 发布路径已由 GitHub Actions release workflow 打通，CLI crate 仍不在本机打包或发布。Unix 默认前台 host 会监听 `SIGINT`/`SIGTERM` 并映射为 `cli.linux.start.signal_received`、`cli.linux.start.lifecycle_interrupted` 和 130 退出码；interruption 后会通过当前进程内 `RuntimeOrchestrator::stop_runtime` 释放 native runtime 并聚合 `engine.native.runtime.accept_loop_stopped`/`engine.native.runtime.released` 诊断，stop 失败时追加 `cli.linux.start.runtime_stop_failed`；`stop` 与后台 `status` 在没有 daemon/control socket 前继续保持稳定 unavailable 诊断。

## Release 边界

当前 Linux CLI artifact 已通过 `.github/workflows/release.yml` 发布路径生成和上传。后续 tag release 仍必须满足：

- 同 commit CI 成功，且 `CI summary` job 通过 release CI gate 校验。
- Linux CLI 源码、platform adapter、artifact manifest、安装/回滚设计和 license/NOTICE confirmed marker 均通过 repository governance。
- `package-linux` 只能在 GitHub Actions 中构建，输出 tarball、sha256、manifest 和 manifest sha256。
- `attest-linux`、release notes、rollback、publish eligibility 和 GitHub Release upload gates 均通过。
- 不上传空壳二进制、未验证二进制或本地构建产物。

## 验收条件

CLI 首个源码增量必须满足：

- 本设计文档保持在 README、ROADMAP、Release Strategy、Linux artifact 设计和 CI policy 中可发现。
- `.github/workflows/ci.yml` governance 检查本文档存在和标题。
- TODO 明确下一步最小增量。
- 后续源码实现不得扩大本文定义的首版命令边界，除非先更新设计并通过 CI。

## 后续工作

- Linux artifact readiness/release gate 已纳入 foreground stop/release 合同检查、artifact manifest 输出合同、license/NOTICE confirmation source contract、license/NOTICE transition validation contract、release CI success source contract、release CI gate activation validation contract、package runner/toolchain/target contract、archive staging contract、checksum/manifest checksum contract、publish/upload boundary contract、signing/attestation policy binding contract、release notes/rollback policy binding contract 和 publish eligibility aggregate contract；当前 marker 为 `linux-artifact-release-state=confirmed-release-path`，后续 tag release 继续通过这些 gates 生成和发布 Linux assets。
- Linux package artifact job preflight validation contract、Linux package artifact build command validation contract、Linux package artifact staging file validation contract、Linux package artifact archive creation validation contract、Linux package artifact checksum execution validation contract、Linux package artifact manifest generation validation contract、Linux package artifact manifest checksum validation contract、Linux package workflow artifact bundle upload validation contract、Linux package artifact attestation execution validation contract、Linux package release notes/rollback execution validation contract 和 Linux package publish eligibility execution validation contract 已进入 release workflow；release CI gate execution validation contract 和 release CI gate API implementation 已激活。
- daemon/control socket、packaging 或任何会修改系统状态的 Linux probing 进入 CLI 前，先补充对应设计并通过 CI。
