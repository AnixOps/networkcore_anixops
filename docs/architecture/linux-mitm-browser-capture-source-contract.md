# Linux MITM Browser Capture Source Contract

评估时间：2026-07-08。

当前合同状态：

```text
mitm-browser-capture-source-contract-status=active
MITM_BROWSER_CAPTURE_GATE=plan-only/mutation-blocked
```

## Purpose

本文固定 Linux 浏览器流量捕获从 plan-only 进入真实源码 mutation 前必须遵守的合同。当前仓库已经有
`networkcore-linux mitm browser-plan`、`networkcore-linux mitm browser-capture plan/launch-plan/session-plan/launch/apply/rollback/verify`、
`mitm_status.browser_plan`、`browser_capture` 机器字段、脱敏 session-plan 和显式授权的本地代理端点 verify，但还没有用户可启用的 live browser capture，
也没有浏览器/系统代理写入、PAC 写入、TUN/DNS/firewall mutation 或回滚实现。

发布边界：当前最新用户可下载 Linux artifact 是 `v0.1.0-alpha.8`；本文描述 current `main`
源码合同。`v0.1.0-alpha.8` 已覆盖 `verify --confirm`、`verify --confirm --target-url <url>`、`session-plan` 和 `--target-url`；该 tag 之后的 main 增量需要后续新 tag release 通过 GitHub Actions
后才会进入 GitHub Release asset。

本合同的目标是先把后续源码边界固定下来，避免浏览器劫持功能直接写入用户系统状态而缺少显式授权、
快照、回滚和 CI governance。

## Current Boundary

当前仓库源码只允许 plan-only/mutation-blocked 行为：

- `networkcore-linux mitm browser-plan` 输出默认显式代理计划 `127.0.0.1:7890`。
- `networkcore-linux mitm browser-capture plan` 输出同一 capture plan 和 source contract report。
- `networkcore-linux mitm browser-capture launch-plan` 输出手动 dedicated-profile 浏览器启动命令模板、计划代理 URL 和已加载插件元数据；该命令不启动浏览器、不写 profile、不写系统状态。
- `networkcore-linux mitm browser-capture session-plan <ss://url> [--browser <executable>] [--profile-dir <dir>] [--target-url <url>] [--listen-host <host>] [--listen-port <port>]` 解析单条订阅链接，输出脱敏 URL 来源、选中节点、本地代理监听、`run-url <subscription-url>` 命令模板、dedicated 浏览器启动命令、可选 target URL、继承 target URL 的 `verify --confirm` 命令和已加载插件元数据；该命令不下载或启动 `sing-box`，不启动浏览器，不写系统或浏览器状态。
- `networkcore-linux mitm browser-capture launch --confirm [--browser <executable>] [--profile-dir <dir>] [--target-url <url>]` 通过注入的 `BrowserCaptureProcessRunner` 启动 dedicated browser profile，传入显式 `--proxy-server=http://127.0.0.1:7890`、`--user-data-dir=<dir>` 和可选 target URL 参数，并输出 `LinuxBrowserCaptureLaunchReport`；该命令不写系统代理、浏览器 policy、PAC、TUN、DNS、firewall 或 CA 状态，也不验证 live browser capture。
- `networkcore-linux mitm browser-capture launch` 缺少 `--confirm` 时返回 authorization required，不调用 process runner。
- `networkcore-linux mitm browser-capture apply --confirm` 接受显式授权信号，但仍返回 blocked report，不写入系统状态。
- `networkcore-linux mitm browser-capture rollback --snapshot <path>` 保留 snapshot path 到 report，但仍返回 blocked report，不读取或写入该路径。
- `networkcore-linux mitm browser-capture verify --confirm` 通过注入的 `BrowserCaptureEndpointProbe` 探测计划本地代理端点 `http://127.0.0.1:7890`，输出 `LinuxBrowserCaptureVerifyRequest` 和 `LinuxBrowserCaptureVerifyReport`；传入 `--target-url <url>` 时，probe 使用 `http-connect-target` 对目标 host:port 发起 HTTP CONNECT 探测，成功时输出 `cli.linux.mitm.browser_capture.verify.target_reachable` 和 `target_reachable` report；无效 target URL 在连接代理前返回 `cli.linux.mitm.browser_capture.verify.target_invalid` 和 `target_invalid` report；该命令只验证本地代理端点或目标代理通路，不验证 live browser traffic、HTTPS MITM 或 rewrite 应用。
- `networkcore-linux mitm browser-capture verify` 缺少 `--confirm` 时返回 authorization required，不调用 endpoint probe；未接线 probe 的 read-only entrypoint 仍返回 verify blocked report。
- `mitm_status.browser_plan` 输出计划步骤、blocked operations 和 `mutation_ready=false`。
- `browser_capture` 输出 action、gate、`BrowserCaptureAuthorization`、`BrowserCaptureRollbackSnapshot`、
  `LinuxBrowserCaptureManualLaunch`、`LinuxBrowserCaptureLaunchRequest`、`LinuxBrowserCaptureLaunchReport`、
  `LinuxBrowserCaptureSessionPlanRequest`、`LinuxBrowserCaptureSessionPlanReport`、
  `LinuxBrowserCaptureVerifyRequest`、`LinuxBrowserCaptureVerifyReport`、`BrowserCaptureEndpointProbe`、
  `LinuxBrowserCaptureApplyReport`、`LinuxBrowserCaptureRollbackReport` 和 verify report。
- `MITM_BROWSER_CAPTURE_GATE` 保持 `plan-only/mutation-blocked`。
- `cli.linux.mitm.browser_plan.ready` 表示计划可见。
- `cli.linux.mitm.browser_capture_mutation.blocked` 表示真实 mutation 仍被阻断。

当前不允许：

- 写入浏览器 policy、profile、proxy setting 或 extension state。
- 通过 `launch-plan` 自动启动浏览器或修改浏览器 profile。
- 通过 `session-plan` 启动 `sing-box`、启动浏览器、写入 profile、写系统状态或把完整订阅 URL 写入诊断和 JSON report；`--target-url` 只进入 dedicated browser launch request 和 command args。
- 通过 `launch` 写入系统代理、浏览器 policy、PAC、TUN、DNS、firewall、CA 或 NetworkCore-owned profile 配置；浏览器进程自身创建 dedicated profile 文件和打开 `--target-url` 不代表 NetworkCore 已获得 profile mutation 权限。
- 通过 `verify --target-url` 将目标代理通路可达性等同于 dedicated browser 真实流量、HTTPS MITM 或 rewrite 应用已验证。
- 写入系统 proxy、PAC、TUN、DNS、route 或 firewall 状态。
- 生成、安装、信任或撤销 MITM CA。
- 解密 HTTPS、解析 HTTP/TLS 数据面或应用 rewrite plan 到真实流量。
- 将本地代理端点可达性等同于 browser hijack、live browser capture 或 HTTPS MITM 已可用。

## Future Source Anchors

当前源码已经提供以下 NetworkCore-owned 类型；启用真实浏览器捕获前，这些类型必须继续保持稳定或经过
CI governance 显式迁移：

- `LinuxBrowserCaptureRequest`
- `LinuxBrowserCapturePlan`
- `LinuxBrowserCaptureManualLaunch`
- `LinuxBrowserCaptureLaunchCommand`
- `LinuxBrowserCaptureSessionPlanRequest`
- `LinuxBrowserCaptureSessionPlanReport`
- `LinuxBrowserCaptureLaunchRequest`
- `LinuxBrowserCaptureLaunchReport`
- `BrowserCaptureProcessRunner`
- `CommandBrowserCaptureProcessRunner`
- `LinuxBrowserCaptureVerifyRequest`
- `LinuxBrowserCaptureVerifyOutcome`
- `LinuxBrowserCaptureVerifyReport`
- `BrowserCaptureEndpointProbe`
- `CommandBrowserCaptureEndpointProbe`
- `LinuxBrowserCaptureApplyReport`
- `LinuxBrowserCaptureRollbackReport`
- `BrowserCaptureAuthorization`
- `BrowserCaptureRollbackSnapshot`

当前 CLI 命令已经显式区分 plan、launch-plan、session-plan、launch、apply、rollback 和 verify：

```text
networkcore-linux mitm browser-capture plan
networkcore-linux mitm browser-capture launch-plan
networkcore-linux mitm browser-capture session-plan <ss://url> --browser chromium --profile-dir /tmp/networkcore-browser-capture-profile --target-url https://example.com
networkcore-linux mitm browser-capture launch --confirm --browser chromium --profile-dir /tmp/networkcore-browser-capture-profile --target-url https://example.com
networkcore-linux mitm browser-capture apply --confirm
networkcore-linux mitm browser-capture rollback --snapshot <path>
networkcore-linux mitm browser-capture verify --confirm --target-url https://example.com
```

`networkcore-linux mitm browser-plan` 保留为兼容 plan-only 入口；真实 mutation 入口不得复用只读 plan 命令。

## Authorization And Snapshot

真实 apply 必须满足：

- 调用方显式传入 `--confirm` 或等价 UI 授权信号。
- `BrowserCaptureAuthorization` 记录授权来源、目标浏览器或系统 scope、时间和 gate 状态。
- apply 前必须生成 `BrowserCaptureRollbackSnapshot`。
- snapshot 必须足以恢复 NetworkCore 修改过的文件、setting 或 profile 状态。
- 不得覆盖未知第三方变更；如果 snapshot 与当前状态冲突，必须拒绝 apply 或 rollback。
- secret、private key、完整订阅 URL、cookie、token 和浏览历史不得写入诊断或 snapshot。

未来首个 apply 增量应优先选择可局部回滚的显式代理配置路径。TUN、DNS、route 和 firewall 捕获不属于本合同的首个可变更范围，
必须另补 platform adapter source contract。

## Diagnostics

未来源码必须提供稳定诊断 code。当前合同预留：

| code | severity | 含义 |
| --- | --- | --- |
| `cli.linux.mitm.browser_capture.authorization_required` | Error | 缺少显式授权，拒绝写入浏览器或系统状态 |
| `cli.linux.mitm.browser_capture.launch_plan.ready` | Info | 手动 dedicated-profile 浏览器启动计划可见，但不写系统或浏览器状态 |
| `cli.linux.mitm.browser_capture.session_plan.ready` | Info | 订阅到本地代理、dedicated 浏览器和 verify 的脱敏会话计划可见，但不启动进程或写系统状态 |
| `cli.linux.mitm.browser_capture.session_plan.url_parse_failed` | Error | session-plan 输入的订阅链接无法解析或归一化 |
| `cli.linux.mitm.browser_capture.session_plan.config_failed` | Error | session-plan 无法为选中节点渲染本地代理配置计划 |
| `cli.linux.mitm.browser_capture.launch.authorization_required` | Error | 缺少显式授权，拒绝启动 dedicated browser profile |
| `cli.linux.mitm.browser_capture.launch.started` | Info | dedicated browser profile 已用显式代理参数启动 |
| `cli.linux.mitm.browser_capture.launch.failed` | Error | dedicated browser profile 启动失败或 runner 未接线 |
| `cli.linux.mitm.browser_capture.apply.blocked` | Error | gate、证书、数据面或平台边界未满足，拒绝 apply |
| `cli.linux.mitm.browser_capture.rollback.blocked` | Error | 缺少 snapshot、snapshot 不匹配或 rollback gate 未满足 |
| `cli.linux.mitm.browser_capture.verify.authorization_required` | Error | 缺少显式授权，拒绝探测计划本地代理端点 |
| `cli.linux.mitm.browser_capture.verify.proxy_reachable` | Info | 计划本地代理端点可达，但不代表 live browser traffic 或 HTTPS MITM 已验证 |
| `cli.linux.mitm.browser_capture.verify.proxy_unreachable` | Error | 计划本地代理端点不可达 |
| `cli.linux.mitm.browser_capture.verify.target_reachable` | Info | 计划本地代理端点可对 target URL host:port 建立 HTTP CONNECT 通路，但不代表浏览器真实流量或 HTTPS MITM 已验证 |
| `cli.linux.mitm.browser_capture.verify.target_invalid` | Error | `--target-url` 缺少 http/https scheme、host 或合法端口 |
| `cli.linux.mitm.browser_capture.verify.blocked` | Error | endpoint probe 未接线或更强 live capture probe 尚未实现，拒绝宣称浏览器真实流量捕获已验证 |
| `cli.linux.mitm.browser_capture.apply.ready` | Info | apply 前置条件通过，准备写入受控目标 |
| `cli.linux.mitm.browser_capture.rollback.ready` | Info | rollback 前置条件通过，准备恢复 snapshot |

当前源码已经提供 `handle_mitm_browser_capture_launch_plan`、`handle_mitm_browser_capture_session_plan`、`handle_mitm_browser_capture_launch`、
`handle_mitm_browser_capture_apply`、`handle_mitm_browser_capture_rollback` 和
`handle_mitm_browser_capture_verify`。`launch-plan` 只输出 manual launch report，`session-plan`
只输出脱敏订阅到本地代理、浏览器、可选 target URL 和 verify 的命令计划，`launch --confirm`
只启动 dedicated browser process 并输出 `launch_report`，`verify --confirm` 只探测计划本地代理端点或目标 URL 代理通路并输出
`verify_report`，apply/rollback 只输出 blocked reports 和上表诊断，直到真实 apply/rollback/live traffic
verification 源码实现并通过 GitHub Actions。

## Plugin And Data Plane Boundary

浏览器捕获只负责把浏览器流量送入 NetworkCore/MITM 数据面，不拥有插件解析或 rewrite 逻辑。

- MITM plugin/parser/runtime 仍归 `mitm-policy`、`MitmPluginService` 和
  [Third-Party Plugin Onboarding Process](third-party-plugin-onboarding-process.md) 管理。
- HTTP/TLS 解密、HTTP parser、body buffering、script runtime 和 rewrite application 仍归
  `MITM_HTTP_TLS_DATA_PLANE_GATE`。
- CA generation、install、trust detection、revocation 和 rollback 仍归
  `MITM_CERTIFICATE_LIFECYCLE_GATE`。

因此，浏览器捕获 apply 即使完成，也不得单独宣称 HTTPS MITM 可用；必须同时满足证书生命周期和 HTTP/TLS 数据面 gate。

## CI Governance

GitHub Actions 必须静态检查：

- 本合同文件存在并包含 `mitm-browser-capture-source-contract-status=active`。
- README、ROADMAP、TODO 和 CI policy 能发现本合同。
- `MITM_BROWSER_CAPTURE_GATE` 当前仍是 `plan-only/mutation-blocked`。
- `networkcore-linux mitm browser-plan` 和 `mitm_status.browser_plan` 仍保持 plan-only 机器字段。
- `BrowserCaptureAuthorization` 和 `BrowserCaptureRollbackSnapshot` 作为后续源码 anchor 可发现。
- `LinuxBrowserCaptureSessionPlanRequest`、`LinuxBrowserCaptureSessionPlanReport` 和 `cli.linux.mitm.browser_capture.session_plan.ready` 作为脱敏会话计划 anchor 可发现。
- `BrowserCaptureEndpointProbe`、`LinuxBrowserCaptureVerifyRequest` 和 `LinuxBrowserCaptureVerifyReport` 作为本地代理端点 verify anchor 可发现。
- 当前源码不得实现无授权 browser/system proxy mutation。
- `session-plan` 必须由合同测试覆盖解析、脱敏 URL 来源、选中节点、本地代理命令模板、dedicated 浏览器命令、可选 `--target-url`、verify 命令、JSON `session_plan` 和不写系统状态边界。
- `launch --confirm` 必须通过 `BrowserCaptureProcessRunner` 注入执行，并由合同测试覆盖缺少授权、runner 成功、runner 未接线、可选 `--target-url` 和 JSON `launch_report`。
- `verify --confirm` 必须通过 `BrowserCaptureEndpointProbe` 注入执行，并由合同测试覆盖缺少授权、endpoint reachable、target URL `http-connect-target` reachable、target URL invalid、endpoint unreachable、未接线 blocked 和 JSON `verify_report`。
- 本机不得运行测试、构建、打包或发布验证。

如果某个浏览器或系统设置必须人工操作才能验证，必须先写入 `docs/manual-intervention.md`，并说明人工动作完成后下一步
GitHub Actions 如何继续验证。
