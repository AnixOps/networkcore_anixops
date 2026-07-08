# Linux MITM Browser Capture Source Contract

评估时间：2026-07-08。

当前合同状态：

```text
mitm-browser-capture-source-contract-status=active
MITM_BROWSER_CAPTURE_GATE=plan-only/mutation-blocked
```

## Purpose

本文固定 Linux 浏览器流量捕获从 plan-only 进入真实源码 mutation 前必须遵守的合同。当前仓库已经有
`networkcore-linux mitm browser-plan`、`networkcore-linux mitm browser-capture plan/apply/rollback/verify`、
`mitm_status.browser_plan` 和 `browser_capture` 机器字段，但还没有用户可启用的 live browser capture，
也没有浏览器/系统代理写入、PAC 写入、TUN/DNS/firewall mutation 或回滚实现。

本合同的目标是先把后续源码边界固定下来，避免浏览器劫持功能直接写入用户系统状态而缺少显式授权、
快照、回滚和 CI governance。

## Current Boundary

当前仓库源码只允许 plan-only/mutation-blocked 行为：

- `networkcore-linux mitm browser-plan` 输出默认显式代理计划 `127.0.0.1:7890`。
- `networkcore-linux mitm browser-capture plan` 输出同一 capture plan 和 source contract report。
- `networkcore-linux mitm browser-capture apply --confirm` 接受显式授权信号，但仍返回 blocked report，不写入系统状态。
- `networkcore-linux mitm browser-capture rollback --snapshot <path>` 保留 snapshot path 到 report，但仍返回 blocked report，不读取或写入该路径。
- `networkcore-linux mitm browser-capture verify` 返回 live capture probe blocked report。
- `mitm_status.browser_plan` 输出计划步骤、blocked operations 和 `mutation_ready=false`。
- `browser_capture` 输出 action、gate、`BrowserCaptureAuthorization`、`BrowserCaptureRollbackSnapshot`、
  `LinuxBrowserCaptureApplyReport`、`LinuxBrowserCaptureRollbackReport` 和 verify report。
- `MITM_BROWSER_CAPTURE_GATE` 保持 `plan-only/mutation-blocked`。
- `cli.linux.mitm.browser_plan.ready` 表示计划可见。
- `cli.linux.mitm.browser_capture_mutation.blocked` 表示真实 mutation 仍被阻断。

当前不允许：

- 写入浏览器 policy、profile、proxy setting 或 extension state。
- 写入系统 proxy、PAC、TUN、DNS、route 或 firewall 状态。
- 生成、安装、信任或撤销 MITM CA。
- 解密 HTTPS、解析 HTTP/TLS 数据面或应用 rewrite plan 到真实流量。
- 声称 browser hijack、live browser capture 或 HTTPS MITM 已可用。

## Future Source Anchors

当前源码已经提供以下 NetworkCore-owned 类型；启用真实浏览器捕获前，这些类型必须继续保持稳定或经过
CI governance 显式迁移：

- `LinuxBrowserCaptureRequest`
- `LinuxBrowserCapturePlan`
- `LinuxBrowserCaptureApplyReport`
- `LinuxBrowserCaptureRollbackReport`
- `BrowserCaptureAuthorization`
- `BrowserCaptureRollbackSnapshot`

当前 CLI 命令已经显式区分 plan、apply、rollback 和 verify：

```text
networkcore-linux mitm browser-capture plan
networkcore-linux mitm browser-capture apply --confirm
networkcore-linux mitm browser-capture rollback --snapshot <path>
networkcore-linux mitm browser-capture verify
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
| `cli.linux.mitm.browser_capture.apply.blocked` | Error | gate、证书、数据面或平台边界未满足，拒绝 apply |
| `cli.linux.mitm.browser_capture.rollback.blocked` | Error | 缺少 snapshot、snapshot 不匹配或 rollback gate 未满足 |
| `cli.linux.mitm.browser_capture.verify.blocked` | Error | live capture probe 尚未实现，拒绝宣称捕获已验证 |
| `cli.linux.mitm.browser_capture.apply.ready` | Info | apply 前置条件通过，准备写入受控目标 |
| `cli.linux.mitm.browser_capture.rollback.ready` | Info | rollback 前置条件通过，准备恢复 snapshot |

当前源码已经提供 `handle_mitm_browser_capture_apply`、`handle_mitm_browser_capture_rollback` 和
`handle_mitm_browser_capture_verify`，但它们只输出 blocked reports 和上表诊断，直到真实 apply/rollback
源码实现并通过 GitHub Actions。

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
- 当前源码不得实现无授权 browser/system proxy mutation。
- 本机不得运行测试、构建、打包或发布验证。

如果某个浏览器或系统设置必须人工操作才能验证，必须先写入 `docs/manual-intervention.md`，并说明人工动作完成后下一步
GitHub Actions 如何继续验证。
