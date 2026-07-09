# Linux MITM Browser Capture Source Contract

评估时间：2026-07-09。

当前合同状态：

```text
mitm-browser-capture-source-contract-status=active
MITM_BROWSER_CAPTURE_GATE=pac-policy-profile-prefs-active/system-mutation-blocked
```

P4 current stage source of truth: browser capture is now P4 Client And Platform
Integration work. P3 Runtime Capability Baseline is completed history; any P3
wording in older completed entries is historical, not the current stage.
The browser-capture slice of the P4 backlog buckets is complete live browser
traffic proof automation, explicit browser/system proxy or system PAC mutation,
safe snapshot, and rollback.

## Purpose

本文固定 Linux 浏览器流量捕获从 plan-only 进入受控源码 mutation 后必须遵守的合同。当前仓库已经有
`networkcore-linux mitm browser-plan`、`networkcore-linux mitm browser-capture plan/launch-plan/session-plan/launch/apply/rollback/verify/traffic-proof`、
`mitm_status.browser_plan`、`browser_capture` 机器字段、脱敏 session-plan、显式授权的本地代理端点 verify、proof-log-token traffic proof，以及 NetworkCore-owned PAC/browser policy artifact apply/rollback。
current `main` 还会在 `session-plan`/`launch --confirm` 中生成 `proof_target_url`、`networkcore_proof_token` 和 `traffic_proof_command`，
并允许 `traffic-proof --confirm [--target-url <url>]` 在 proof token/log 省略时复用同一默认 proof 绑定；
默认 proof token 使用 CONNECT endpoint 和 proxy URL 派生，以便与 native SOCKS5 CONNECT 层可见信息对齐。
`v0.1.0-alpha.19` 进一步让 `traffic-proof` 在可解析 target URL 时输出
`proof_connect_authority`，并要求同一 proof log 行同时包含 proof token、计划 proxy URL 和 CONNECT authority；
不匹配时返回 `cli.linux.mitm.browser_capture.traffic_proof.binding_mismatch`，避免 token 孤立出现被误判为同一显式浏览器会话。
`session-plan`、`launch`、`apply`、`verify` 和 `traffic-proof` 支持显式 `--proxy-scheme http|socks5`，
其中 `socks5` 会生成 `socks5://127.0.0.1:7890` browser/PAC/policy/verify/proof 计划，用于让授权的 dedicated 浏览器会话走到 native SOCKS5 CONNECT MITM hook。
`apply --confirm` 还可在调用方显式传入 `--profile-prefs-file <path>` 时写入并回滚 Firefox dedicated profile `user.js` 代理 prefs。
`networkcore-linux start` 还能在 explicit SOCKS5 CONNECT 层应用内置 MITM 插件 `Reject` 为 CONNECT failure，并输出
`engine.native.runtime.http_mitm_connect_browser_proof_observed` 诊断记录默认 proof token、CONNECT target 和本地 socks5 proxy URL。
但还没有用户可启用的完整 live browser capture，也没有系统级浏览器/系统代理写入、系统 PAC 安装、
TUN/DNS/firewall mutation、CA lifecycle、HTTPS 解密或 live HTTP/TLS request/response rewrite data plane。

发布边界：当前最新用户可下载 Linux artifact 是 `v0.1.0-alpha.19`；本文描述 current `main`
源码合同。`v0.1.0-alpha.19` 已覆盖 `verify --confirm`、`verify --confirm --target-url <url>`、`session-plan`、`--target-url`、
`traffic-proof --confirm [--target-url <url>] [--proof-token <token>] [--proof-log <path>]` proof-log-token 验证入口、
`proof_connect_authority`、同一行 token/proxy/CONNECT authority binding mismatch 诊断、`session-plan`/`launch --confirm` proof URL/default proof 绑定、`--proxy-scheme socks5` native plugin proxy mode、
`apply --confirm --pac-file <path> [--policy-file <path>] [--profile-prefs-file <path>] --snapshot <path>` / `rollback --snapshot <path>` PAC/browser policy artifact 与 Firefox dedicated profile prefs apply/rollback，
explicit SOCKS5 CONNECT-level plugin reject/proof 诊断、explicit HTTP proxy live plain HTTP data plane、TLS CA certificate PEM、private key PEM、dedicated profile CA PEM copy、explicit HTTP `CONNECT` pass-through tunnel foundation、bounded ClientHello/SNI observation、controlled downstream TLS termination plan/report、caller-provided HTTPS request rewrite preview，以及 caller-provided HTTPS response rewrite preview。
当前 `main` 已同步到 `v0.1.0-alpha.19` proof binding hardening 发布边界；后续新能力仍必须等待新 tag、
同 commit CI、package、attestation、publish eligibility 和 GitHub Release asset 全部通过后才会成为用户可下载 artifact。
逐 alpha 能力边界以 [Alpha Release Feature Matrix](../alpha-release-feature-matrix.md) 为准。

本合同的目标是先把后续源码边界固定下来，避免浏览器劫持功能直接写入用户系统状态而缺少显式授权、
快照、回滚和 CI governance。

## Current Boundary

当前仓库源码只允许 pac-policy-profile-prefs-active/system-mutation-blocked 行为：

- `networkcore-linux mitm browser-plan` 输出默认显式代理计划 `127.0.0.1:7890`。
- `networkcore-linux mitm browser-capture plan` 输出同一 capture plan 和 source contract report。
- `networkcore-linux mitm browser-capture launch-plan` 输出手动 dedicated-profile 浏览器启动命令模板、计划代理 URL 和已加载插件元数据；该命令不启动浏览器、不写 profile、不写系统状态。
- `networkcore-linux mitm browser-capture session-plan <ss://url> [--browser <executable>] [--profile-dir <dir>] [--target-url <url>] [--proof-token <token>] [--proof-log <path>] [--proxy-scheme http|socks5] [--listen-host <host>] [--listen-port <port>]` 解析单条订阅链接，输出脱敏 URL 来源、选中节点、本地代理监听、`run-url <subscription-url>` 命令模板、dedicated 浏览器启动命令、可选 target URL、带 `networkcore_proof_token` 的 `proof_target_url`、继承 target URL 的 `verify --confirm` 命令、`traffic-proof` 命令和已加载插件元数据；`--proxy-scheme socks5` 会把 browser command、verify command 和 traffic-proof command 绑定到 `socks5://127.0.0.1:7890`，用于显式走 native SOCKS5 CONNECT hook；该命令不下载或启动 `sing-box`，不启动浏览器，不写系统或浏览器状态。
- `networkcore-linux mitm browser-capture launch --confirm [--browser <executable>] [--profile-dir <dir>] [--target-url <url>] [--proof-token <token>] [--proof-log <path>] [--proxy-scheme http|socks5]` 通过注入的 `BrowserCaptureProcessRunner` 启动 dedicated browser profile，传入显式 `--proxy-server=http://127.0.0.1:7890` 或 `--proxy-server=socks5://127.0.0.1:7890`、`--user-data-dir=<dir>` 和可选 proof target URL 参数，并输出 `LinuxBrowserCaptureLaunchReport`、`proxy_scheme`、`proof_target_url`、proof token/log 和 `traffic_proof_command`；该命令不写系统代理、浏览器 policy、system PAC、TUN、DNS、firewall 或 CA 状态，也不单独验证 live browser capture。
- `networkcore-linux mitm browser-capture launch` 缺少 `--confirm` 时返回 authorization required，不调用 process runner。
- `networkcore-linux mitm browser-capture apply --confirm --pac-file <path> [--policy-file <path>] [--profile-prefs-file <path>] --snapshot <path> [--proxy-scheme http|socks5]` 接受显式授权信号，通过 `BrowserCapturePacFileStore` 写入 operator-provided NetworkCore PAC 文件、可选 Chromium/Chrome managed proxy policy artifact、可选 Firefox dedicated profile `user.js` prefs 文件和 rollback snapshot。PAC 内容按 scheme 返回 `PROXY 127.0.0.1:7890; DIRECT` 或 `SOCKS5 127.0.0.1:7890; DIRECT`；policy artifact 内容写入 `ProxyMode=fixed_servers`、`ProxyServer=<planned proxy URL>` 和 `ProxyBypassList=<-loopback>`，用于让调用方手动安装到浏览器 policy 路径或继续接入后续授权安装流程；profile prefs 内容只写调用方指定的 dedicated Firefox profile `user.js`，HTTP 模式写 http/ssl proxy，SOCKS5 模式写 socks/socks_remote_dns；该命令不安装系统 PAC，不安装浏览器 policy，不写系统代理。缺少 `--pac-file` 或 `--snapshot` 时返回 config missing 且不写文件；已存在目标 PAC、policy 或 snapshot 时拒绝覆盖，profile prefs 会先记录原始内容再替换。
- `networkcore-linux mitm browser-capture rollback --snapshot <path>` 读取 NetworkCore snapshot，删除 snapshot 记录的 PAC 文件和可选 browser policy artifact，并在 profile prefs 未被外部修改时恢复原 `user.js` 内容或删除 NetworkCore 新建的 `user.js`；artifact 已不存在时按幂等成功处理，profile prefs 与 snapshot 写入内容不一致时拒绝覆盖未知变更。该命令不恢复或修改系统 proxy/system PAC 状态。
- `networkcore-linux mitm browser-capture verify --confirm [--proxy-scheme http|socks5]` 通过注入的 `BrowserCaptureEndpointProbe` 探测计划本地代理端点 `http://127.0.0.1:7890` 或 `socks5://127.0.0.1:7890`，输出 `LinuxBrowserCaptureVerifyRequest` 和 `LinuxBrowserCaptureVerifyReport`；传入 `--target-url <url>` 时，probe 使用 `http-connect-target` 对目标 host:port 发起 HTTP CONNECT 探测，成功时输出 `cli.linux.mitm.browser_capture.verify.target_reachable` 和 `target_reachable` report；无效 target URL 在连接代理前返回 `cli.linux.mitm.browser_capture.verify.target_invalid` 和 `target_invalid` report；该命令只验证本地代理端点或目标代理通路，不验证 live browser traffic、HTTPS MITM 或 rewrite 应用。
- `networkcore-linux mitm browser-capture verify` 缺少 `--confirm` 时返回 authorization required，不调用 endpoint probe；未接线 probe 的 read-only entrypoint 仍返回 verify blocked report。
- `networkcore-linux mitm browser-capture traffic-proof --confirm [--target-url <url>] [--proof-token <token>] [--proof-log <path>] [--proxy-scheme http|socks5]` 通过注入的 `BrowserCaptureTrafficProofProbe` 检查 operator-provided proof log，输出 `LinuxBrowserCaptureTrafficProofRequest`、`LinuxBrowserCaptureTrafficProofReport`、`probe=proof-log-token`、`proxy_scheme`、proxy URL、target URL、`proof_connect_authority`、proof target URL、proof token 和 proof log path；未传 proof token/log 时会使用 `--target-url` 的 CONNECT endpoint、计划代理 URL 和 `MITM_BROWSER_CAPTURE_DEFAULT_PROOF_LOG_PATH` 生成与 `session-plan`/`launch --confirm` 一致的默认 proof 绑定。native SOCKS5 CONNECT hook 在 `networkcore-linux start` 的运行时诊断中输出同一默认 token，调用方可把启动日志作为 `--proof-log` 输入。target URL 可解析时，command probe 要求同一 proof log 行同时包含 proof token、计划 proxy URL 和 CONNECT authority；符合绑定时返回 `cli.linux.mitm.browser_capture.traffic_proof.observed` 和 `proven=true`，token 孤立出现但未绑定到 proxy/authority 时返回 `cli.linux.mitm.browser_capture.traffic_proof.binding_mismatch`，token 缺失或 log 不可读时分别返回 `cli.linux.mitm.browser_capture.traffic_proof.missing` 或 `cli.linux.mitm.browser_capture.traffic_proof.log_unreadable`。该命令只证明调用方提供的证据文件中存在同一显式代理会话 proof 绑定，不写系统或浏览器状态，不证明 HTTPS MITM、数据面 rewrite 或自动 browser hijack 已可用。
- `networkcore-linux mitm browser-capture traffic-proof` 缺少 `--confirm` 时返回 authorization required，不调用 traffic proof probe；未接线 proof probe 的 read-only entrypoint 仍返回 traffic-proof blocked report。
- `networkcore-linux start` 注入内置 `networkcore.adblock` native MITM hook；当浏览器或其他显式代理客户端向本地 SOCKS5 listener 发起 CONNECT 且插件返回 `Reject` 时，native accept loop 写 SOCKS5 general failure response 并跳过 outbound，同时通过 `engine.native.runtime.http_mitm_connect_browser_proof_observed` 输出默认 browser proof token、CONNECT target 和本地 socks5 proxy URL。该能力只阻断 CONNECT tunnel 并提供显式代理 CONNECT proof 诊断，不写浏览器/系统代理状态，不解密 HTTPS，也不应用 redirect/header/body/script rewrite。
- `mitm_status.browser_plan` 输出计划步骤、blocked operations 和 `mutation_ready=false`。
- `browser_capture` 输出 action、gate、`BrowserCaptureAuthorization`、`BrowserCaptureRollbackSnapshot`、
  `LinuxBrowserCaptureManualLaunch`、`LinuxBrowserCaptureLaunchRequest`、`LinuxBrowserCaptureLaunchReport`、`proxy_scheme`、
  `LinuxBrowserCaptureSessionPlanRequest`、`LinuxBrowserCaptureSessionPlanReport`、
  `LinuxBrowserCaptureVerifyRequest`、`LinuxBrowserCaptureVerifyReport`、`BrowserCaptureEndpointProbe`、
  `LinuxBrowserCaptureTrafficProofRequest`、`LinuxBrowserCaptureTrafficProofReport`、`BrowserCaptureTrafficProofProbe`、
  `LinuxBrowserCapturePacRequest`、`LinuxBrowserCapturePacApplyOutcome`、`LinuxBrowserCapturePacRollbackOutcome`、
  `BrowserCapturePacFileStore`、`LinuxBrowserCaptureApplyReport`、`LinuxBrowserCaptureRollbackReport`、verify report、traffic proof report、`profile_prefs_file_path`、`profile_prefs_content` 和 PAC/browser policy/profile prefs artifact report。
- `MITM_BROWSER_CAPTURE_GATE` 保持 `pac-policy-profile-prefs-active/system-mutation-blocked`。
- `cli.linux.mitm.browser_plan.ready` 表示计划可见。
- `cli.linux.mitm.browser_capture_mutation.blocked` 表示真实 mutation 仍被阻断。

当前不允许：

- 安装浏览器 policy、写入未显式指定的 profile、全局 browser proxy setting 或 extension state；当前仅允许 `--profile-prefs-file` 指向的 Firefox dedicated profile `user.js`。
- 通过 `launch-plan` 自动启动浏览器或修改浏览器 profile。
- 通过 `session-plan` 启动 `sing-box`、启动浏览器、写入 profile、写系统状态或把完整订阅 URL 写入诊断和 JSON report；`--target-url` 只进入 dedicated browser launch request、proof target URL 和 command args。
- 通过 `launch` 写入系统代理、浏览器 policy、system PAC、TUN、DNS、firewall、CA 或 NetworkCore-owned profile 配置；浏览器进程自身创建 dedicated profile 文件和打开 `--target-url` 不代表 NetworkCore 已获得 profile mutation 权限。
- 通过 `verify --target-url` 或 native CONNECT reject 将目标代理通路可达性等同于 dedicated browser 真实流量、HTTPS MITM 或 rewrite 应用已验证。
- 通过 `traffic-proof` 将 operator-provided proof log token 或 token/proxy/CONNECT authority binding 等同于 HTTPS MITM 解密、rewrite 应用、系统代理 mutation 或完整 browser hijack 已验证。
- 写入系统 proxy、system PAC、TUN、DNS、route 或 firewall 状态。
- 生成、安装、信任或撤销 MITM CA。
- 解密 HTTPS、解析 browser/system captured HTTP/TLS 数据面或应用 redirect/header/body/script rewrite plan 到 browser/system captured HTTPS request/response 或 script runtime。
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
- `LinuxBrowserCaptureTrafficProofRequest`
- `LinuxBrowserCaptureTrafficProofOutcome`
- `LinuxBrowserCaptureTrafficProofReport`
- `BrowserCaptureTrafficProofProbe`
- `CommandBrowserCaptureTrafficProofProbe`
- `LinuxBrowserCapturePacRequest`
- `LinuxBrowserCapturePacApplyOutcome`
- `LinuxBrowserCapturePacRollbackOutcome`
- `BrowserCapturePacFileStore`
- `CommandBrowserCapturePacFileStore`
- `profile_prefs_file_path`
- `profile_prefs_content`
- `LinuxBrowserCaptureApplyReport`
- `LinuxBrowserCaptureRollbackReport`
- `BrowserCaptureAuthorization`
- `BrowserCaptureRollbackSnapshot`
- `MITM_BROWSER_CAPTURE_PROOF_QUERY_PARAM`
- `MITM_BROWSER_CAPTURE_DEFAULT_PROOF_LOG_PATH`
- `MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME`
- `MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME`
- `engine.native.runtime.http_mitm_connect_browser_proof_observed`
- `proxy_scheme`
- `proof_target_url`
- `proof_connect_authority`
- `traffic_proof_command`

当前 CLI 命令已经显式区分 plan、launch-plan、session-plan、launch、apply、rollback、verify 和 traffic-proof：

```text
networkcore-linux mitm browser-capture plan
networkcore-linux mitm browser-capture launch-plan
networkcore-linux mitm browser-capture session-plan <ss://url> --browser chromium --profile-dir /tmp/networkcore-browser-capture-profile --target-url https://example.com --proof-token browser-proof-123 --proof-log /tmp/networkcore-browser-proof.log
networkcore-linux mitm browser-capture session-plan <ss://url> --browser chromium --profile-dir /tmp/networkcore-browser-capture-profile --target-url https://example.com --proxy-scheme socks5
networkcore-linux mitm browser-capture launch --confirm --browser chromium --profile-dir /tmp/networkcore-browser-capture-profile --target-url https://example.com --proof-token browser-proof-123 --proof-log /tmp/networkcore-browser-proof.log
networkcore-linux mitm browser-capture launch --confirm --browser chromium --profile-dir /tmp/networkcore-browser-capture-profile --target-url https://example.com --proxy-scheme socks5
networkcore-linux mitm browser-capture apply --confirm --pac-file /tmp/networkcore-browser-capture.pac --profile-prefs-file /tmp/networkcore-firefox-profile/user.js --snapshot /tmp/networkcore-browser-capture.snapshot.json --proxy-scheme socks5
networkcore-linux mitm browser-capture rollback --snapshot <path>
networkcore-linux mitm browser-capture verify --confirm --target-url https://example.com --proxy-scheme socks5
networkcore-linux mitm browser-capture traffic-proof --confirm --target-url https://example.com --proof-token browser-proof-123 --proof-log /tmp/networkcore-browser-proof.log --proxy-scheme socks5
networkcore-linux mitm browser-capture traffic-proof --confirm --target-url https://example.com
```

`networkcore-linux mitm browser-plan` 保留为兼容 plan-only 入口；真实 mutation 入口不得复用只读 plan 命令。

## Authorization And Snapshot

当前 PAC/browser policy artifact apply 已满足：

- 调用方显式传入 `--confirm`。
- 调用方显式传入 `--pac-file <path>` 和 `--snapshot <path>`；`--policy-file <path>` 是可选 browser policy artifact。
- `BrowserCaptureAuthorization` 记录授权来源、scope 和 gate。
- `BrowserCapturePacFileStore` 拒绝覆盖已存在 PAC 文件、policy artifact 或 rollback snapshot。
- rollback snapshot 只记录 NetworkCore 创建的 PAC/policy artifact，rollback 只删除这些 artifact。
- snapshot、PAC 文件和 policy artifact 不得包含完整订阅 URL、cookie、token、私钥或浏览历史。

未来 browser/system mutation apply 必须满足：

- 调用方显式传入 `--confirm` 或等价 UI 授权信号。
- `BrowserCaptureAuthorization` 记录授权来源、目标浏览器或系统 scope、时间和 gate 状态。
- apply 前必须生成 `BrowserCaptureRollbackSnapshot`。
- snapshot 必须足以恢复 NetworkCore 修改过的文件、setting 或 profile 状态。
- 不得覆盖未知第三方变更；如果 snapshot 与当前状态冲突，必须拒绝 apply 或 rollback。
- secret、private key、完整订阅 URL、cookie、token 和浏览历史不得写入诊断或 snapshot。

未来 browser/system proxy mutation 增量应优先选择可局部回滚的显式代理配置路径。TUN、DNS、route 和 firewall 捕获不属于本合同的首个可变更范围，
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
| `cli.linux.mitm.browser_capture.apply.blocked` | Error | 未接入 PAC store 的只读入口、gate、证书、数据面或平台边界未满足，拒绝 apply |
| `cli.linux.mitm.browser_capture.apply.ready` | Info | PAC artifact、可选 browser policy artifact 和 rollback snapshot 已写入 operator-provided path，但不代表系统代理或浏览器 policy 已安装 |
| `cli.linux.mitm.browser_capture.apply.config_missing` | Error | 缺少 `--pac-file <path>` 或 `--snapshot <path>`，拒绝写入 |
| `cli.linux.mitm.browser_capture.pac.write_failed` | Error | PAC artifact 写入失败或目标已存在 |
| `cli.linux.mitm.browser_capture.policy.write_failed` | Error | browser policy artifact 写入失败或目标已存在 |
| `cli.linux.mitm.browser_capture.snapshot.write_failed` | Error | rollback snapshot 写入失败或目标已存在 |
| `cli.linux.mitm.browser_capture.snapshot.read_failed` | Error | rollback snapshot 无法读取、解析或不是 NetworkCore PAC snapshot |
| `cli.linux.mitm.browser_capture.rollback.blocked` | Error | 缺少 snapshot、未接入 PAC store 或 rollback gate 未满足 |
| `cli.linux.mitm.browser_capture.rollback.ready` | Info | rollback 已根据 NetworkCore snapshot 删除 PAC/policy artifact |
| `cli.linux.mitm.browser_capture.rollback.failed` | Error | rollback 无法删除 snapshot 指向的 PAC/policy artifact |
| `cli.linux.mitm.browser_capture.verify.authorization_required` | Error | 缺少显式授权，拒绝探测计划本地代理端点 |
| `cli.linux.mitm.browser_capture.verify.proxy_reachable` | Info | 计划本地代理端点可达，但不代表 live browser traffic 或 HTTPS MITM 已验证 |
| `cli.linux.mitm.browser_capture.verify.proxy_unreachable` | Error | 计划本地代理端点不可达 |
| `cli.linux.mitm.browser_capture.verify.target_reachable` | Info | 计划本地代理端点可对 target URL host:port 建立 HTTP CONNECT 通路，但不代表浏览器真实流量或 HTTPS MITM 已验证 |
| `cli.linux.mitm.browser_capture.verify.target_invalid` | Error | `--target-url` 缺少 http/https scheme、host 或合法端口 |
| `cli.linux.mitm.browser_capture.verify.blocked` | Error | endpoint probe 未接线或更强 live capture probe 尚未实现，拒绝宣称浏览器真实流量捕获已验证 |
| `cli.linux.mitm.browser_capture.traffic_proof.authorization_required` | Error | 缺少显式授权，拒绝读取 operator-provided proof log |
| `cli.linux.mitm.browser_capture.traffic_proof.observed` | Info | `proof-log-token` 在 operator-provided proof log 中被观察到，但不代表 HTTPS MITM 或 rewrite 已验证 |
| `cli.linux.mitm.browser_capture.traffic_proof.missing` | Error | operator-provided proof log 中未观察到 proof token |
| `cli.linux.mitm.browser_capture.traffic_proof.log_unreadable` | Error | operator-provided proof log 无法读取 |
| `cli.linux.mitm.browser_capture.traffic_proof.binding_mismatch` | Error | proof token 已出现，但没有同一行绑定到计划 proxy URL 和 CONNECT authority |
| `cli.linux.mitm.browser_capture.traffic_proof.blocked` | Error | traffic proof probe 未接线或更强 live capture proof 尚未实现，拒绝宣称浏览器真实流量捕获已验证 |

当前源码已经提供 `handle_mitm_browser_capture_launch_plan`、`handle_mitm_browser_capture_session_plan`、`handle_mitm_browser_capture_launch`、
`handle_mitm_browser_capture_apply`、`handle_mitm_browser_capture_rollback` 和
`handle_mitm_browser_capture_verify`、`handle_mitm_browser_capture_traffic_proof`。`launch-plan` 只输出 manual launch report，`session-plan`
只输出脱敏订阅到本地代理、浏览器、可选 target URL、proof target URL、verify 和 traffic-proof 的命令计划，`launch --confirm`
只启动 dedicated browser process 并输出 `launch_report`、proof target URL 和 `traffic_proof_command`，`verify --confirm` 只探测计划本地代理端点或目标 URL 代理通路并输出
`verify_report`，`traffic-proof --confirm` 只读取 operator-provided proof log 并输出
`traffic_proof_report`；target URL 可解析时会输出 `proof_connect_authority`，并要求同一 proof log 行绑定 token、计划 proxy URL 和 CONNECT authority；未传 token/log 时只生成同一显式会话的默认 proof token、proof target URL 和默认 proof log path。PAC/browser policy artifact `apply --confirm --pac-file <path> [--policy-file <path>] --snapshot <path>` 只写 NetworkCore PAC 文件、可选 Chromium/Chrome managed proxy policy artifact 和 rollback snapshot，`rollback --snapshot <path>` 只删除这些 artifact。系统/browser mutation、完整 live traffic verification、证书 lifecycle 和 HTTP/TLS data plane 仍必须等待后续源码实现并通过 GitHub Actions。

## Plugin And Data Plane Boundary

浏览器捕获只负责把浏览器流量送入 NetworkCore/MITM 数据面，不拥有插件解析或 rewrite 逻辑。

- MITM plugin/parser/runtime 仍归 `mitm-policy`、`MitmPluginService` 和
  [Third-Party Plugin Onboarding Process](third-party-plugin-onboarding-process.md) 管理。
- Native explicit-proxy CONNECT reject 归 `engine-native` 的
  `NativeHttpMitmPluginHook` 管理，只消费 `HttpMitmAction::Reject` 并写
  SOCKS5 failure response。
- HTTP/TLS 解密、HTTP parser、body buffering、script runtime 和 rewrite application 仍归
  `MITM_HTTP_TLS_DATA_PLANE_GATE`。
- CA generation、install、trust detection、revocation 和 rollback 仍归
  `MITM_CERTIFICATE_LIFECYCLE_GATE`。

因此，PAC/browser policy artifact apply 即使完成，也不得单独宣称 HTTPS MITM 可用；必须同时满足证书生命周期和 HTTP/TLS 数据面 gate。

## CI Governance

GitHub Actions 必须静态检查：

- 本合同文件存在并包含 `mitm-browser-capture-source-contract-status=active`。
- README、ROADMAP、TODO 和 CI policy 能发现本合同。
- `MITM_BROWSER_CAPTURE_GATE` 当前仍是 `pac-policy-profile-prefs-active/system-mutation-blocked`。
- `networkcore-linux mitm browser-plan` 和 `mitm_status.browser_plan` 仍保持 plan-only 机器字段。
- `BrowserCaptureAuthorization` 和 `BrowserCaptureRollbackSnapshot` 作为后续源码 anchor 可发现。
- `LinuxBrowserCaptureSessionPlanRequest`、`LinuxBrowserCaptureSessionPlanReport` 和 `cli.linux.mitm.browser_capture.session_plan.ready` 作为脱敏会话计划 anchor 可发现。
- `BrowserCaptureEndpointProbe`、`LinuxBrowserCaptureVerifyRequest` 和 `LinuxBrowserCaptureVerifyReport` 作为本地代理端点 verify anchor 可发现。
- `BrowserCaptureTrafficProofProbe`、`LinuxBrowserCaptureTrafficProofRequest`、`LinuxBrowserCaptureTrafficProofReport`、`proof-log-token`、`proof_connect_authority`、`proof_target_url`、`networkcore_proof_token`、`MITM_BROWSER_CAPTURE_DEFAULT_PROOF_LOG_PATH`、`traffic_proof_command` 和 `traffic_proof_report` 作为 proof-log-token traffic proof anchor 可发现。
- `BrowserCapturePacFileStore`、`CommandBrowserCapturePacFileStore`、`LinuxBrowserCapturePacRequest`、`LinuxBrowserCapturePacApplyOutcome`、`LinuxBrowserCapturePacRollbackOutcome`、`--pac-file`、`--policy-file`、`--profile-prefs-file`、`policy_file_path`、`policy_url`、`policy_content`、`profile_prefs_file_path`、`profile_prefs_content`、`cli.linux.mitm.browser_capture.apply.ready`、`cli.linux.mitm.browser_capture.apply.config_missing`、`cli.linux.mitm.browser_capture.pac.write_failed`、`cli.linux.mitm.browser_capture.policy.write_failed`、`cli.linux.mitm.browser_capture.profile_prefs.write_failed`、`cli.linux.mitm.browser_capture.snapshot.read_failed` 和 `cli.linux.mitm.browser_capture.rollback.ready` 作为 PAC/browser policy/profile prefs apply/rollback anchor 可发现。
- 当前源码不得实现无授权 browser/system proxy mutation。
- `session-plan` 必须由合同测试覆盖解析、脱敏 URL 来源、选中节点、本地代理命令模板、dedicated 浏览器命令、可选 `--target-url`、proof target URL、traffic-proof 命令、JSON `session_plan` 和不写系统状态边界。
- `launch --confirm` 必须通过 `BrowserCaptureProcessRunner` 注入执行，并由合同测试覆盖缺少授权、runner 成功、runner 未接线、可选 `--target-url`、proof target URL、traffic-proof command 和 JSON `launch_report`。
- `verify --confirm` 必须通过 `BrowserCaptureEndpointProbe` 注入执行，并由合同测试覆盖缺少授权、endpoint reachable、target URL `http-connect-target` reachable、target URL invalid、endpoint unreachable、未接线 blocked 和 JSON `verify_report`。
- `traffic-proof --confirm` 必须通过 `BrowserCaptureTrafficProofProbe` 注入执行，并由合同测试覆盖缺少授权、可选 `--target-url` 默认 proof 绑定、proof token observed、proof token/proxy/CONNECT authority binding mismatch、proof token missing、未接线 blocked 和 JSON `traffic_proof_report`。
- `apply --confirm --pac-file <path> [--policy-file <path>] [--profile-prefs-file <path>] --snapshot <path>` 和 `rollback --snapshot <path>` 必须通过 `BrowserCapturePacFileStore` 注入执行，并由合同测试覆盖缺少 PAC/snapshot config、PAC/browser policy/profile prefs artifact 写入、rollback、entrypoint routing 和 JSON artifact fields。
- 本机不得运行测试、构建、打包或发布验证。

如果某个浏览器或系统设置必须人工操作才能验证，必须先写入 `docs/manual-intervention.md`，并说明人工动作完成后下一步
GitHub Actions 如何继续验证。
