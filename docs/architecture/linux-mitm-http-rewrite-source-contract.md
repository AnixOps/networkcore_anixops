# Linux MITM HTTP Rewrite Source Contract

评估时间：2026-07-09。

当前合同状态：

```text
mitm-http-rewrite-source-contract-status=active
MITM_HTTP_TLS_DATA_PLANE_GATE=plain-http-rewrite-foundation-active/tls-decryption-blocked
```

本文固定 Linux MITM HTTP rewrite 从 policy-only plan 进入显式明文 HTTP
rewrite foundation 后必须遵守的源码边界。当前仓库允许调用方通过
`networkcore-linux mitm http-rewrite preview --confirm --url <url>` 把一条调用方提供的
HTTP message 映射成 `HttpMitmEvent`，交给内置 `networkcore.adblock`
插件生成 `HttpMitmOutcome`，并把 reject、redirect、header mutation 和 body mutation
应用到该合成输入。该能力不解密 TLS，不拦截真实浏览器或系统流量，不安装或信任 CA，
不修改 browser/system proxy、system PAC、TUN、DNS 或 firewall，也不执行插件脚本。

## Current Boundary

- `networkcore-linux mitm http-rewrite plan` 输出 `http_rewrite` report，声明 source contract
  active、mutation_ready=true、live_traffic_ready=false 和 tls_decryption_ready=false。
- `networkcore-linux mitm http-rewrite preview --confirm --url <url> [--method <method>] [--phase request|response] [--status-code <code>] [--header <name:value>] [--body <text>]` 只消费调用方提供的明文 HTTP 输入。
- 缺少 `--confirm` 时返回 `cli.linux.mitm.http_rewrite.authorization_required`，不应用插件 outcome。
- 缺少 `--url` 时返回 `cli.linux.mitm.http_rewrite.config_missing`。
- Preview 通过 `NativePlainHttpMessage` 映射 `HttpMitmEvent`，调用 `MitmPluginService::handle_http_mitm_event`，再返回 `NativePlainHttpRewriteReport`。
- `Reject` terminal action 会生成 final status、清空 body 并设置 `Content-Length: 0`。
- `Redirect` terminal action 会生成 final status、设置 `Location` 和 `Content-Length: 0` 并清空 body。
- Header mutation 支持 add、replace、delete 和 set；body mutation 替换 output body。
- `HttpMitmScriptDispatch` 只记录 `script_dispatch_deferred=true`，不运行 JavaScript 或外部脚本。
- `http_rewrite` JSON/text report 输出 request、authorization、outcome、output_headers、output_body 和 blocked_operations。

## Source Anchors

当前源码必须保留或通过 CI governance 显式迁移以下 NetworkCore-owned anchors：

- `NativePlainHttpMessage`
- `NativePlainHttpRewriteApplication`
- `NativePlainHttpRewriteReport`
- `plan_and_apply_plain_http_mitm`
- `apply_http_mitm_outcome_to_plain_http_message`
- `ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_EVENT_PLANNED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_PLAN_READY_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_TERMINAL_ACTION_APPLIED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_HEADER_MUTATION_APPLIED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_BODY_MUTATION_APPLIED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_SCRIPT_DISPATCH_DEFERRED_CODE`
- `LinuxMitmHttpRewriteReport`
- `LinuxMitmHttpRewriteRequest`
- `LinuxMitmHttpRewriteOutcomeReport`
- `LinuxMitmHttpRewriteAuthorization`
- `handle_mitm_http_rewrite_plan`
- `handle_mitm_http_rewrite_preview`
- `http_rewrite`
- `--url`
- `--method`
- `--phase`
- `--status-code`
- `--header`
- `--body`
- `cli.linux.mitm.http_rewrite.authorization_required`
- `cli.linux.mitm.http_rewrite.plan.ready`
- `cli.linux.mitm.http_rewrite.apply.ready`
- `cli.linux.mitm.http_rewrite.config_missing`
- `cli.linux.mitm.http_rewrite.tls_blocked`

## Explicitly Blocked

当前合同明确禁止：

- 解密 HTTPS 或终止 TLS。
- 安装、信任、撤销或回滚 system trust store、NSS DB、p11-kit 或 Firefox trust store。
- 修改 browser/system proxy、system PAC、TUN、DNS、firewall 或路由状态。
- 把 caller-provided preview 输入等同于 live browser traffic capture。
- 把明文 HTTP rewrite foundation 等同于完整 HTTPS rewrite。
- 执行 JavaScript plugin script dispatch。
- 在没有显式 `--confirm` 的情况下应用 rewrite outcome。

## CI Governance

CI 必须静态检查源码中的命令、类型、诊断 code、JSON report 字段、文档 anchor、
gate 状态和合同测试。任何后续把 TLS decryption 或 live traffic mutation 从 blocked
改为 active 的提交，必须先新增或修订 source contract，覆盖 CA trust、TLS interception、
HTTP parser、body buffering、script runtime、browser/system capture、rollback 和显式授权边界。
