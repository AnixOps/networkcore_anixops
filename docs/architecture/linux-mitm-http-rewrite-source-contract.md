# Linux MITM HTTP Rewrite Source Contract

评估时间：2026-07-09。

当前合同状态：

```text
mitm-http-rewrite-source-contract-status=active
MITM_HTTP_TLS_DATA_PLANE_GATE=plain-http-live-data-plane-active/tls-decryption-blocked
```

本文固定 Linux MITM HTTP rewrite 从 caller-provided preview foundation 推进到
explicit plain HTTP proxy live data plane，并开始进入 explicit HTTP CONNECT tunnel foundation
后必须遵守的源码边界。当前仓库允许调用方通过
`networkcore-linux mitm http-rewrite preview --confirm --url <url>` 对一条调用方提供的
HTTP message 应用 plugin outcome，也允许 `ListenerKind::Http` 的 native explicit HTTP proxy
路径解析真实 `http://` HTTP/1.x 请求，交给内置 `networkcore.adblock` 或注入的
`NativeHttpMitmPluginHook` 生成 `HttpMitmOutcome`，并在 request/response 两阶段应用
reject、redirect、header mutation 和 body mutation。`CONNECT host:443` 已可经既有 SOCKS
outbound primitive 建立标准 `HTTP/1.1 200 Connection Established` tunnel，在 relay 前 bounded
peek TLS ClientHello/SNI，并做有限双向 relay，作为后续 TLS MITM foundation 的第一步。该能力仍
不解密 TLS，不执行 downstream TLS termination，不解析 CONNECT 后 HTTPS request/response，不安装或
信任 CA，不修改 browser/system proxy、system PAC、TUN、DNS 或 firewall，也不执行插件脚本。

## Current Boundary

- `networkcore-linux mitm http-rewrite plan` 输出 `http_rewrite` report，声明 source contract
  active、mutation_ready=true、live_traffic_ready=true 和 tls_decryption_ready=false。
- `networkcore-linux mitm http-rewrite preview --confirm --url <url> [--method <method>] [--phase request|response] [--status-code <code>] [--header <name:value>] [--body <text>]` 继续消费调用方提供的明文 HTTP 输入，作为可重复 preview/debug 入口。
- `engine-native` 允许 `ListenerKind::Http` 通过 `NativeLoopbackTcpAcceptLoopHandle` 接收 explicit HTTP proxy 请求；`ListenerKind::Socks` 和 `ListenerKind::LocalTcp` 继续走既有 SOCKS5 path。
- `read_explicit_http_proxy_request` 只支持 bounded HTTP/1.x、absolute-form `http://` request target、origin-form + `Host` 和 `Content-Length` body；`Transfer-Encoding: chunked`、streaming body、HTTP/2 和 request smuggling 场景继续不承诺。
- `CONNECT` target 在 HTTP listener 中会先生成 `NativeTlsMitmFoundationReport`，再经既有
  SOCKS outbound CONNECT primitive 建立 tunnel；成功后写标准空 body `200 Connection Established`
  response 并进行有限 TCP relay。
- `CONNECT` relay 前会通过 `observe_explicit_http_connect_tls_client_hello` 对已到达 bytes 做
  bounded `peek`，生成 `NativeTlsClientHelloObservationReport`；可观察 TLS record/handshake
  version 和 SNI hostname，但不消费 client bytes，也不终止 TLS。
- `CONNECT` tunnel foundation 只证明 explicit HTTP proxy 到 SOCKS outbound 的 tunnel path；
  `NativeTlsMitmFoundationReport.downstream_tls_termination_ready=false`、
  `https_request_rewrite_ready=false`、`https_response_rewrite_ready=false` 和
  `script_dispatch_ready=false`。
- `https://` absolute-form target 在 HTTP listener 中仍返回 TLS blocked 诊断；HTTPS 必须通过
  CONNECT path 进入后续 TLS foundation。
- 非 terminal request rewrite 会经既有 SOCKS outbound CONNECT primitive 转发到目标 host:port，并以 origin-form request 写给 upstream；bounded upstream response 会再进入 response phase rewrite 后写回 client。
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
- `NativeExplicitHttpProxyRequest`
- `NativePlainHttpProxyResponse`
- `NativeTlsMitmFoundationReport`
- `NativeTlsClientHelloObservationReport`
- `read_explicit_http_proxy_request`
- `apply_http_mitm_outcome_to_live_plain_http_request`
- `serialize_explicit_http_proxy_request_for_upstream`
- `plan_explicit_http_connect_tls_mitm_foundation`
- `observe_explicit_http_connect_tls_client_hello`
- `write_http_connect_established_response`
- `plan_and_apply_plain_http_mitm`
- `apply_http_mitm_outcome_to_plain_http_message`
- `ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_EVENT_PLANNED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_PLAN_READY_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_TERMINAL_ACTION_APPLIED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_HEADER_MUTATION_APPLIED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_BODY_MUTATION_APPLIED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_SCRIPT_DISPATCH_DEFERRED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REQUEST_READ_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CONNECT_TLS_BLOCKED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_FOUNDATION_READY_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CONNECT_TUNNEL_ESTABLISHED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CLIENT_HELLO_OBSERVED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CLIENT_HELLO_DEFERRED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REWRITE_APPLIED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_REQUEST_WRITTEN_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_RESPONSE_READ_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITTEN_CODE`
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
- 把 caller-provided preview 输入等同于 live browser traffic capture；live path 仅限用户或 dedicated browser 显式指向 HTTP proxy listener 的 `http://` 请求。
- 把明文 HTTP live data plane 等同于完整 HTTPS rewrite。
- 执行 JavaScript plugin script dispatch。
- 在没有显式 `--confirm` 的情况下应用 rewrite outcome。

## CI Governance

CI 必须静态检查源码中的命令、类型、诊断 code、JSON report 字段、文档 anchor、
gate 状态和合同测试。任何后续把 TLS decryption、HTTPS request/response rewrite、
script runtime 或 browser/system capture mutation 从 blocked 改为 active 的提交，必须先新增或修订
source contract，覆盖 CA trust、TLS interception、HTTP parser、body buffering、script runtime、
browser/system capture、rollback 和显式授权边界。
