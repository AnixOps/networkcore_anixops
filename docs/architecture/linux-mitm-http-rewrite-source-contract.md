# Linux MITM HTTP Rewrite Source Contract

评估时间：2026-07-09。

当前合同状态：

```text
mitm-http-rewrite-source-contract-status=active
MITM_HTTP_TLS_DATA_PLANE_GATE=plain-http-live-data-plane-active/tls-decryption-blocked
controlled-tls-and-script-runtime-source=implemented-ci-pending
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
peek TLS ClientHello/SNI，并做有限双向 relay，作为后续 TLS MITM foundation 的第一步。当前 main
还新增 controlled downstream TLS termination plan：在 CONNECT tunnel、ClientHello/SNI 和 NetworkCore CA
certificate/private key PEM material 同时具备时输出 plan-ready 诊断。当前 main 还新增
authority-bound TLS leaf certificate issuance：只在 controlled termination plan ready、CA PEM
material 可解析且 CONNECT authority/SNI 仍一致时，由 NetworkCore CA 签发含 server-auth EKU 的
leaf certificate material；该 material 不写入 report debug output，不安装到系统。当前 main 还新增 rustls
downstream/upstream configuration 和受控 engine path：仅由 `NativeProxyEngineService` 显式注入 CA
material 时，HTTP listener 的 CONNECT path 会完成 downstream TLS termination、web-PKI-verified
upstream TLS、bounded HTTP/1.1 request/response rewrite exchange；Linux CLI 仅在 `start` 同时使用
`--enable-https-mitm --mitm-ca-cert --mitm-ca-key --confirm` 时读取并注入 material，默认启动继续保持
pass-through public boundary。当前 main 还新增
caller-provided HTTPS request rewrite preview：在 controlled TLS termination plan ready 且输入为
request-phase `https://` message 时，可对 reject、redirect 和 request header mutation 生成 preview
application report。当前 main 还新增 caller-provided HTTPS response rewrite preview：在 controlled TLS
termination plan ready 且输入为 response-phase `https://` message 时，可对 response header mutation
和受 content-type/body-size/buffering guard 约束的 response body mutation 生成 preview application
report。受控 live engine path 还可在显式 `--enable-script-runtime --script-runner <local-runner>`、至少一个
`--script-map <script-url>=<local-file>` 与 `--confirm` 同时存在时，调用本地 Node runner 执行映射后的
可信插件脚本；它限制 body、超时和输出协议，脚本失败或没有映射时 fail-open 并保留 deferred diagnostic。
该能力不安装或信任 CA，不修改 browser/system proxy、system PAC、TUN、DNS 或 firewall。公开发行门禁在
GitHub Actions 完整 E2E/security 验证前仍保持 `tls-decryption-blocked`，本地结果不能替代该门禁。

## Current Boundary

- `networkcore-linux mitm http-rewrite plan` 输出 `http_rewrite` report，声明 source contract
  active、mutation_ready=true、live_traffic_ready=true 和 tls_decryption_ready=false。
- `networkcore-linux mitm http-rewrite preview --confirm --url <url> [--method <method>] [--phase request|response] [--status-code <code>] [--header <name:value>] [--body <text>]` 继续消费调用方提供的明文 HTTP 输入，作为可重复 preview/debug 入口。
- `engine-native` 允许 `ListenerKind::Http` 通过 `NativeLoopbackTcpAcceptLoopHandle` 接收 explicit HTTP proxy 请求；`ListenerKind::Socks` 和 `ListenerKind::LocalTcp` 继续走既有 SOCKS5 path。
- accept loop 会为每个已接受连接启动独立 worker，并在 shutdown 时汇总 worker diagnostics；同时在
  loopback listener 上限制最多 64 个并发连接，达到上限只关闭新连接并记录 stable diagnostic，避免单一
  TLS/HTTP session 阻塞后续 proxy traffic 或无限制创建 worker。
- `read_explicit_http_proxy_request` 只支持 bounded HTTP/1.x、absolute-form `http://` request target、origin-form + `Host` 和 `Content-Length` body；`Transfer-Encoding: chunked`、streaming body、HTTP/2 和 request smuggling 场景继续不承诺。
- `CONNECT` target 在 HTTP listener 中会先生成 `NativeTlsMitmFoundationReport`，再经既有
  SOCKS outbound CONNECT primitive 建立 tunnel；成功后写标准空 body `200 Connection Established`
  response。未配置 CA material 时继续进行有限 TCP relay；配置 material 时进入受控 TLS path。
- `CONNECT` relay 前会通过 `observe_explicit_http_connect_tls_client_hello` 对已到达 bytes 做
  bounded `peek`，生成 `NativeTlsClientHelloObservationReport`；可观察 TLS record/handshake
  version 和 SNI hostname，但不消费 client bytes，也不终止 TLS。未启用 CA material 的 pass-through
  只进行一次 observation；受控 TLS path 最多在 1 秒 bounded window 内轮询完整 ClientHello，避免将正常
  TCP fragmentation 误判为缺失 SNI。
- `CONNECT` tunnel foundation 只证明 explicit HTTP proxy 到 SOCKS outbound 的 tunnel path；
  `NativeTlsMitmFoundationReport.downstream_tls_termination_ready=false`、
  `https_request_rewrite_ready=false`、`https_response_rewrite_ready=false` 和
  `script_dispatch_ready=false`。
- `plan_explicit_http_connect_controlled_tls_termination` 只生成 controlled TLS termination plan report；
  当 CONNECT tunnel、ClientHello/SNI、CONNECT authority 与 SNI hostname 一致、以及 NetworkCore CA
  certificate/private key PEM material 同时具备时，
  `NativeControlledTlsTerminationPlanReport.downstream_tls_termination_plan_ready=true`，但
  `live_https_decryption_ready=false`、`https_request_rewrite_ready=false`、
  `https_response_rewrite_ready=false` 和 `script_dispatch_ready=false`。
- `issue_controlled_tls_termination_leaf_certificate` 只为已经 ready 的 controlled TLS plan 签发与
  normalized CONNECT authority 绑定的 leaf certificate；它会再次检查 plan 中的 SNI/authority
  一致性，使用 CA certificate/private-key PEM 解析 `Issuer`，并赋予 leaf `serverAuth` EKU。失败、
  缺失或不匹配输入只能返回无 material 的 stable diagnostic；证书和私钥不进入 `Debug` 输出。
  签发 leaf material 本身不代表 TLS handshake、live HTTPS decryption、HTTP parser 或 rewrite 已启用。
- `build_controlled_tls_termination_server_config` 把 authority-bound leaf DER material 转为受控的
  `rustls::ServerConfig`；`build_controlled_tls_upstream_client_config` 使用 web-PKI roots 创建
  TLS 1.2/1.3 upstream client config。empty material、不匹配 certificate/key、无 trust root 或无效
  authority 只能返回 failure diagnostic。
- `NativeProxyEngineService::with_tls_mitm_ca_material` 是唯一 engine-level activation boundary：它会把
  redacted CA material 传到 accept loop。受控 CONNECT path 重新绑定 decrypted origin-form request 到
  CONNECT authority，拒绝 inner Host mismatch，以 TLS 终止后的 HTTP/1.1 请求/响应继续调用现有
  `NativeHttpMitmPluginHook` request/response rewrite；没有 material 时绝不尝试 TLS termination。
  Linux CLI 只在 `start --enable-https-mitm --mitm-ca-cert <path> --mitm-ca-key <path> --confirm`
  中读取 material；缺任一 flag、路径、内容或 confirmation 都拒绝启动，且不回显 key。该 release
  path 在 TLS handshake、request/response 交换期间使用独立 15 秒受限 I/O timeout，仍须 GitHub
  Actions E2E/安全门禁通过，故 public release gate 在验证前继续 blocked。
- `NativeHttpMitmPluginHook::with_node_script_executor` 是 live script activation boundary。CLI 只有在
  `start --enable-script-runtime --script-runner <local-runner> --script-map <script-url>=<local-file>
  [--script-map ...] [--script-store <path>] [--node-binary <path>] --confirm` 时创建 executor；runner 和
  每个 asset 必须是本地普通文件，script URL 只可映射到明确配置的本地 asset，绝不自动下载远程脚本。
  executor 只传递 staged temporary file 中的 bounded UTF-8 body（Unix owner-only permission）、受规则和
  runtime 双重约束的超时，以及 request/response phase；执行失败、超时、非 UTF-8 body、未映射 asset 或
  无效 runner output 一律不改写原消息。脚本 URL mutation 仅可
  保留原 scheme/authority/port 后改变路径，跨 authority 或 scheme 的 mutation 会拒绝并产生 diagnostic。
  Node runner 执行的 asset 必须视为操作员显式信任的本地代码，不把该进程模型描述为安全 sandbox。
- `plan_and_apply_https_request_rewrite_preview` 只消费调用方提供的 request-phase `https://`
  `NativePlainHttpMessage` 和 `HttpMitmOutcome`，并要求 controlled TLS termination plan 已 ready；它可在
  `NativeHttpsRequestRewritePreviewReport` 中表达 reject、redirect 和 request header mutation preview
  application，同时保持 `https_response_rewrite_ready=false`、`script_dispatch_ready=false`、
  body mutation deferred 和 live HTTPS decryption blocked。
- `plan_and_apply_https_response_rewrite_preview` 只消费调用方提供的 response-phase `https://`
  `NativePlainHttpMessage` 和 `HttpMitmOutcome`，并要求 controlled TLS termination plan 已 ready；它可在
  `NativeHttpsResponseRewritePreviewReport` 中表达 reject、redirect、response header mutation 和
  response body mutation preview application。response body mutation 必须同时通过 content-type guard、
  body-size guard 和 bounded buffering guard；未通过时只报告 `body_mutation_deferred=true`，不改写 body。
- `https://` absolute-form target 在 HTTP listener 中仍返回 TLS blocked 诊断；HTTPS 必须通过
  CONNECT path 进入后续 TLS foundation。
- 非 terminal request rewrite 会经既有 SOCKS outbound CONNECT primitive 转发到目标 host:port，并以 origin-form request 写给 upstream；bounded upstream response 会再进入 response phase rewrite 后写回 client。
- 缺少 `--confirm` 时返回 `cli.linux.mitm.http_rewrite.authorization_required`，不应用插件 outcome。
- 缺少 `--url` 时返回 `cli.linux.mitm.http_rewrite.config_missing`。
- Preview 通过 `NativePlainHttpMessage` 映射 `HttpMitmEvent`，调用 `MitmPluginService::handle_http_mitm_event`，再返回 `NativePlainHttpRewriteReport`。
- `Reject` terminal action 会生成 final status、清空 body 并设置 `Content-Length: 0`。
- `Redirect` terminal action 会生成 final status、设置 `Location` 和 `Content-Length: 0` 并清空 body。
- Header mutation 支持 add、replace、delete 和 set；body mutation 替换 output body。
- 未配置 executor 的 preview/default path 继续记录 `script_dispatch_deferred=true`，不运行脚本；只有上述
  显式启用的 live engine hook 执行已映射本地 JavaScript asset，并在成功时设置
  `script_dispatch_executed=true`、清除 `script_dispatch_deferred`。
- `http_rewrite` JSON/text report 输出 request、authorization、outcome、output_headers、output_body 和 blocked_operations。
- `http_rewrite` JSON/text report 同时输出 `controlled_tls_termination_plan_ready`、
  `downstream_tls_termination_plan_ready` 和 `upstream_tls_forwarding_ready`，但必须继续输出
  `tls_decryption_ready=false`。
- `http_rewrite` JSON/text report 还输出 `https_request_rewrite_preview_ready=true`、
  `https_response_rewrite_preview_ready=true`、`https_response_rewrite_ready=false` 和
  `script_dispatch_ready=false`，明确 alpha.18 仅开放 caller-provided HTTPS request/response rewrite
  preview，不开放 live HTTPS response rewrite 或脚本执行。

## Source Anchors

当前源码必须保留或通过 CI governance 显式迁移以下 NetworkCore-owned anchors：

- `NativePlainHttpMessage`
- `NativePlainHttpRewriteApplication`
- `NativePlainHttpRewriteReport`
- `NativeExplicitHttpProxyRequest`
- `NativePlainHttpProxyResponse`
- `NativeTlsMitmFoundationReport`
- `NativeTlsClientHelloObservationReport`
- `NativeControlledTlsTerminationPlanReport`
- `NativeTlsLeafCertificateMaterial`
- `NativeTlsLeafCertificateIssueReport`
- `NativeTlsServerConfigBuildReport`
- `NativeTlsUpstreamClientConfigBuildReport`
- `NativeTlsMitmCaMaterial`
- `NativeNodeScriptRuntimeConfig`
- `NativeNodeScriptExecutor`
- `NativeHttpScriptExecutionReport`
- `NativeHttpsRequestRewritePreviewReport`
- `NativeHttpsResponseRewritePreviewReport`
- `read_explicit_http_proxy_request`
- `apply_http_mitm_outcome_to_live_plain_http_request`
- `serialize_explicit_http_proxy_request_for_upstream`
- `plan_explicit_http_connect_tls_mitm_foundation`
- `observe_explicit_http_connect_tls_client_hello`
- `plan_explicit_http_connect_controlled_tls_termination`
- `issue_controlled_tls_termination_leaf_certificate`
- `build_controlled_tls_termination_server_config`
- `build_controlled_tls_upstream_client_config`
- `read_https_connect_http_request`
- `NativeProxyEngineService::with_tls_mitm_ca_material`
- `NativeHttpMitmPluginHook::with_node_script_executor`
- `native_proxy_engine_service_with_builtin_mitm_plugin_and_runtime_files`
- `native_proxy_engine_service_with_builtin_mitm_plugin_and_tls_mitm_files`
- `plan_and_apply_https_request_rewrite_preview`
- `plan_and_apply_https_response_rewrite_preview`
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
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SNI_AUTHORITY_MATCHED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SNI_AUTHORITY_MISMATCH_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_TERMINATION_PLAN_READY_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_TERMINATION_DEFERRED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_LEAF_CERTIFICATE_ISSUED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_LEAF_CERTIFICATE_DEFERRED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_LEAF_CERTIFICATE_FAILED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SERVER_CONFIG_READY_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SERVER_CONFIG_FAILED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_UPSTREAM_CONFIG_READY_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_UPSTREAM_CONFIG_FAILED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SESSION_DECRYPTION_READY_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SESSION_DECRYPTION_FAILED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_EXECUTED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_DEFERRED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_FAILED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_URL_MUTATION_BLOCKED_CODE`
- `CLI_START_TLS_MITM_AUTHORIZATION_REQUIRED_CODE`
- `CLI_START_TLS_MITM_MATERIAL_REQUIRED_CODE`
- `CLI_START_TLS_MITM_MATERIAL_READ_FAILED_CODE`
- `CLI_START_SCRIPT_RUNTIME_AUTHORIZATION_REQUIRED_CODE`
- `CLI_START_SCRIPT_RUNTIME_CONFIG_REQUIRED_CODE`
- `CLI_START_SCRIPT_RUNTIME_CONFIG_INVALID_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_REQUEST_REWRITE_PREVIEW_READY_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_REQUEST_REWRITE_PREVIEW_DEFERRED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_REQUEST_REWRITE_SCRIPT_DEFERRED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_RESPONSE_REWRITE_PREVIEW_READY_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_RESPONSE_REWRITE_PREVIEW_DEFERRED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_RESPONSE_REWRITE_SCRIPT_DEFERRED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REWRITE_APPLIED_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_REQUEST_WRITTEN_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_RESPONSE_READ_CODE`
- `ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITTEN_CODE`
- `LinuxMitmHttpRewriteReport`
- `controlled_tls_termination_plan_ready`
- `downstream_tls_termination_plan_ready`
- `upstream_tls_forwarding_ready`
- `https_request_rewrite_preview_ready`
- `https_response_rewrite_preview_ready`
- `https_response_rewrite_ready`
- `content_type_guard_ready`
- `body_size_limit_bytes`
- `body_buffering_guard_ready`
- `script_dispatch_ready`
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
- `--enable-https-mitm`
- `--mitm-ca-cert`
- `--mitm-ca-key`
- `--enable-script-runtime`
- `--script-runner`
- `--script-map`
- `--script-store`
- `--node-binary`
- `cli.linux.mitm.http_rewrite.authorization_required`
- `cli.linux.mitm.http_rewrite.plan.ready`
- `cli.linux.mitm.http_rewrite.apply.ready`
- `cli.linux.mitm.http_rewrite.config_missing`
- `cli.linux.mitm.http_rewrite.tls_blocked`

## Explicitly Blocked

当前合同明确禁止：

- 在没有显式 `NativeTlsMitmCaMaterial` 的默认/CLI path 执行 live HTTPS decryption 或真实 TLS stream termination。
- 在没有 `--enable-https-mitm --mitm-ca-cert --mitm-ca-key --confirm` 的 Linux CLI start path 读取或使用 CA material。
- 把 caller-provided HTTPS request rewrite preview 等同于 live CONNECT 后 HTTPS request rewrite。
- 把 caller-provided HTTPS response rewrite preview 等同于 live CONNECT 后 HTTPS response rewrite。
- 在 alpha.18 response preview 中绕过 content-type/body-size/buffering guard 应用 body mutation。
- 在 CONNECT authority 与 ClientHello SNI 不一致或 SNI 缺失时启用 downstream TLS termination。
- 在未明确配置本地 runner、local asset map 和 `--confirm` 时执行 JavaScript script dispatch。
- 安装、信任、撤销或回滚 system trust store、NSS DB、p11-kit 或 Firefox trust store。
- 修改 browser/system proxy、system PAC、TUN、DNS、firewall 或路由状态。
- 把 caller-provided preview 输入等同于 live browser traffic capture；live path 仅限用户或 dedicated browser 显式指向 HTTP proxy listener 的 `http://` 请求。
- 把明文 HTTP live data plane 等同于完整 HTTPS rewrite。
- 从远程 URL 自动下载、缓存或执行 JavaScript plugin script dispatch。
- 在没有显式 `--confirm` 的情况下应用 rewrite outcome。

## CI Governance

CI 必须静态检查源码中的命令、类型、诊断 code、JSON report 字段、文档 anchor、
gate 状态和合同测试，并在 Rust matrix 中提供 Node 22 以执行本地 runner 合同测试。任何把本 source
increment 标记为可公开发行的提交，必须先让 GitHub Actions 覆盖 CA trust、TLS interception、HTTP parser、
body buffering、script runtime、browser/system capture、rollback 和显式授权边界。至少一条 live-socket
contract 必须同时验证 downstream TLS decrypt、upstream TLS forward 与 request/response script dispatch；本地
环境不得替代该结论。
