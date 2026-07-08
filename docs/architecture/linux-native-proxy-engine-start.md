# Linux Native Proxy Engine Start Design

本文定义首个原生代理执行内核源码进入仓库前必须满足的 `ProxyEngineService`
adapter、前台生命周期 host 和 `networkcore-linux start` 接线边界。它承接
[Proxy Engine Adapter Interface](proxy-engine-adapter.md)、
[Native Engine Listener And Node Config Design](native-engine-listener-node-config.md)、
[Subscription Catalog Runtime Orchestration Design](subscription-catalog-runtime-orchestration.md)、
[Linux CLI Runtime Wiring Design](linux-cli-runtime-wiring.md)、
[Linux CLI Entrypoint Design](linux-cli-entrypoint.md) 和
[Linux Platform Adapter Design](linux-platform-adapter.md)。

评估时间：2026-07-06。

## 目标

- 明确首个原生执行内核 adapter 的职责、crate 边界和诊断合同。
- 明确 `networkcore-linux start` 何时可以从稳定 unavailable 诊断进入前台运行模式。
- 防止空壳 adapter、一次性配置校验或测试替身被误认为 runtime 已启动。
- 为后续最小 `engine-native` 源码增量提供可验证、可回滚的接线门槛。

## 非目标

- 不在本文实现 UDP、TUN、DNS、完整 HTTP/TLS MITM 或透明代理协议。
- 不在本文实现 daemon、control socket、systemd unit、PID file、installer 或 release artifact。
- 不选择 async runtime、socket 库、packet capture、netlink 或平台代理 SDK。
- 不启动外部 `sing-box`、`xray-core`、`mihomo` 或其他二进制。
- 不在本机运行、构建、测试、打包或试用 CLI。

## 当前源码状态

当前仓库已经具备：

- `control-domain::ProxyEngineService` 领域端口，定义 engine descriptor、配置校验、启动、重载、停止、状态和事件读取。
- `control-runtime::RuntimeOrchestrator::start_runtime`，按平台、配置和引擎校验顺序编排启动。
- `config-core::CoreConfigurationService`，提供只读 TOML schema/profile 和最小 listener/node/route 配置准备。
- `config-core::CoreSubscriptionService`，提供纯内存 `inline:` subscription source 解析，把最小 subscription TOML `nodes`/`routes` 子集归一化为 `NodeCatalog`；subscription catalog runtime gate 已在 `control-runtime` 支持显式 `SubscriptionService`/`SubscriptionSource` handoff 和重复 id 拒绝边界，当前 `networkcore-linux start` 还不消费 subscription catalog。
- [Native Engine Listener And Node Config Design](native-engine-listener-node-config.md) 定义后续 listener、node、route 和 DNS 配置图进入 `engine-native` 前的模型边界。
- `engine-native::NativeProxyEngineService`，提供原生 engine descriptor、listener/node/route 结构化图校验、service-owned runtime state、`start`/`status`/`events`/`stop` 生命周期合同。
- `engine-native` 已补充首个 native runtime handle 源码合同，覆盖 loopback listener handle、SOCKS outbound handler handoff、启动失败释放报告、runtime events 和 foreground lifecycle handoff status。
- `engine-native` 已补充真实 loopback TCP listener 绑定/释放实现，runtime assembly 可持有当前进程内的 `TcpListener` resource。
- `engine-native` 已补充从有效配置图生成首个 native runtime assembly plan 的源码合同，选择 loopback TCP listener 与 SOCKS outbound handler，并覆盖绑定失败和 lifecycle handoff 失败的释放报告。
- `engine-native` 已补充首个 loopback TCP accept loop 与受控关闭源码合同，覆盖 accepted connection 计数、runtime release 停止报告和 ready/stopped 诊断。
- `engine-native` 已补充 accepted TCP connection 的协议前置关闭诊断合同；未完成 SOCKS5 route/outbound 处理的 accepted connection 会记录 pre-protocol close 计数和 `engine.native.runtime.connection_pre_protocol_closed` 诊断。
- `engine-native` 已补充首个 SOCKS5 greeting 版本/认证方法读取诊断合同，可在 accepted loopback TCP connection 上读取 greeting 并记录 `engine.native.runtime.socks5_greeting_read`、`engine.native.runtime.socks5_greeting_invalid` 或 `engine.native.runtime.socks5_greeting_read_failed` 诊断。
- `engine-native` 已补充 SOCKS5 no-auth 方法选择与 unsupported auth 方法拒绝诊断合同，可在有效 greeting 后记录 `engine.native.runtime.socks5_auth_method_selected` 或 `engine.native.runtime.socks5_auth_method_unsupported` 诊断，并继续进入后续方法响应、命令和 CONNECT route/outbound 分支。
- `engine-native` 已补充 SOCKS5 认证方法响应写入诊断合同，可写入 `[0x05, method]` 响应并记录 `engine.native.runtime.socks5_auth_method_response_written` 或 `engine.native.runtime.socks5_auth_method_response_write_failed` 诊断。
- `engine-native` 已补充 SOCKS5 命令头读取与 unsupported command 拒绝诊断合同，可在 no-auth 响应后读取 `[VER, CMD, RSV, ATYP]` 并记录 `engine.native.runtime.socks5_command_header_read`、`engine.native.runtime.socks5_command_header_invalid` 或 `engine.native.runtime.socks5_command_header_read_failed` 诊断，对非 CONNECT 命令记录 `engine.native.runtime.socks5_command_unsupported`。
- `engine-native` 已补充 SOCKS5 CONNECT 目标地址读取、route/outbound 行为选择、SOCKS outbound CONNECT request frame 生成、SOCKS outbound TCP connection plan、SOCKS outbound TCP connection attempt、SOCKS outbound CONNECT request write、SOCKS outbound CONNECT response read、SOCKS outbound CONNECT response decision、SOCKS outbound CONNECT relay readiness、SOCKS outbound CONNECT data relay plan、SOCKS outbound CONNECT data relay execution、SOCKS outbound CONNECT client success response readiness、SOCKS outbound CONNECT client success response write plan、SOCKS outbound CONNECT client success response write、accept loop client success response 与有限 data relay 接线、未接入拒绝与 CONNECT failure response 写入诊断合同。accept loop 在上游 CONNECT accepted 后记录 ready 诊断，写入 client success response frame，再对有限 client/outbound TCP stream 执行双向复制并记录 completed/failed data relay 诊断；上游 rejected、连接失败或 plan 不完整路径继续写 SOCKS5 general failure response。
- `engine-native` 已补充 `NativeHttpMitmPluginHook` 和 `plan_socks5_connect_http_mitm` 源码合同；当注入的 MITM plugin 对 SOCKS5 CONNECT target 返回 `Reject` 时，accept loop 会在 route/outbound selection 前写 SOCKS5 general failure response 并跳过 outbound，并通过 `engine.native.runtime.http_mitm_connect_browser_proof_observed` 输出由 CONNECT endpoint 和本地 socks5 proxy URL 派生的默认 browser proof token。该能力不解密 TLS，不应用 redirect/header/body/script rewrite。
- `engine-native` 已补充 service-owned runtime state 与 foreground lifecycle handoff 源码合同；有效配置能生成 native runtime assembly plan 时记录 `engine.native.start.runtime_assembly_ready`，`NativeProxyEngineService::start` 随后启动 loopback TCP accept loop、保存当前进程内 runtime handle，并返回 `engine.native.start.running`、`engine.native.runtime.foreground_handoff_ready` 与 `engine.native.runtime.accept_loop_ready`；`status`/`events`/`stop` 可观察和释放该 runtime。
- `networkcore-linux` 库层提供 `ForegroundLifecycleHost`、`ForegroundLifecycleRequest`、`ForegroundLifecycleOutcome`、默认 unavailable host 和 `handle_foreground_lifecycle` 合同，覆盖前台 handoff 诊断聚合。
- `platform-linux::ReadOnlyLinuxPlatformCapabilityService<HostLinuxReadOnlyProbe>`，提供只读 Linux 平台能力诊断。
- `networkcore-linux` binary 已将 `prepare-config` 接入 `RuntimeOrchestrator`，并将 `start` 接入带内置 `networkcore.adblock` MITM hook 的 `NativeProxyEngineService` 与 current-process foreground lifecycle host；foreground interruption 后会通过当前进程内 `RuntimeOrchestrator::stop_runtime` 聚合 native runtime stop/release 诊断。

该状态仍保持无 daemon/control socket 安全边界。`stop` 与后台 `status` 不得因为前台
`start` 接线而声称支持跨进程控制。

## Adapter 边界

当前首个源码边界是 `crates/engine-native`。该 crate 必须：

1. 只依赖 `control-domain` 和实现自身需要的最小运行时依赖。
2. 提供 `NativeProxyEngineService` 或等价类型，实现 `ProxyEngineService`。
3. 通过 `list_engines()` 返回 id 为 `native`、kind 为 `ProxyEngineKind::Native` 的 descriptor。
4. 只声明已经真实实现的 `ProxyEngineCapability`，不得预先声明 TUN、DNS、MITM、HotReload 或 HealthCheck。
5. 将所有 adapter 私有错误映射为稳定 `Diagnostic` 或 `DomainError`，不得向 CLI 泄漏内部错误类型、backtrace、socket path 或敏感配置值。
6. 在没有真实运行句柄前，`start()` 必须返回 `DomainError`，不得返回 `Running`。

当前 adapter 已实现 service-owned 运行句柄和生命周期诊断合同，并已通过
`networkcore-linux start` 的前台 lifecycle host 接入二进制入口。

## 配置输入边界

`ProxyEngineConfig` 是 adapter 唯一的配置输入：

- `engine_id` 必须匹配 `native` 或后续显式支持的 id。
- `config` 只能使用 `ConfigSnapshot` 中已经标准化的字段，不重新解析原始 TOML。
- `ConfigSnapshot.nodes` 与 `nodes` 会被 adapter 合并为 typed node catalog，并在重复 id 时拒绝；`metadata` 只作为 adapter 附加上下文，不得让 adapter 自行读取额外配置文件或承载节点主模型。
- 缺少原生 engine 所需 listener、node、policy 或 DNS 信息时，adapter 必须返回错误诊断，不能启动空 runtime。

推荐稳定诊断 code：

| code | severity | 含义 |
| --- | --- | --- |
| `engine.native.config.engine_id_unsupported` | Error | `ProxyEngineConfig.engine_id` 不是当前 adapter 支持的 id |
| `engine.native.config.listener_missing` | Error | 缺少可启动 listener 或入站入口 |
| `engine.native.config.listener_id_duplicate` | Error | listener id 重复 |
| `engine.native.config.listener_bind_invalid` | Error | listener bind 非法 |
| `engine.native.config.listener_kind_unsupported` | Error | listener handler 当前未实现 |
| `engine.native.config.node_missing` | Error | 缺少可用出站节点或直连策略 |
| `engine.native.config.node_id_duplicate` | Error | typed node id 重复 |
| `engine.native.config.node_protocol_unsupported` | Error | outbound handler 当前未实现 |
| `engine.native.config.route_id_duplicate` | Error | route id 重复 |
| `engine.native.config.route_target_missing` | Error | route 引用的 rule set 或 node 不存在 |
| `engine.native.config.route_empty` | Error | listener 没有可执行 proxy route |
| `engine.native.config.secret_redacted` | Info | 诊断输出已隐藏敏感配置值 |

## 启动语义

`ProxyEngineService::start` 成功返回 `ProxyEngineLifecycleState::Running` 前必须满足：

1. 平台能力已经由 `RuntimeOrchestrator` 确认为可启动。
2. `validate_config` 没有 Error 级诊断。
3. adapter 已创建当前进程内拥有的运行句柄。
4. 运行句柄已经进入可接收生命周期控制或事件观察的状态。
5. 失败路径能返回稳定 `DomainError`，并通过 CLI 映射为 `cli.linux.start.engine_denied` 或更具体的后续 code。

不得把以下情况视为启动成功：

- 只完成配置解析或配置校验。
- 只创建了 descriptor，没有 runtime 句柄。
- 只返回 `Starting`，但没有后续前台 host 持有进程。
- 只启动外部进程但没有状态、事件和退出诊断合同。
- 在测试替身中返回 `Running` 后直接接入 binary。

推荐启动诊断 code：

| code | severity | 含义 |
| --- | --- | --- |
| `engine.native.start.runtime_unavailable` | Error | 原生运行时尚未实现或不可用 |
| `engine.native.start.runtime_assembly_ready` | Info | 有效配置已可生成 native runtime assembly plan，可进入 service start gate 评估 |
| `engine.native.start.service_runtime_owner_missing` | Error | 历史 gate 诊断：service 尚未拥有可跨 start/status/events/stop 生命周期管理的 runtime state |
| `engine.native.start.bind_failed` | Error | listener 绑定失败 |
| `engine.native.start.lifecycle_failed` | Error | 运行句柄创建或进入运行状态失败 |
| `engine.native.start.running` | Info | 原生 runtime 已进入当前进程前台运行状态 |
| `engine.native.runtime.listener_disabled` | Error | runtime handle 拒绝 disabled listener |
| `engine.native.runtime.listener_non_loopback` | Error | runtime handle 拒绝非 loopback listener |
| `engine.native.runtime.listener_unsupported` | Error | runtime handle 拒绝尚未声明的 listener handler |
| `engine.native.runtime.outbound_endpoint_invalid` | Error | runtime handle 拒绝非法 outbound endpoint |
| `engine.native.runtime.outbound_unsupported` | Error | runtime handle 拒绝尚未声明的 outbound handler |
| `engine.native.runtime.resource_missing` | Error | runtime handle 缺少 listener 或 outbound handler |
| `engine.native.runtime.released` | Info | 启动失败或停止路径已释放已持有 handle |
| `engine.native.runtime.foreground_handoff_ready` | Info | runtime handle 可交给前台 lifecycle host |
| `engine.native.runtime.accept_loop_ready` | Info | loopback TCP accept loop 已准备好由 runtime handle 持有 |
| `engine.native.runtime.accept_loop_stopped` | Info | loopback TCP accept loop 已受控停止 |
| `engine.native.runtime.connection_pre_protocol_closed` | Info | accepted TCP connection 未完成 route/outbound 处理即被显式关闭 |
| `engine.native.runtime.socks5_greeting_read` | Info | accepted TCP connection 的 SOCKS5 greeting 版本和认证方法已读取 |
| `engine.native.runtime.socks5_greeting_invalid` | Warning | accepted TCP connection 的 SOCKS5 greeting 版本或认证方法边界非法 |
| `engine.native.runtime.socks5_greeting_read_failed` | Warning | accepted TCP connection 在关闭或超时前未能完整读取 SOCKS5 greeting |
| `engine.native.runtime.socks5_auth_method_selected` | Info | accepted TCP connection 的 SOCKS5 no-auth 方法已选择 |
| `engine.native.runtime.socks5_auth_method_unsupported` | Warning | accepted TCP connection 未声明当前支持的 SOCKS5 认证方法 |
| `engine.native.runtime.socks5_auth_method_response_written` | Info | accepted TCP connection 的 SOCKS5 认证方法响应已写入 |
| `engine.native.runtime.socks5_auth_method_response_write_failed` | Warning | accepted TCP connection 的 SOCKS5 认证方法响应写入失败 |
| `engine.native.runtime.socks5_command_header_read` | Info | accepted TCP connection 的 SOCKS5 命令头已读取 |
| `engine.native.runtime.socks5_command_header_invalid` | Warning | accepted TCP connection 的 SOCKS5 命令头版本、reserved 或地址类型边界非法 |
| `engine.native.runtime.socks5_command_header_read_failed` | Warning | accepted TCP connection 在关闭或超时前未能完整读取 SOCKS5 命令头 |
| `engine.native.runtime.socks5_command_unsupported` | Warning | accepted TCP connection 请求了当前未支持的 SOCKS5 命令 |
| `engine.native.runtime.socks5_connect_target_read` | Info | accepted TCP connection 的 SOCKS5 CONNECT 目标地址和端口已读取 |
| `engine.native.runtime.socks5_connect_target_invalid` | Warning | accepted TCP connection 的 SOCKS5 CONNECT 目标地址或端口边界非法 |
| `engine.native.runtime.socks5_connect_target_read_failed` | Warning | accepted TCP connection 在关闭或超时前未能完整读取 SOCKS5 CONNECT 目标地址或端口 |
| `engine.native.runtime.http_mitm_connect_browser_proof_observed` | Info | native SOCKS5 CONNECT hook 已输出 browser capture 默认 proof token、CONNECT target 和本地 socks5 proxy URL |
| `engine.native.runtime.http_mitm_connect_event_planned` | Info | accepted TCP connection 的 SOCKS5 CONNECT target 已映射为 rich HTTP MITM event |
| `engine.native.runtime.http_mitm_connect_plan_ready` | Info | native SOCKS5 CONNECT MITM plugin plan 已生成 |
| `engine.native.runtime.http_mitm_connect_plan_failed` | Error | native SOCKS5 CONNECT MITM plugin plan 生成失败 |
| `engine.native.runtime.http_mitm_connect_plan_not_applied` | Warning | HTTP/TLS 数据面尚未应用 redirect/header/body/script MITM plan |
| `engine.native.runtime.http_mitm_connect_reject_applied` | Info | native SOCKS5 CONNECT 已按 MITM plugin `Reject` plan 阻断 |
| `engine.native.runtime.http_mitm_connect_reject_response_written` | Info | MITM plugin rejection 的 SOCKS5 CONNECT failure response 已写入 |
| `engine.native.runtime.http_mitm_connect_reject_response_write_failed` | Warning | MITM plugin rejection 的 SOCKS5 CONNECT failure response 写入失败 |
| `engine.native.runtime.socks5_route_outbound_selected` | Info | accepted TCP connection 的 CONNECT 目标已选择当前配置的 SOCKS outbound handler |
| `engine.native.runtime.socks5_outbound_connect_request_frame_generated` | Info | accepted TCP connection 的上游 SOCKS5 CONNECT request frame 已在内存中生成 |
| `engine.native.runtime.socks5_outbound_connect_request_frame_invalid` | Warning | accepted TCP connection 的上游 SOCKS5 CONNECT request frame 目标边界非法 |
| `engine.native.runtime.socks5_outbound_tcp_connection_planned` | Info | accepted TCP connection 的 SOCKS outbound TCP connection plan 已在内存中创建 |
| `engine.native.runtime.socks5_outbound_tcp_connection_plan_invalid` | Warning | SOCKS outbound TCP connection plan 的 endpoint 或 request frame 边界非法 |
| `engine.native.runtime.socks5_outbound_tcp_connection_attempt_succeeded` | Info | SOCKS outbound TCP connection attempt 已成功建立 TCP stream |
| `engine.native.runtime.socks5_outbound_tcp_connection_attempt_failed` | Warning | SOCKS outbound TCP connection attempt 失败或 endpoint 尚不能转换为 IP socket address |
| `engine.native.runtime.socks5_outbound_connect_request_written` | Info | SOCKS outbound CONNECT request 已写入上游 TCP stream |
| `engine.native.runtime.socks5_outbound_connect_request_write_failed` | Warning | SOCKS outbound CONNECT request 无法写入上游 TCP stream 或 request frame 为空 |
| `engine.native.runtime.socks5_outbound_connect_response_read` | Info | SOCKS outbound CONNECT response 已从上游 TCP stream 读取且 reply 成功 |
| `engine.native.runtime.socks5_outbound_connect_response_invalid` | Warning | SOCKS outbound CONNECT response 格式非法或 reply 非成功 |
| `engine.native.runtime.socks5_outbound_connect_response_read_failed` | Warning | SOCKS outbound CONNECT response 读取失败或超时 |
| `engine.native.runtime.socks5_outbound_connect_response_accepted` | Info | SOCKS outbound CONNECT response 已接受 CONNECT request，可进入 client success response 与 data relay |
| `engine.native.runtime.socks5_outbound_connect_response_rejected` | Warning | SOCKS outbound CONNECT response 拒绝 CONNECT request 或响应无效 |
| `engine.native.runtime.socks5_outbound_connect_relay_ready` | Info | SOCKS outbound CONNECT relay readiness 已就绪 |
| `engine.native.runtime.socks5_outbound_connect_relay_unwired` | Warning | SOCKS outbound CONNECT response 已接受，但本地 relay 尚未接线，不能写入 client success response |
| `engine.native.runtime.socks5_outbound_connect_relay_rejected` | Warning | SOCKS outbound CONNECT relay readiness 被上游拒绝响应阻断 |
| `engine.native.runtime.socks5_outbound_connect_data_relay_plan_ready` | Info | SOCKS outbound CONNECT data relay plan 已就绪 |
| `engine.native.runtime.socks5_outbound_connect_data_relay_plan_unwired` | Warning | SOCKS outbound CONNECT response 已接受，但 data relay plan 尚未接线，不能写入 client success response |
| `engine.native.runtime.socks5_outbound_connect_data_relay_plan_rejected` | Warning | SOCKS outbound CONNECT data relay plan 被上游拒绝响应阻断 |
| `engine.native.runtime.socks5_outbound_connect_data_relay_completed` | Info | SOCKS outbound CONNECT data relay 已完成双向有限 stream 复制 |
| `engine.native.runtime.socks5_outbound_connect_data_relay_failed` | Warning | SOCKS outbound CONNECT data relay 至少一个方向复制失败 |
| `engine.native.runtime.socks5_outbound_connect_client_success_response_ready` | Info | SOCKS outbound CONNECT client success response readiness 已就绪 |
| `engine.native.runtime.socks5_outbound_connect_client_success_response_unwired` | Warning | SOCKS outbound CONNECT client success response readiness 被未接线 data relay plan 阻断 |
| `engine.native.runtime.socks5_outbound_connect_client_success_response_rejected` | Warning | SOCKS outbound CONNECT client success response readiness 被上游拒绝响应阻断 |
| `engine.native.runtime.socks5_outbound_connect_client_success_response_write_plan_ready` | Info | SOCKS outbound CONNECT client success response write plan 已就绪 |
| `engine.native.runtime.socks5_outbound_connect_client_success_response_write_plan_unwired` | Warning | SOCKS outbound CONNECT client success response write plan 尚未接线 |
| `engine.native.runtime.socks5_outbound_connect_client_success_response_write_plan_rejected` | Warning | SOCKS outbound CONNECT client success response write plan 被上游拒绝响应阻断 |
| `engine.native.runtime.socks5_outbound_connect_client_success_response_written` | Info | SOCKS outbound CONNECT client success response frame 已写入 |
| `engine.native.runtime.socks5_outbound_connect_client_success_response_write_failed` | Warning | SOCKS outbound CONNECT client success response frame 写入失败或上游 success response 无效 |
| `engine.native.runtime.socks5_route_outbound_unwired` | Warning | accepted TCP connection 的 CONNECT 目标已读取，但 route/outbound 数据面尚未接入 |
| `engine.native.runtime.socks5_connect_failure_response_written` | Info | route/outbound 尚未接入时已向 client 写入 SOCKS5 CONNECT failure response |
| `engine.native.runtime.socks5_connect_failure_response_write_failed` | Warning | route/outbound 尚未接入时 SOCKS5 CONNECT failure response 写入失败 |

## 前台生命周期 Host

前台 host 属于 `apps/linux-cli` 或后续应用层 adapter，不属于 `control-runtime` 或
`control-domain`。它必须：

- 只持有当前进程内的 runtime，不 fork、不 daemonize、不安装服务。
- 在 `ProxyEngineService::start` 返回 running 状态后接管当前进程生命周期。
- 聚合平台、配置、引擎和 host 自身诊断后渲染 CLI 输出。
- 明确普通退出、启动失败、运行中失败和用户中断的退出码。
- 在信号处理设计完成前，不承诺跨进程 `stop`、`reload` 或后台 `status`。
- 不写 systemd unit、PID file、launchd plist、Windows service 或 installer 状态。

当前 `apps/linux-cli` 已提供源码合同并接入 binary：

- `ForegroundLifecycleHost::run_foreground` 是前台 host 唯一 handoff 边界。
- `ForegroundLifecycleRequest` 当前只携带 `ProxyEngineStatus`；真实 runtime 所有权保留在 `ProxyEngineService` 内，foreground cleanup 通过 `RuntimeOrchestrator::stop_runtime` 触发。
- `ForegroundLifecycleOutcome` 统一返回 CLI exit code 和 host 诊断。
- `ForegroundLifecycleInterruptionSource` 与 `ForegroundLifecycleInterruption` 定义前台 host 收到用户或平台中断后的可测试合同。
- `UnavailableForegroundLifecycleHost` 稳定返回 `cli.linux.start.lifecycle_host_missing`。
- `CurrentProcessForegroundLifecycleHost` 稳定持有当前进程的 running handoff，并可注入 interruption source；Unix 默认 source 监听 `SIGINT`/`SIGTERM`，非 Unix 默认 parking source 继续阻塞持有当前进程。
- `handle_foreground_lifecycle` 只接受已经完成 `RuntimeOrchestrator::start_runtime` 的 `RuntimeOperationResult`，并在非 `Running` 状态时返回 `cli.linux.start.lifecycle_failed`，不会调用 host。
- `handle_foreground_lifecycle_with_runtime_stop` 在 foreground host 返回 `Interrupted` 后调用当前进程内 `RuntimeOrchestrator::stop_runtime`，聚合 `engine.native.runtime.accept_loop_stopped` 与 `engine.native.runtime.released`，stop 失败时追加 `cli.linux.start.runtime_stop_failed`。

推荐 host 诊断 code：

| code | severity | 含义 |
| --- | --- | --- |
| `cli.linux.start.foreground_only` | Info | 当前 `start` 只支持前台模式 |
| `cli.linux.start.lifecycle_host_missing` | Error | 注入的 foreground lifecycle host 缺失或显式 unavailable |
| `cli.linux.start.lifecycle_interrupted` | Warning | 前台运行被用户或平台信号中断 |
| `cli.linux.start.lifecycle_failed` | Error | 前台 host 运行阶段失败 |
| `cli.linux.start.runtime_stop_failed` | Error | 前台 interruption 后当前进程内 runtime stop 失败 |
| `cli.linux.start.signal_received` | Warning | 前台 host 收到 Unix OS signal |
| `cli.linux.start.signal_source_failed` | Error | 前台 host 无法注册或读取 Unix OS signal source |

前台 interruption 合同使用退出码 `130`，并保留 `cli.linux.start.foreground_only`
和 interruption source 自身诊断；当前进程内 runtime stop/release 诊断追加在 lifecycle interruption 诊断之后，不代表支持跨进程 `stop`、daemon 或后台 `status`。

## `networkcore-linux start` 接线门槛

二进制入口只有在以下条件全部满足后，才能将 `LinuxCliCommand::Start` 从
`handle_entrypoint` 的 unavailable 路径改为 `handle_start` 或等价前台启动路径：

- `engine-native` 或等价 crate 存在，并有 GitHub Actions 覆盖 format、lint、test、build 和 dependency audit。
- adapter 合同测试覆盖 descriptor、结构化配置拒绝、runtime handle 源码合同、runtime assembly plan、loopback TCP listener 绑定/释放、loopback TCP accept loop 受控关闭、协议前置关闭诊断、SOCKS5 greeting 读取、auth 方法选择/拒绝、auth 方法响应写入、SOCKS5 命令头读取、unsupported command 拒绝、CONNECT 目标地址读取、MITM plugin hook plan、CONNECT-level reject 应用、route/outbound 行为选择、SOCKS outbound CONNECT request frame 生成、SOCKS outbound TCP connection plan、SOCKS outbound TCP connection attempt、SOCKS outbound CONNECT request write、SOCKS outbound CONNECT response read、SOCKS outbound CONNECT response decision、SOCKS outbound CONNECT relay readiness、SOCKS outbound CONNECT data relay plan、data relay execution、client success response readiness、client success response write plan、client success response write、accept loop data relay、route/outbound 未接入拒绝、CONNECT failure response 写入、启动失败、running 状态、status、events 和 secret 不泄露。
- listener/node 配置模型按 [Native Engine Listener And Node Config Design](native-engine-listener-node-config.md) 完成源码合同，且 adapter 能校验 listener、node、route 和 DNS 图；当前已覆盖 listener/node/route，DNS 需求判断仍需在真实 handler 前完成。
- 前台 lifecycle host 有源码或设计合同，覆盖不 daemonize、不安装服务、退出码和诊断聚合。
- CLI 合同测试覆盖 `start` 成功、平台拒绝、配置拒绝、engine 拒绝、host 失败和 JSON 输出。
- `stop` 与后台 `status` 继续保持无 daemon/control socket 诊断，不能因为前台 start 合入而声称支持跨进程控制。
- Linux artifact readiness 与安装/回滚文档当前通过 confirmed release path 约束 release asset；后续 tag release 仍必须通过 packaging、license/NOTICE、attestation、release notes、rollback 和 publish eligibility gates。

未满足任一条件时，binary 必须组合 `UnavailableProxyEngineService` 或等价 unavailable host，
并让 `start` 返回 `cli.linux.runtime.unwired` 或更具体的 lifecycle unavailable 诊断。

## 验证边界

所有验证只在 GitHub Actions 执行。后续源码增量必须至少覆盖：

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace --all-targets`
- `cargo build --workspace --all-targets`
- `cargo generate-lockfile`
- `cargo audit`

本地只允许查看文件、编辑文件、查看 diff、提交、推送和查询 GitHub Actions。

## 后续工作

- Linux artifact readiness/release gate 已纳入 foreground stop/release 合同检查、artifact manifest 输出合同、license/NOTICE confirmation source contract、license/NOTICE transition validation contract、release license/NOTICE confirmed 状态 summary、release CI success source contract、release CI gate activation validation contract、package runner/toolchain/target contract、archive staging contract、checksum/manifest checksum contract、publish/upload boundary contract、signing/attestation policy binding contract、release notes/rollback policy binding contract 和 publish eligibility aggregate contract；当前 marker 为 `linux-artifact-release-state=confirmed-release-path`；后续 tag release 继续通过 release workflow、同 commit CI、checksum、manifest、attestation、release notes、rollback 和 publish eligibility gates 生成和发布 Linux assets。
- Linux package artifact job preflight validation contract、Linux package artifact build command validation contract、Linux package artifact staging file validation contract、Linux package artifact archive creation validation contract 和 Linux package artifact checksum execution validation contract 已定义；Linux package artifact manifest generation validation contract、Linux package artifact manifest checksum validation contract、Linux package workflow artifact bundle upload validation contract、Linux package artifact attestation execution validation contract、Linux package release notes/rollback execution validation contract 和 Linux package publish eligibility execution validation contract 已定义；release CI gate execution validation contract 和 release CI gate API implementation 已激活；当前 license/NOTICE 和 artifact gates 已进入 confirmed release path；后续 tag release 继续通过 release workflow、同 commit CI、checksum、manifest、attestation、release notes、rollback 和 publish eligibility gates 生成和发布 Linux assets。
