# Native Engine Listener And Node Config Design

本文定义 `engine-native` 从当前配置拒绝合同推进到真实 runtime handle 前必须具备的
listener、node、route 和 DNS 配置模型边界。它承接
[Control Kernel Interface Draft](control-kernel-interfaces.md)、
[Proxy Engine Adapter Interface](proxy-engine-adapter.md)、
[Control Runtime Orchestration Design](control-runtime-orchestration.md)、
[Subscription Catalog Runtime Orchestration Design](subscription-catalog-runtime-orchestration.md) 和
[Linux Native Proxy Engine Start Design](linux-native-proxy-engine-start.md)。

评估时间：2026-07-06。

## 目标

- 明确原生执行内核启动前需要的最小 listener/node 图。
- 定义 `ConfigSnapshot`、`NodeDescriptor`、`RuleSet`、`DnsUpstream` 和
  `ProxyEngineConfig` 如何进入 `engine-native`。
- 防止 adapter 因存在 profile 或任意 metadata 就停止返回配置拒绝诊断。
- 为下一步源码增量提供可测试、可回滚的字段、诊断和接线门槛。

## 非目标

- 不在本文实现 TCP、UDP、SOCKS、HTTP、TUN、DNS、MITM 或透明代理协议。
- 不选择 async runtime、socket 库、packet parser、DNS resolver 或 netlink 依赖。
- 不定义订阅格式、外部代理内核原生配置格式、daemon/control socket 或 packaging。
- 不把 listener、node、DNS 或平台文件系统细节放入 `control-runtime`。
- 不在本机运行、构建、测试、打包或试用 CLI。

## 当前源码状态

当前仓库已经具备：

- `control-domain::NodeDescriptor`，包含 `id`、`name`、`protocol`、`endpoint` 和 `tags`。
- `control-domain::ListenerDescriptor`、`ListenerBind`、`ListenerKind`、`ListenerNetwork` 和 `ListenerRoute`，能表达入站 listener 的 id、enabled、kind、bind、network、route、tags 和 metadata。
- `control-domain::RuleSet`、`RouteRule` 和 `RouteAction`，能表达直连、代理节点和拒绝策略意图。
- `control-domain::DnsUpstream`，能表达标准化 DNS 上游入口。
- `control-domain::ConfigSnapshot.listeners`、`nodes` 和 `policies`，作为本地 listener、node 和 route 配置的领域事实来源。
- `control-domain::ProxyEngineConfig`，组合标准化 `ConfigSnapshot`、运行请求提供的 `nodes` 和 adapter `metadata`。
- `control-runtime::RuntimeConfigRequest`，把 `engine_id`、原始配置、`nodes` 和 `metadata` 传给运行层。
- `config-core::CoreConfigurationService`，当前解析 schema/profile 和最小 listener/node/route TOML 子集。
- `config-core::CoreSubscriptionService`，当前只接受显式 `inline:` source，并把最小 subscription TOML `nodes`/`routes` 子集解析为 `SubscriptionDocument` 和 `NodeCatalog`；已完成的 subscription catalog runtime gate 已在 `control-runtime` 定义并实现 `NodeCatalog.nodes` 进入 `RuntimeConfigRequest.nodes` 前的运行层 gate，远程拉取、文件读取、认证、secret 和 listener/node 图校验仍未进入 config-core。
- `engine-native::NativeProxyEngineService`，当前对 listener、node 和 route 做结构化图校验，合并 `ConfigSnapshot.nodes` 与运行请求 nodes 作为 typed node catalog，并在缺少 listener/node、重复 id、route target 缺失和超出当前 plan 合同的 handler/protocol 时返回稳定诊断。
- `engine-native` 已补充首个 native runtime handle 源码合同，覆盖 loopback listener handle、SOCKS outbound handler handoff、启动失败释放报告、runtime events 和 foreground lifecycle handoff status。
- `engine-native` 已补充真实 loopback TCP listener 绑定/释放实现，runtime assembly 可持有当前进程内的 `TcpListener` resource 并在 release 或失败报告中释放。
- `engine-native` 已补充从有效配置图生成首个 native runtime assembly plan 的源码合同，可选择 loopback TCP listener 与 SOCKS outbound handler，并在绑定失败或 lifecycle handoff 失败时输出 release report。
- `engine-native` 已补充首个 loopback TCP accept loop 与受控关闭源码合同，可持有 bound listener 与 SOCKS outbound handler identity，记录 accepted connection 计数，并在 runtime release 或 drop 路径停止。
- `engine-native` 已补充 accepted TCP connection 的协议前置关闭诊断合同；未完成 SOCKS5 route/outbound 处理的 accepted connection 会记录 pre-protocol close 计数和 `engine.native.runtime.connection_pre_protocol_closed` 诊断。
- `engine-native` 已补充首个 SOCKS5 greeting 版本/认证方法读取诊断合同，可在 accepted loopback TCP connection 上读取 greeting 并记录 `engine.native.runtime.socks5_greeting_read`、`engine.native.runtime.socks5_greeting_invalid` 或 `engine.native.runtime.socks5_greeting_read_failed` 诊断。
- `engine-native` 已补充 SOCKS5 no-auth 方法选择与 unsupported auth 方法拒绝诊断合同，可在有效 greeting 后记录 `engine.native.runtime.socks5_auth_method_selected` 或 `engine.native.runtime.socks5_auth_method_unsupported` 诊断，并继续进入后续方法响应、命令和 CONNECT route/outbound 分支。
- `engine-native` 已补充 SOCKS5 认证方法响应写入诊断合同，可写入 `[0x05, method]` 响应并记录 `engine.native.runtime.socks5_auth_method_response_written` 或 `engine.native.runtime.socks5_auth_method_response_write_failed` 诊断。
- `engine-native` 已补充 SOCKS5 命令头读取与 unsupported command 拒绝诊断合同，可在 no-auth 响应后读取 `[VER, CMD, RSV, ATYP]` 并记录 `engine.native.runtime.socks5_command_header_read`、`engine.native.runtime.socks5_command_header_invalid` 或 `engine.native.runtime.socks5_command_header_read_failed` 诊断，对非 CONNECT 命令记录 `engine.native.runtime.socks5_command_unsupported`。
- `engine-native` 已补充 SOCKS5 CONNECT 目标地址读取、route/outbound 行为选择、SOCKS outbound CONNECT request frame 生成、SOCKS outbound TCP connection plan、SOCKS outbound TCP connection attempt、SOCKS outbound CONNECT request write、SOCKS outbound CONNECT response read、SOCKS outbound CONNECT response decision、SOCKS outbound CONNECT relay readiness、SOCKS outbound CONNECT data relay plan、SOCKS outbound CONNECT data relay execution、SOCKS outbound CONNECT client success response readiness、SOCKS outbound CONNECT client success response write plan、SOCKS outbound CONNECT client success response write、accept loop client success response 与有限 data relay 接线、未接入拒绝与 CONNECT failure response 写入诊断合同。accept loop 在上游 CONNECT accepted 后记录 `engine.native.runtime.socks5_outbound_connect_relay_ready`、`engine.native.runtime.socks5_outbound_connect_data_relay_plan_ready`、`engine.native.runtime.socks5_outbound_connect_client_success_response_ready` 和 `engine.native.runtime.socks5_outbound_connect_client_success_response_write_plan_ready`，写入 client success response frame，再对有限 client/outbound TCP stream 执行双向复制并记录 `engine.native.runtime.socks5_outbound_connect_data_relay_completed` 或 `engine.native.runtime.socks5_outbound_connect_data_relay_failed`；上游 rejected、连接失败或 plan 不完整路径继续记录 rejected/unwired 诊断，写入 SOCKS5 general failure response 并关闭连接。
- `engine-native` 已补充 service-owned runtime state 与 foreground lifecycle handoff 源码合同；有效配置可让 `NativeProxyEngineService::start` 启动并持有 loopback TCP accept loop runtime，返回 `Running`、`engine.native.start.running`、`engine.native.runtime.foreground_handoff_ready` 和 `engine.native.runtime.accept_loop_ready`，`status`/`events`/`stop` 可观察和释放 runtime。
- `networkcore-linux start` binary 已接入 `NativeProxyEngineService` 与 current-process foreground lifecycle host；foreground interruption 后会调用当前进程内 `RuntimeOrchestrator::stop_runtime` 并聚合 native runtime stop/release 诊断，继续保持无 daemon/control socket 边界。

因此，`engine-native` service 层现在可以在源码合同和 Linux CLI 前台入口中启动当前进程内 runtime；但不得声称支持 daemon、control socket 或跨进程 stop/status。

## 配置所有权

配置模型必须保持领域优先：

1. `ConfigSnapshot` 是标准化配置事实来源，后续应显式承载 listener、node、route、DNS 和插件配置。
2. `NodeDescriptor` 来自 `ConfigSnapshot.nodes`、运行请求、订阅归一化或测试替身；`engine-native` 当前把 `ConfigSnapshot.nodes` 与 `ProxyEngineConfig.nodes` 合并为 typed node catalog，并用 `engine.native.config.node_id_duplicate` 拒绝重复 id。
3. `ProxyEngineConfig.metadata` 只用于 adapter 附加上下文，不得作为 listener 或节点主模型。
4. `engine-native` 只消费 `ProxyEngineConfig`，不得重新读取 TOML、扫描默认配置路径或访问订阅来源。
5. secret、token、密码和私钥必须进入后续显式 secret 模型；诊断不得输出原值、metadata value 或完整 URL secret。

下一步源码若需要校验 listener/node 图，必须继续通过领域类型和配置快照推进；不得用自由格式 metadata 绕过领域模型。

## Listener 模型

当前领域模型已新增 `ListenerDescriptor` 和相关值类型，最小字段如下：

| 字段 | 含义 | 首版约束 |
| --- | --- | --- |
| `id` | listener 稳定标识 | 必填，同一配置内唯一 |
| `enabled` | 是否参与启动候选 | disabled listener 不计入可启动 listener |
| `kind` | 入站类型 | 首版只允许已实现的 kind，例如 `local_tcp` 或后续 `socks` |
| `bind` | 监听地址和端口 | 必须显式，不能默认监听公网地址 |
| `network` | `tcp`、`udp` 或 `tcp_udp` | 未实现 UDP 前必须拒绝 UDP listener |
| `route` | 默认 route 或 rule set id | 必须能解析到有效 `RouteAction` |
| `tags` | 用户或策略标签 | 不影响启动门禁 |
| `metadata` | adapter 附加字段 | 不得携带 secret 原文 |

首个可启动 listener 必须满足：

- 至少存在一个 enabled listener。
- listener id 不重复。
- bind host 和 port 合法，端口范围为 `1..=65535`。
- 首版默认只允许 loopback bind，例如 `127.0.0.1`、`::1` 或显式设计允许的本机地址；公网或通配地址进入前必须有权限、风险和提示设计。
- listener kind、network 和后续 handler 已真实实现，否则返回 capability unsupported。
- listener 的 route 引用能解析到存在的 rule set 或默认 route。

## Node 模型

现有 `NodeDescriptor` 是首个 outbound 节点模型。后续源码必须保持以下语义：

- `id` 是策略引用和运行状态引用的唯一键。
- `protocol` 只能取 adapter 已实现协议；未实现协议必须返回 unsupported，而不是静默降级。
- `endpoint.host` 不能为空，`endpoint.port` 必须在合法范围内。
- `tags` 只用于策略筛选，不得替代能力或 secret 声明。
- 需要认证信息的协议必须先定义 secret redaction 和权限边界。

`engine-native` 只有在以下条件满足时才能停止返回
`engine.native.config.node_missing`：

- 配置图至少存在一个可用于 `Proxy` route 的 node，或明确存在已实现的 `Direct` route。
- 所有 `RouteAction::Proxy { node_id }` 都引用存在的 node。
- node protocol 和 listener network 能被当前 native runtime 共同支持。
- 不存在重复 node id。

直连 route 不能被用作空 runtime 逃生口。只有 native runtime 已实现真实 direct connector 并有合同测试覆盖时，`Direct` 才能作为可启动 outbound。

## Route 和 DNS 图

listener 到 outbound 的图必须显式、可诊断：

1. listener 选择一个默认 rule set 或 route。
2. rule set 编译后得到 `RouteAction`。
3. `Proxy` action 必须引用现有 node。
4. `Direct` action 必须依赖已实现 direct connector。
5. `Reject` action 不能作为唯一可启动路径。
6. DNS 上游只有在 adapter 实际解析域名或代理协议需要域名解析时才是启动必需项。

DNS 配置进入前应继续保守：

- 缺少 DNS 时，如果所有 endpoints 都已是 IP 且协议不需要远程解析，可不阻断启动。
- 需要本地解析域名但没有可用 DNS plan 时，返回 `engine.native.config.dns_required`。
- DNS 不能触发 Linux 系统 DNS 修改；系统 DNS mutation 仍属于后续 Linux adapter 设计。

## 推荐诊断 code

| code | severity | 含义 |
| --- | --- | --- |
| `engine.native.config.listener_missing` | Error | 没有可启动 listener |
| `engine.native.config.listener_id_duplicate` | Error | listener id 重复 |
| `engine.native.config.listener_bind_invalid` | Error | listener bind 地址或端口非法 |
| `engine.native.config.listener_kind_unsupported` | Error | listener kind 当前未实现 |
| `engine.native.config.node_missing` | Error | 缺少可用 outbound node 或已实现 direct route |
| `engine.native.config.node_id_duplicate` | Error | node id 重复 |
| `engine.native.config.node_protocol_unsupported` | Error | node 协议当前未实现 |
| `engine.native.config.route_id_duplicate` | Error | route/rule set id 重复 |
| `engine.native.config.route_target_missing` | Error | route 引用的 node 或 rule set 不存在 |
| `engine.native.config.route_empty` | Error | listener 没有可执行 route |
| `engine.native.config.dns_required` | Error | 当前配置需要 DNS plan 才能启动 |
| `engine.native.config.secret_redacted` | Info | 诊断输出已隐藏敏感配置值 |
| `engine.native.start.runtime_assembly_ready` | Info | 有效配置已可生成 native runtime assembly plan，可进入 service start gate 评估 |
| `engine.native.start.service_runtime_owner_missing` | Error | 历史 gate 诊断：service 尚未拥有可跨 start/status/events/stop 生命周期管理的 runtime state |
| `engine.native.start.running` | Info | 原生 runtime 已进入当前进程前台运行状态 |
| `engine.native.start.bind_failed` | Error | 真实 loopback TCP listener 绑定失败 |
| `engine.native.start.lifecycle_failed` | Error | runtime handle 创建后进入 lifecycle handoff 失败 |
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

已有 code `engine.native.config.engine_id_unsupported`、`listener_missing` 和
`node_missing` 保持兼容。

## 源码接线阶段

后续最小源码增量应按以下顺序推进：

1. 已在 `control-domain` 中新增 listener 领域类型并扩展 `ConfigSnapshot`，合同测试覆盖 id、bind、network 和 route 引用边界。
2. 已在 `config-core` 中解析最小 listener/node/route TOML 子集，并新增最小 inline subscription parser；两者仍保持纯内存、无文件 I/O、无网络请求。
3. `control-runtime` 继续只编排端口，并把 `ConfigSnapshot` 与 `RuntimeConfigRequest.nodes` 作为显式类型传入 `ProxyEngineConfig`；当前 typed node catalog 合并和去重在 `engine-native` 中完成，不读取 adapter 私有 metadata。
4. 已在 `engine-native` 中把配置拒绝从固定 `listener_missing`/`node_missing` 改为结构化图校验，覆盖 enabled listener、重复 id、route target、typed node catalog 和未实现 listener/node handler。
5. 已补充首个 native runtime handle 的最小源码合同，明确 loopback listener handle、SOCKS outbound handler handoff、失败释放、事件和前台 lifecycle handoff status。
6. 已补充真实 loopback TCP listener 绑定/释放实现，合同测试覆盖可用端口绑定、占用端口失败和 release 后端口可复用。
7. 已补充从有效配置图生成首个 runtime assembly plan 的源码合同，选择 loopback TCP listener 与 SOCKS outbound handler，并覆盖绑定失败和 lifecycle handoff 失败时的释放边界。
8. 已补充首个 loopback TCP accept loop 与受控关闭源码合同，覆盖 accepted connection 计数、runtime release 停止报告和 ready/stopped 诊断，仍不接入 `networkcore-linux start`。
9. 已补充首个 accepted TCP connection 的协议前置关闭诊断合同，明确完整 proxy protocol 未实现时的连接处理边界，仍不接入 `networkcore-linux start`。
10. 已补充首个 SOCKS5 greeting 版本/认证方法读取诊断合同，继续不接入 route/outbound 或 `networkcore-linux start`。
11. 已补充 SOCKS5 no-auth 方法选择与 unsupported auth 方法拒绝诊断合同，继续不写入 SOCKS5 方法响应、不接入 route/outbound 或 `networkcore-linux start`。
12. 已补充 SOCKS5 认证方法响应写入诊断合同，继续不解析 SOCKS5 命令、不接入 route/outbound 或 `networkcore-linux start`。
13. 已补充 SOCKS5 命令头读取与 unsupported command 拒绝诊断合同，继续不读取 CONNECT 目标地址、不接入 route/outbound 或 `networkcore-linux start`。
14. 已补充 SOCKS5 CONNECT 目标地址读取与 route/outbound 未接入拒绝诊断合同，继续不写入 SOCKS5 failure response、不接入 `networkcore-linux start`。
15. 已补充 SOCKS5 route/outbound 未接入时的 CONNECT failure response 写入诊断合同，继续不接入 `networkcore-linux start`。
16. 已补充 SOCKS5 CONNECT route/outbound 行为选择诊断合同，继续不建立真实 outbound 连接、不接入 `networkcore-linux start`。
17. 已补充 SOCKS5 outbound CONNECT request frame 生成诊断合同，继续不建立真实 outbound 连接、不接入 `networkcore-linux start`。
18. 已补充 SOCKS5 outbound TCP connection plan 诊断合同，继续不建立真实 outbound 连接、不接入 `networkcore-linux start`。
19. 已补充 SOCKS5 outbound TCP connection attempt 诊断合同，继续不进行数据转发、不接入 `networkcore-linux start`。
20. 已补充 SOCKS5 outbound CONNECT request write 诊断合同，当时继续不进行双向数据转发、不接入 `networkcore-linux start`。
21. 已补充 SOCKS5 outbound CONNECT response read 诊断合同，当时继续不进行双向数据转发、不接入 `networkcore-linux start`。
22. 已补充 SOCKS5 outbound CONNECT response decision 诊断合同，继续不写入 client success response、不进行双向数据转发、不接入 `networkcore-linux start`。
23. 已补充 SOCKS5 outbound CONNECT relay readiness 诊断合同，继续不写入 client success response、不进行双向数据转发、不接入 `networkcore-linux start`。
24. 已补充 SOCKS5 outbound CONNECT data relay plan 诊断合同，继续不写入 client success response、不进行双向数据转发、不接入 `networkcore-linux start`。
25. 已补充 SOCKS5 outbound CONNECT client success response readiness 诊断合同，继续不写入 client success response、不进行双向数据转发、不接入 `networkcore-linux start`。
26. 已补充 SOCKS5 outbound CONNECT client success response write plan 诊断合同，继续不写入 client success response、不进行双向数据转发、不接入 `networkcore-linux start`。
27. 已补充 SOCKS5 outbound CONNECT client success response write 诊断合同，源码层可写入 success response frame，但当时 accept loop 继续不进行双向数据转发、不接入 `networkcore-linux start`。
28. 已补充 SOCKS5 outbound CONNECT data relay 执行诊断合同，源码层可对有限 client/outbound stream 进行双向复制，但当时 accept loop 继续不接入 data relay、不接入 `networkcore-linux start`。
29. 已补充 SOCKS5 outbound CONNECT accept loop client success response 与有限 data relay 接线诊断合同，继续不接入 `networkcore-linux start`。
30. 已补充 `engine-native` service start readiness gate，确认有效 runtime assembly plan 已具备，但当时 service-owned runtime state 与 foreground lifecycle handoff 仍阻断 service `start()` 返回 `Running`，继续不接入 `networkcore-linux start`。
31. 已补充 `engine-native` service-owned runtime state 与 foreground lifecycle handoff 源码合同，`NativeProxyEngineService::start` 可持有 loopback TCP accept loop runtime 并返回 `Running`，`status`/`events`/`stop` 可观察和释放 runtime，继续不接入 `networkcore-linux start`。
32. 已将 `networkcore-linux start` binary 接入 `NativeProxyEngineService` 与前台 lifecycle host。
33. 已为 `networkcore-linux start` 前台 lifecycle host 补充 signal/interruption 处理合同。
34. 已为 `CurrentProcessForegroundLifecycleHost` 接入真实 Unix OS signal/interruption source。
35. 已为前台 lifecycle interruption 后的 runtime stop/release 诊断聚合补充显式合同。
36. 已在 Linux artifact readiness/release gate 中纳入 foreground stop/release 合同检查，并继续保持 license/NOTICE 未确认时不生成 `package-linux` artifact。
37. 已在不生成 artifact 的前提下补充首个 Linux `package-linux` artifact manifest/metadata 输出合同设计。
38. 已补充 Linux artifact license/NOTICE confirmation source contract 和 pending marker，继续不生成 artifact。
39. 已在 release placeholder summary 中补充 license/NOTICE source contract 状态，继续不生成 artifact。
40. 已补充 release CI success source contract，定义真实 `package-linux` 前同 commit CI run/source 字段，继续不生成 artifact。
41. 已补充 Linux package runner/toolchain/target 输入合同，固定首个 Linux packaging runner、Rust toolchain、target triple、crate、binary 和 archive naming 输入，仍不生成 artifact。
42. 已补充 Linux package archive staging contract，固定 future `package-linux` staging/output/top-level directory、archive path 和允许文件来源，仍不生成 artifact。
43. 已补充 Linux package checksum/manifest checksum contract，固定 future `package-linux` checksum sidecar 文件命名、sha256 计算顺序和 manifest 交叉校验字段，仍不生成 artifact。
44. 已补充 Linux package publish/upload boundary contract，固定 future `package-linux` workflow artifact bundle、retention days、publish download source、release asset set 和禁止覆盖策略，仍不生成 artifact。
45. 已补充 Linux package signing/attestation policy binding contract，固定首个 Linux artifact 的 unsigned tarball 策略、GitHub artifact attestation/provenance required 策略和 publish without attestation 阻断，仍不生成 artifact。
46. 已补充 Linux package release notes/rollback policy binding contract，固定 release notes required fields、manual-extract rollback policy、withdrawal/replacement policy 和 publish without rollback 阻断，仍不生成 artifact。
47. 已补充 Linux package publish eligibility aggregate contract，汇总 Linux package release gates 的 eligible/blocked 状态和 next action，仍不生成 artifact。
48. 已补充 Linux package license/NOTICE transition validation contract，固定 pending 到 confirmed 的独立确认提交字段和文件存在性检查，仍不生成 artifact。
49. 已补充 Linux package release CI gate activation validation contract，固定 `release-ci-gate` 从 placeholder 切换到自动 CI run 读取前的权限、API 字段和失败边界，仍不生成 artifact。
50. Linux package artifact job preflight validation contract、Linux package artifact build command validation contract、Linux package artifact staging file validation contract、Linux package artifact archive creation validation contract 和 Linux package artifact checksum execution validation contract 已定义；Linux package artifact manifest generation validation contract、Linux package artifact manifest checksum validation contract、Linux package workflow artifact bundle upload validation contract、Linux package artifact attestation execution validation contract、Linux package release notes/rollback execution validation contract 和 Linux package publish eligibility execution validation contract 已定义；release CI gate execution validation contract 和 release CI gate API implementation 已激活；当前 license/NOTICE 和 artifact gates 已进入 confirmed release path；后续 tag release 继续通过 release workflow、同 commit CI、checksum、manifest、attestation、release notes、rollback 和 publish eligibility gates 生成和发布 Linux assets。

每个阶段都必须同步 README、TODO、CHANGELOG、设计文档和合同测试，并只通过 GitHub Actions 验证。

## `Running` 门槛

`engine-native::start` 返回 `ProxyEngineLifecycleState::Running` 前必须同时满足：

- listener 配置图已通过校验。
- outbound node/direct route 图已通过校验。
- 平台能力已由 `RuntimeOrchestrator` 确认可启动。
- adapter 已创建当前进程拥有的真实 listener/runtime handle，并具备 accept loop、受控关闭、SOCKS5 认证方法响应、命令头读取、CONNECT 目标地址解析、route/outbound 行为选择、SOCKS outbound request frame 生成、SOCKS outbound connection plan、SOCKS outbound connection attempt、outbound request write、outbound response read、outbound response decision、relay readiness、data relay plan、client success response readiness、client success response write plan、accept loop client success response 写入、data relay 和 failure response 写入合同，而不仅是源码合同结构或 assembly plan。
- 失败路径能释放已创建的句柄，并返回稳定 `DomainError` 或 `Diagnostic`。
- `events()` 至少能返回启动失败或运行状态变化的内存事件合同，或者在设计中明确首版事件为空的边界。

不得把以下情况视为 running：

- 只解析了 listener/node 配置。
- 只验证了节点存在。
- 只创建了 runtime handle 合同结构，没有绑定或持有任何真实运行资源。
- 只绑定端口、只生成 assembly plan、只启动 accept loop、只完成 SOCKS5 CONNECT 到有限 data relay 的连接级合同，但 service 未持有可跨 `start`/`status`/`events`/`stop` 管理的 runtime handle。
- 只能在测试替身中返回 `Running`。

## 验收条件

本设计进入仓库后，后续源码必须满足：

- `.github/workflows/ci.yml` governance 检查本文档存在和标题。
- README、ROADMAP、Linux native start 设计和 release strategy 能发现本文档。
- TODO 指向下一步最小源码增量，而不是直接接入 `start`。
- `engine-native` 在 listener/node 解析和图校验完成后，必须先以 service-owned runtime state 返回 `Running`，再接入 `networkcore-linux start` binary。
- `networkcore-linux start` 接入真实 runtime handle 和 binary lifecycle 后，仍必须保持无 daemon/control socket 边界。

## 后续工作

- Linux artifact readiness/release gate 已纳入 foreground stop/release 合同检查、artifact manifest 输出合同、license/NOTICE confirmation source contract、license/NOTICE transition validation contract、release license/NOTICE confirmed 状态 summary、release CI success source contract、release CI gate activation validation contract、package runner/toolchain/target contract、archive staging contract、checksum/manifest checksum contract、publish/upload boundary contract、signing/attestation policy binding contract、release notes/rollback policy binding contract 和 publish eligibility aggregate contract；当前 marker 为 `linux-artifact-release-state=confirmed-release-path`，后续 tag release 继续通过 release workflow gates 生成 `package-linux` artifact。
- Linux package artifact job preflight validation contract、Linux package artifact build command validation contract、Linux package artifact staging file validation contract、Linux package artifact archive creation validation contract 和 Linux package artifact checksum execution validation contract 已定义；Linux package artifact manifest generation validation contract、Linux package artifact manifest checksum validation contract、Linux package workflow artifact bundle upload validation contract、Linux package artifact attestation execution validation contract、Linux package release notes/rollback execution validation contract 和 Linux package publish eligibility execution validation contract 已定义；release CI gate execution validation contract 和 release CI gate API implementation 已激活；当前 license/NOTICE 和 artifact gates 已进入 confirmed release path；后续 tag release 继续通过 release workflow、同 commit CI、checksum、manifest、attestation、release notes、rollback 和 publish eligibility gates 生成和发布 Linux assets。
