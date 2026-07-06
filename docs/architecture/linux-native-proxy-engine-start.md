# Linux Native Proxy Engine Start Design

本文定义首个原生代理执行内核源码进入仓库前必须满足的 `ProxyEngineService`
adapter、前台生命周期 host 和 `networkcore-linux start` 接线边界。它承接
[Proxy Engine Adapter Interface](proxy-engine-adapter.md)、
[Native Engine Listener And Node Config Design](native-engine-listener-node-config.md)、
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

- 不在本文实现 TCP、UDP、TUN、DNS、MITM 或透明代理协议。
- 不在本文实现 daemon、control socket、systemd unit、PID file、installer 或 release artifact。
- 不选择 async runtime、socket 库、packet capture、netlink 或平台代理 SDK。
- 不启动外部 `sing-box`、`xray-core`、`mihomo` 或其他二进制。
- 不在本机运行、构建、测试、打包或试用 CLI。

## 当前源码状态

当前仓库已经具备：

- `control-domain::ProxyEngineService` 领域端口，定义 engine descriptor、配置校验、启动、重载、停止、状态和事件读取。
- `control-runtime::RuntimeOrchestrator::start_runtime`，按平台、配置和引擎校验顺序编排启动。
- `config-core::CoreConfigurationService`，提供只读 TOML schema/profile 和最小 listener/node/route 配置准备。
- [Native Engine Listener And Node Config Design](native-engine-listener-node-config.md) 定义后续 listener、node、route 和 DNS 配置图进入 `engine-native` 前的模型边界。
- `engine-native::NativeProxyEngineService`，提供原生 engine descriptor、listener/node/route 结构化图校验、启动不可用、stopped status 和空 events 合同。
- `engine-native` 已补充首个 native runtime handle 源码合同，覆盖 loopback listener handle、SOCKS outbound handler handoff、启动失败释放报告、runtime events 和 foreground lifecycle handoff status。
- `engine-native` 已补充真实 loopback TCP listener 绑定/释放实现，runtime assembly 可持有当前进程内的 `TcpListener` resource。
- `engine-native` 已补充从有效配置图生成首个 native runtime assembly plan 的源码合同，选择 loopback TCP listener 与 SOCKS outbound handler，并覆盖绑定失败和 lifecycle handoff 失败的释放报告。
- `engine-native` 已补充首个 loopback TCP accept loop 与受控关闭源码合同，覆盖 accepted connection 计数、runtime release 停止报告和 ready/stopped 诊断。
- `engine-native` 已补充 accepted TCP connection 的协议前置关闭诊断合同，在完整 proxy protocol 尚未实现时显式关闭 accepted connection，记录 pre-protocol close 计数和 `engine.native.runtime.connection_pre_protocol_closed` 诊断；当前仍未接入 `NativeProxyEngineService::start`，也没有 route/outbound 数据面。
- `engine-native` 已补充首个 SOCKS5 greeting 版本/认证方法读取诊断合同，可在 accepted loopback TCP connection 上读取 greeting 并记录 `engine.native.runtime.socks5_greeting_read`、`engine.native.runtime.socks5_greeting_invalid` 或 `engine.native.runtime.socks5_greeting_read_failed` 诊断，后续可进入 auth、命令和 CONNECT failure response 分支，最终仍关闭连接且不进入 route/outbound 数据面。
- `engine-native` 已补充 SOCKS5 no-auth 方法选择与 unsupported auth 方法拒绝诊断合同，可在有效 greeting 后记录 `engine.native.runtime.socks5_auth_method_selected` 或 `engine.native.runtime.socks5_auth_method_unsupported` 诊断；当前已继续写入 SOCKS5 方法响应并读取命令，但仍没有 route/outbound 数据面。
- `engine-native` 已补充 SOCKS5 认证方法响应写入诊断合同，可写入 `[0x05, method]` 响应并记录 `engine.native.runtime.socks5_auth_method_response_written` 或 `engine.native.runtime.socks5_auth_method_response_write_failed` 诊断。
- `engine-native` 已补充 SOCKS5 命令头读取与 unsupported command 拒绝诊断合同，可在 no-auth 响应后读取 `[VER, CMD, RSV, ATYP]` 并记录 `engine.native.runtime.socks5_command_header_read`、`engine.native.runtime.socks5_command_header_invalid` 或 `engine.native.runtime.socks5_command_header_read_failed` 诊断，对非 CONNECT 命令记录 `engine.native.runtime.socks5_command_unsupported`。
- `engine-native` 已补充 SOCKS5 CONNECT 目标地址读取、route/outbound 行为选择、SOCKS outbound CONNECT request frame 生成、SOCKS outbound TCP connection plan、SOCKS outbound TCP connection attempt、SOCKS outbound CONNECT request write、SOCKS outbound CONNECT response read、SOCKS outbound CONNECT response decision、SOCKS outbound CONNECT relay readiness、未接入拒绝与 CONNECT failure response 写入诊断合同，可在有效 no-auth CONNECT 命令后读取 IPv4、domain 或 IPv6 目标地址和端口并记录 `engine.native.runtime.socks5_connect_target_read`、`engine.native.runtime.socks5_connect_target_invalid` 或 `engine.native.runtime.socks5_connect_target_read_failed`，随后用当前配置的 SOCKS outbound handler 生成 `NativeSocks5RouteOutboundBehavior::ProxyViaSocksOutbound` 并记录 `engine.native.runtime.socks5_route_outbound_selected`，再基于该行为在内存中生成上游 SOCKS5 CONNECT request frame 并记录 `engine.native.runtime.socks5_outbound_connect_request_frame_generated` 或 `engine.native.runtime.socks5_outbound_connect_request_frame_invalid`，再创建内存中的 SOCKS outbound TCP connection plan 并记录 `engine.native.runtime.socks5_outbound_tcp_connection_planned` 或 `engine.native.runtime.socks5_outbound_tcp_connection_plan_invalid`，随后对 IP endpoint 执行有界 TCP connection attempt 并记录 `engine.native.runtime.socks5_outbound_tcp_connection_attempt_succeeded` 或 `engine.native.runtime.socks5_outbound_tcp_connection_attempt_failed`，在 outbound TCP stream 可用时写入 SOCKS outbound CONNECT request 并记录 `engine.native.runtime.socks5_outbound_connect_request_written` 或 `engine.native.runtime.socks5_outbound_connect_request_write_failed`，在 request 写入成功后读取 SOCKS outbound CONNECT response 并记录 `engine.native.runtime.socks5_outbound_connect_response_read`、`engine.native.runtime.socks5_outbound_connect_response_invalid` 或 `engine.native.runtime.socks5_outbound_connect_response_read_failed`，再将上游 success reply 归类为 accepted 并记录 `engine.native.runtime.socks5_outbound_connect_response_accepted`，或将非成功/invalid response 归类为 rejected 并记录 `engine.native.runtime.socks5_outbound_connect_response_rejected`，随后记录 relay readiness：已 accepted 但本地 relay 未接线时记录 `engine.native.runtime.socks5_outbound_connect_relay_unwired`，上游 rejected 时记录 `engine.native.runtime.socks5_outbound_connect_relay_rejected`，最后记录 `engine.native.runtime.socks5_route_outbound_unwired` 并写入 SOCKS5 general failure response；该实现尚没有 client success response 写入或数据转发。
- `networkcore-linux` 库层提供 `ForegroundLifecycleHost`、`ForegroundLifecycleRequest`、`ForegroundLifecycleOutcome`、默认 unavailable host 和 `handle_foreground_lifecycle` 合同，覆盖前台 handoff 诊断聚合。
- `platform-linux::ReadOnlyLinuxPlatformCapabilityService<HostLinuxReadOnlyProbe>`，提供只读 Linux 平台能力诊断。
- `networkcore-linux` binary 只将 `prepare-config` 接入 `RuntimeOrchestrator`；`start` 仍通过 `UnavailableProxyEngineService` 和 `cli.linux.runtime.unwired` 保持未接线。

该状态是正确的安全边界。原生 engine adapter 的完整运行句柄、数据面和前台 handoff 未完成前，不得把
`LinuxCliCommand::Start` 路由到二进制入口的 `handle_start`。

## Adapter 边界

当前首个源码边界是 `crates/engine-native`。该 crate 必须：

1. 只依赖 `control-domain` 和实现自身需要的最小运行时依赖。
2. 提供 `NativeProxyEngineService` 或等价类型，实现 `ProxyEngineService`。
3. 通过 `list_engines()` 返回 id 为 `native`、kind 为 `ProxyEngineKind::Native` 的 descriptor。
4. 只声明已经真实实现的 `ProxyEngineCapability`，不得预先声明 TUN、DNS、MITM、HotReload 或 HealthCheck。
5. 将所有 adapter 私有错误映射为稳定 `Diagnostic` 或 `DomainError`，不得向 CLI 泄漏内部错误类型、backtrace、socket path 或敏感配置值。
6. 在没有真实运行句柄前，`start()` 必须返回 `DomainError`，不得返回 `Running`。

当前 adapter 只实现严格的配置拒绝和生命周期诊断合同，不能被接入
`networkcore-linux start`，除非同时具备真实运行句柄和前台 lifecycle host 接线。

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
| `engine.native.runtime.connection_pre_protocol_closed` | Info | accepted TCP connection 在 route/outbound 处理前被显式关闭 |
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
| `engine.native.runtime.socks5_outbound_connect_response_accepted` | Info | SOCKS outbound CONNECT response 已接受 CONNECT request，但尚未向 client 写入 success response |
| `engine.native.runtime.socks5_outbound_connect_response_rejected` | Warning | SOCKS outbound CONNECT response 拒绝 CONNECT request 或响应无效 |
| `engine.native.runtime.socks5_outbound_connect_relay_unwired` | Warning | SOCKS outbound CONNECT response 已接受，但本地 relay 尚未接线，不能写入 client success response |
| `engine.native.runtime.socks5_outbound_connect_relay_rejected` | Warning | SOCKS outbound CONNECT relay readiness 被上游拒绝响应阻断 |
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

当前 `apps/linux-cli` 已提供源码合同，但未接入 binary：

- `ForegroundLifecycleHost::run_foreground` 是前台 host 唯一 handoff 边界。
- `ForegroundLifecycleRequest` 当前只携带 `ProxyEngineStatus`，后续真实运行句柄进入前必须先扩展合同。
- `ForegroundLifecycleOutcome` 统一返回 CLI exit code 和 host 诊断。
- `UnavailableForegroundLifecycleHost` 稳定返回 `cli.linux.start.lifecycle_host_missing`。
- `handle_foreground_lifecycle` 只接受已经完成 `RuntimeOrchestrator::start_runtime` 的 `RuntimeOperationResult`，并在非 `Running` 状态时返回 `cli.linux.start.lifecycle_failed`，不会调用 host。

推荐 host 诊断 code：

| code | severity | 含义 |
| --- | --- | --- |
| `cli.linux.start.foreground_only` | Info | 当前 `start` 只支持前台模式 |
| `cli.linux.start.lifecycle_host_missing` | Error | binary 尚未接入前台 lifecycle host |
| `cli.linux.start.lifecycle_interrupted` | Warning | 前台运行被用户或平台信号中断 |
| `cli.linux.start.lifecycle_failed` | Error | 前台 host 运行阶段失败 |

## `networkcore-linux start` 接线门槛

二进制入口只有在以下条件全部满足后，才能将 `LinuxCliCommand::Start` 从
`handle_entrypoint` 的 unavailable 路径改为 `handle_start` 或等价前台启动路径：

- `engine-native` 或等价 crate 存在，并有 GitHub Actions 覆盖 format、lint、test、build 和 dependency audit。
- adapter 合同测试覆盖 descriptor、结构化配置拒绝、runtime handle 源码合同、runtime assembly plan、loopback TCP listener 绑定/释放、loopback TCP accept loop 受控关闭、协议前置关闭诊断、SOCKS5 greeting 读取、auth 方法选择/拒绝、auth 方法响应写入、SOCKS5 命令头读取、unsupported command 拒绝、CONNECT 目标地址读取、route/outbound 行为选择、SOCKS outbound CONNECT request frame 生成、SOCKS outbound TCP connection plan、SOCKS outbound TCP connection attempt、SOCKS outbound CONNECT request write、SOCKS outbound CONNECT response read、SOCKS outbound CONNECT response decision、SOCKS outbound CONNECT relay readiness、data relay、route/outbound 未接入拒绝、CONNECT failure response 写入、启动失败、running 状态、status、events 和 secret 不泄露。
- listener/node 配置模型按 [Native Engine Listener And Node Config Design](native-engine-listener-node-config.md) 完成源码合同，且 adapter 能校验 listener、node、route 和 DNS 图；当前已覆盖 listener/node/route，DNS 需求判断仍需在真实 handler 前完成。
- 前台 lifecycle host 有源码或设计合同，覆盖不 daemonize、不安装服务、退出码和诊断聚合。
- CLI 合同测试覆盖 `start` 成功、平台拒绝、配置拒绝、engine 拒绝、host 失败和 JSON 输出。
- `stop` 与后台 `status` 继续保持无 daemon/control socket 诊断，不能因为前台 start 合入而声称支持跨进程控制。
- Linux artifact readiness 与安装/回滚文档继续阻止 release asset，直到 packaging、license/NOTICE 和回滚门禁完成。

未满足任一条件时，binary 必须继续组合 `UnavailableProxyEngineService`，并让
`start` 返回 `cli.linux.runtime.unwired`。

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

- 在 `engine-native` 中补充 SOCKS5 outbound CONNECT data relay plan 诊断合同，继续不写入 client success response、不进行双向数据转发、不接入 `networkcore-linux start`。
- 当前 `networkcore-linux start` 继续保持 `cli.linux.runtime.unwired`。
- 在原生 runtime 运行句柄和前台 lifecycle host binary 接线完成前，不加入 `package-linux`，也不发布 Linux artifact。
