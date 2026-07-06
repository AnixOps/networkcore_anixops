# Changelog

本文件记录项目可审计变更。格式遵循轻量级 `Keep a Changelog` 风格，但所有验证结论以 GitHub Actions 为准。

## Unreleased

### Added

- 在 `engine-native` 中新增 SOCKS5 outbound CONNECT data relay 执行诊断合同，`relay_socks5_outbound_connect_data` 可在源码合同边界对有限 `Read`/`Write` stream 执行 client-to-outbound 与 outbound-to-client 复制，返回双向字节数并记录 `engine.native.runtime.socks5_outbound_connect_data_relay_completed` 或 `engine.native.runtime.socks5_outbound_connect_data_relay_failed`；accept loop 当前仍不调用该 relay executor，也不写入 client success response，继续记录 write plan blocked/rejected、随后写入 CONNECT general failure response 并关闭连接；`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增 SOCKS5 outbound CONNECT client success response write 诊断合同，`write_socks5_outbound_connect_client_success_response` 会基于有效的上游 SOCKS5 CONNECT success response 生成并写入 client success response frame，记录 `engine.native.runtime.socks5_outbound_connect_client_success_response_written` 或 `engine.native.runtime.socks5_outbound_connect_client_success_response_write_failed`；该 writer 目前保持源码合同和单元合同测试边界，accept loop 仍因 data relay 尚未接线而只记录 write plan blocked/rejected、随后写入 CONNECT general failure response 并关闭连接；双向数据转发、`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增 SOCKS5 outbound CONNECT client success response write plan 诊断合同，`plan_socks5_outbound_connect_client_success_response_write` 将 client success response readiness 尚未接线的路径标记为 blocked，将上游 rejected 路径标记为 rejected，并记录 `engine.native.runtime.socks5_outbound_connect_client_success_response_write_plan_unwired` 或 `engine.native.runtime.socks5_outbound_connect_client_success_response_write_plan_rejected`；accept loop 在 client success response readiness 后记录 write plan，随后仍记录 route/outbound 未接入、向 client 写入 CONNECT general failure response 并关闭 accepted/outbound 连接；SOCKS5 success response 写入、双向数据转发、`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增 SOCKS5 outbound CONNECT client success response readiness 诊断合同，`assess_socks5_outbound_connect_client_success_response_readiness` 将 data relay plan 尚未接线的路径标记为 blocked，将上游 rejected 路径标记为 rejected，并记录 `engine.native.runtime.socks5_outbound_connect_client_success_response_unwired` 或 `engine.native.runtime.socks5_outbound_connect_client_success_response_rejected`；accept loop 在 data relay plan 后记录 client success response readiness，随后仍记录 route/outbound 未接入、向 client 写入 CONNECT general failure response 并关闭 accepted/outbound 连接；client success response write plan、SOCKS5 success response 写入、双向数据转发、`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增 SOCKS5 outbound CONNECT data relay plan 诊断合同，`plan_socks5_outbound_connect_data_relay` 将已 accepted 但 relay 尚未接线的路径标记为 blocked，将上游 rejected 路径标记为 rejected，并记录 `engine.native.runtime.socks5_outbound_connect_data_relay_plan_unwired` 或 `engine.native.runtime.socks5_outbound_connect_data_relay_plan_rejected`；accept loop 在 relay readiness 后记录 data relay plan，随后仍记录 route/outbound 未接入、向 client 写入 CONNECT general failure response 并关闭 accepted/outbound 连接；client success response readiness、SOCKS5 success response 写入、双向数据转发、`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增 SOCKS5 outbound CONNECT relay readiness 诊断合同，`assess_socks5_outbound_connect_relay_readiness` 将已 accepted 的上游 CONNECT response 标记为 blocked，因为本地 relay 尚未接线，并将 rejected 上游 response 标记为 rejected，记录 `engine.native.runtime.socks5_outbound_connect_relay_unwired` 或 `engine.native.runtime.socks5_outbound_connect_relay_rejected`；accept loop 在 response decision 后记录 relay readiness，随后仍记录 route/outbound 未接入、向 client 写入 CONNECT general failure response 并关闭 accepted/outbound 连接；data relay plan、双向数据转发、SOCKS5 success response 写入、`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增 SOCKS5 outbound CONNECT response decision 诊断合同，`decide_socks5_outbound_connect_response` 将上游 success reply 归类为 accepted，将非成功或 invalid response 归类为 rejected，并记录 `engine.native.runtime.socks5_outbound_connect_response_accepted` 或 `engine.native.runtime.socks5_outbound_connect_response_rejected`；accept loop 在 response read 后记录 decision，随后仍记录 route/outbound 未接入、向 client 写入 CONNECT general failure response 并关闭 accepted/outbound 连接；SOCKS outbound relay readiness、双向数据转发、SOCKS5 success response 写入、`NativeProxyEngineService::start` 与 `networkcore-linux start` 在该增量中继续保持未接线。
- 在 `engine-native` 中新增 SOCKS5 outbound CONNECT response read 诊断合同，`read_socks5_outbound_connect_response` 读取上游 SOCKS5 response header、bound address 和 bound port，并记录 `engine.native.runtime.socks5_outbound_connect_response_read`、`engine.native.runtime.socks5_outbound_connect_response_invalid` 或 `engine.native.runtime.socks5_outbound_connect_response_read_failed`；accept loop 在 outbound CONNECT request 写入成功后读取上游响应，随后仍记录 route/outbound 未接入、向 client 写入 CONNECT general failure response 并关闭 accepted/outbound 连接；SOCKS outbound CONNECT response decision、双向数据转发、SOCKS5 success response 写入、`NativeProxyEngineService::start` 与 `networkcore-linux start` 在该增量中继续保持未接线。
- 在 `engine-native` 中新增 SOCKS5 outbound CONNECT request write 诊断合同，`write_socks5_outbound_connect_request` 将 connection plan 中已生成的 request frame 写入可用 outbound TCP stream，并记录 `engine.native.runtime.socks5_outbound_connect_request_written` 或 `engine.native.runtime.socks5_outbound_connect_request_write_failed`；accept loop 在 outbound TCP connection attempt 成功后写入上游 SOCKS5 CONNECT request，随后仍记录 route/outbound 未接入、向 client 写入 CONNECT general failure response 并关闭 accepted/outbound 连接；该增量当时仍未接入 SOCKS outbound CONNECT response 读取、双向数据转发、SOCKS5 success response 写入、`NativeProxyEngineService::start` 与 `networkcore-linux start`。
- 在 `engine-native` 中新增 SOCKS5 outbound TCP connection attempt 诊断合同，`attempt_socks5_outbound_tcp_connection` 基于 connection plan 对 IP endpoint 执行有界 `TcpStream::connect_timeout`，并记录 `engine.native.runtime.socks5_outbound_tcp_connection_attempt_succeeded` 或 `engine.native.runtime.socks5_outbound_tcp_connection_attempt_failed`；accept loop 在 plan 生成后尝试 outbound TCP 连接，随后仍记录 route/outbound 未接入、写入 CONNECT general failure response 并关闭 accepted connection；SOCKS outbound CONNECT request 写入、双向数据转发、SOCKS5 success response 写入、`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增 SOCKS5 outbound TCP connection plan 诊断合同，`plan_socks5_outbound_tcp_connection` 基于 `ProxyViaSocksOutbound` 与 request frame 记录 outbound handler endpoint、CONNECT 目标和 frame，并记录 `engine.native.runtime.socks5_outbound_tcp_connection_planned` 或 `engine.native.runtime.socks5_outbound_tcp_connection_plan_invalid`；accept loop 在 frame 生成后创建 plan 诊断，随后仍记录 route/outbound 未接入、写入 CONNECT general failure response 并关闭连接；真实 outbound TCP connection attempt、数据转发、SOCKS5 success response 写入、`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增 SOCKS5 outbound CONNECT request frame 生成诊断合同，`build_socks5_outbound_connect_request_frame` 可为 IPv4、domain 和 IPv6 CONNECT 目标生成上游 SOCKS5 request frame，并记录 `engine.native.runtime.socks5_outbound_connect_request_frame_generated` 或 `engine.native.runtime.socks5_outbound_connect_request_frame_invalid`；accept loop 会在 route/outbound 行为选择后生成该 frame 的诊断，随后仍记录 route/outbound 未接入、写入 CONNECT general failure response 并关闭连接；真实 outbound TCP 连接、数据转发、SOCKS5 success response 写入、`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增 SOCKS5 CONNECT route/outbound 行为选择诊断合同，accept loop 会在有效 no-auth CONNECT 目标后用当前配置的 SOCKS outbound handler 生成 `NativeSocks5RouteOutboundBehavior::ProxyViaSocksOutbound` 并记录 `engine.native.runtime.socks5_route_outbound_selected`，随后仍记录 `engine.native.runtime.socks5_route_outbound_unwired`、写入 CONNECT general failure response 并关闭连接；真实 outbound TCP 连接、SOCKS outbound request frame、数据转发、SOCKS5 success response 写入、`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增 SOCKS5 route/outbound 未接入时的 CONNECT failure response 写入诊断合同，accept loop 会在有效 no-auth CONNECT 目标后记录 `engine.native.runtime.socks5_route_outbound_unwired`，写入 `[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]` 并记录 `engine.native.runtime.socks5_connect_failure_response_written` 或 `engine.native.runtime.socks5_connect_failure_response_write_failed`，随后关闭连接；该增量当时仍没有 route/outbound 行为选择、route/outbound 数据面、SOCKS5 success response 写入、`NativeProxyEngineService::start` 与 `networkcore-linux start` 接线。
- 在 `engine-native` 中新增 SOCKS5 CONNECT 目标地址读取与 route/outbound 未接入拒绝诊断合同，accept loop 会在 no-auth CONNECT 命令头后读取 IPv4、domain 或 IPv6 目标地址和端口并记录 `engine.native.runtime.socks5_connect_target_read`、`engine.native.runtime.socks5_connect_target_invalid` 或 `engine.native.runtime.socks5_connect_target_read_failed`，随后记录 `engine.native.runtime.socks5_route_outbound_unwired` 并关闭连接；该增量当时仍不写入 SOCKS5 failure response，route/outbound 数据面、`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增 SOCKS5 命令头读取与 unsupported command 拒绝诊断合同，accept loop 会在 no-auth 响应写入后读取 `[VER, CMD, RSV, ATYP]` 命令头并记录 `engine.native.runtime.socks5_command_header_read`、`engine.native.runtime.socks5_command_header_invalid` 或 `engine.native.runtime.socks5_command_header_read_failed`，对非 CONNECT 命令记录 `engine.native.runtime.socks5_command_unsupported`；该增量当时仍关闭连接且不解析 CONNECT 目标地址、不进入 route/outbound 数据面，`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增 SOCKS5 认证方法响应写入诊断合同，accept loop 会在 auth 方法选择后写入 `[0x05, method]` 响应并记录 `engine.native.runtime.socks5_auth_method_response_written` 或 `engine.native.runtime.socks5_auth_method_response_write_failed`；该增量当时仍关闭连接且不解析 SOCKS5 命令、不进入 route/outbound 数据面，`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增 SOCKS5 no-auth 方法选择与 unsupported auth 方法拒绝诊断合同，accept loop 会在读取有效 greeting 后记录 `engine.native.runtime.socks5_auth_method_selected` 或 `engine.native.runtime.socks5_auth_method_unsupported`；该增量当时仍关闭连接且不写入 SOCKS5 方法响应、不进入 route/outbound 数据面，`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增首个 SOCKS5 greeting 版本/认证方法读取诊断合同，accept loop 会在 accepted loopback TCP connection 上读取 greeting 并记录 `engine.native.runtime.socks5_greeting_read`、`engine.native.runtime.socks5_greeting_invalid` 或 `engine.native.runtime.socks5_greeting_read_failed` 诊断，随后仍关闭连接且不进入 route/outbound 数据面；`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增 accepted TCP connection 的协议前置关闭诊断合同，accept loop 会在完整 proxy protocol 尚未实现时显式关闭连接并记录 `engine.native.runtime.connection_pre_protocol_closed` 诊断和计数；完整 proxy protocol 解析、route/outbound 数据面、`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增首个 loopback TCP accept loop 源码合同，覆盖受控关闭、accepted connection 计数、runtime release 停止报告和 accept loop ready/stopped 诊断；完整 proxy protocol、route/outbound 数据面、`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增 `NativeRuntimeAssemblyPlan`，可从有效 listener/node/route 配置图选择 loopback TCP listener 与 SOCKS outbound handler，并将绑定失败或 lifecycle handoff 失败映射为带资源释放报告的 startup failure；`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增真实 loopback TCP listener 绑定/释放实现，runtime assembly 可持有并释放当前进程内的 listener resource，覆盖绑定失败和端口释放合同测试；`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增首个 native runtime handle 源码合同，覆盖 loopback listener handle、SOCKS outbound handler handoff、启动失败释放报告、runtime events 和 foreground lifecycle handoff status；`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增 listener/node/route 结构化图校验，明确 `ConfigSnapshot.nodes` 与运行请求 nodes 的合并和重复 id 拒绝边界；`networkcore-linux start` 继续保持未接线。
- 在 `config-core` 中解析最小 listener/node/route TOML 子集，将本地 nodes 标准化进 `ConfigSnapshot`，并补充稳定诊断合同测试；`networkcore-linux start` 继续保持未接线。
- 在 `control-domain` 中新增 listener 配置领域类型，将 `ConfigSnapshot` 扩展为显式携带 listeners，并补充合同测试；`networkcore-linux start` 继续保持未接线。
- 新增 Native engine listener/node 配置设计文档，定义原生 runtime handle 前的 listener、node、route、DNS 图、诊断 code 和源码接线门槛，并纳入 CI/release readiness governance；`networkcore-linux start` 继续保持未接线。
- 新增 `networkcore-linux` 前台 lifecycle host 源码合同，覆盖 running handoff、默认 unavailable host、非 running 拒绝和诊断聚合；二进制入口的 `start` 继续保持未接线。
- 新增最小 `engine-native` crate，提供原生 `ProxyEngineService` descriptor、配置拒绝、生命周期诊断和 secret 不泄露合同测试；`networkcore-linux start` 继续保持未接线。
- 新增 Linux native proxy engine start 设计文档，明确首个原生 `ProxyEngineService` adapter、前台 lifecycle host、`networkcore-linux start` 接线门槛和继续保持未接线诊断的条件。
- 新增最小 `config-core` crate，提供纯 TOML 配置服务、schema/profile 解析、secret 不泄露诊断合同测试，并将 `networkcore-linux prepare-config` 接入二进制入口；`start` 继续保持未接线诊断。
- 新增 Linux CLI runtime wiring 设计文档，明确 `prepare-config`/`start` 接入运行层前的配置服务、代理引擎服务和前台生命周期 host 边界，并纳入 CI governance 检查。
- 将 `networkcore-linux capabilities/status/diagnostics` 接入 `HostLinuxReadOnlyProbe`，通过 `PlatformCapabilityService` 输出只读 Linux 平台诊断，并保留 `start` 等运行层命令未接线诊断。
- 在 `platform-linux` 中新增只读 Linux 平台探测服务，提供 `HostLinuxReadOnlyProbe`、可注入 probe 边界、TUN/权限/DNS/service 诊断映射和 `/proc/self/status` 解析合同测试。
- 补充 release workflow 的 `linux-artifact-readiness` job，检查 Linux CLI 源码、platform adapter、安装/回滚设计和 license/NOTICE 人工事项，并继续阻止 release asset 上传。
- 新增 Linux CLI artifact 安装、卸载与回滚设计文档，明确首个 `networkcore-linux` 压缩包的手动解压模型、卸载清单、用户侧回滚和 `package-linux` 前置门禁。
- 补充真实 release artifact 前的 license 或 NOTICE 文本人工确认事项。
- 新增最小 `networkcore-linux` CLI crate，提供命令解析、配置读取抽象、平台能力/status/stop/start 诊断映射和 JSON 输出合同测试。
- 新增最小 `platform-linux` crate，提供 `PlatformCapabilityService` 静态测试替身、Linux 诊断 code 常量和 TUN、权限、DNS、服务管理、证书状态映射合同测试。
- 新增 Linux CLI entrypoint 设计文档，明确首个 `networkcore-linux` 入口的命令、配置加载、启动/停止、状态查询、输出和退出码边界。
- 新增 Linux platform adapter 设计文档，定义 TUN、权限、DNS、服务管理、证书和诊断探测边界。
- 新增 Linux artifact 发布前设计文档，明确首个平台产物的源码、packaging、checksum、签名/证明和回滚前置条件。
- 补充 release rollback contract 占位 job，定义真实 artifact 发布说明必须输出的回滚字段。
- 补充 release signing/attestation contract 占位 job，定义真实平台 artifact 发布前的签名或证明进入条件。
- 补充 release artifact checksum contract 占位 job，定义首个真实 artifact job 的 checksum 输出字段。
- 补充 release-ci-gate 占位 job，记录真实 artifact 前必须关联 `main` CI 成功结果。
- 补充 release workflow summary job，输出 placeholder 发布状态和后续 artifact 门禁。
- 补充 release workflow 发布来源 summary，记录 workflow_dispatch 版本输入、触发事件、ref、commit SHA 和 actor。
- 补充 release workflow 版本格式与触发来源一致性 policy gate，约束手动 placeholder release 来源和 tag 版本。
- 补充 CI summary GitHub Step Summary 表格，汇总项目类型检测开关和关键 job 结果。
- 补充 CI summary 项目类型检测输出，每次记录 Go、Rust、Node、Swift 和 Apple 检测开关。
- 补强 CI summary Go、Node、Swift 和 Apple 条件门禁，显式输出并在对应项目出现时检查语言与平台 job 结果。
- 补强 CI summary Rust 门禁，显式输出并检查 Rust build/test 矩阵结果和 Rust dependency security audit 结果。
- 补充 `control-runtime` MITM gate 权限拒绝诊断顺序合同测试，覆盖平台、证书、manifest 非错误诊断和 runtime 权限拒绝诊断按聚合顺序输出。
- 补充 `control-runtime` MITM gate manifest 错误拒绝诊断顺序合同测试，覆盖平台、证书、manifest 和 runtime 诊断按聚合顺序输出。
- 补充 `control-runtime` MITM gate manifest 错误优先于权限拒绝合同测试，覆盖 manifest 错误会在缺失权限前短路并返回 manifest 错误拒绝原因。
- 补充 `control-runtime` MITM gate manifest 错误拒绝证书诊断保留合同测试，覆盖证书诊断会保留在 manifest 错误拒绝决策输出中。
- 补充 `control-runtime` MITM gate manifest 错误拒绝平台诊断保留合同测试，覆盖平台诊断会保留在 manifest 错误拒绝决策输出中。
- 补充 `control-runtime` MITM gate manifest 错误拒绝审计合同测试，覆盖 manifest 错误拒绝 reason、审计和禁止调用插件 `load`/`handle_http_event`/`audit` 端口。
- 补充 `control-runtime` MITM gate 远程脚本拒绝诊断聚合合同测试，覆盖平台诊断会保留在远程脚本拒绝决策输出中。
- 补充 `control-runtime` MITM gate 证书拒绝诊断聚合合同测试，覆盖证书状态诊断会保留在证书拒绝决策输出中。
- 补充 `control-runtime` MITM gate 权限拒绝诊断聚合合同测试，覆盖 manifest 非错误诊断会保留在权限拒绝决策输出中。
- 补充 `control-runtime` MITM gate 平台诊断拒绝路径合同测试，覆盖平台能力诊断会保留在平台拒绝决策输出中。
- 补充 `control-runtime` MITM gate 平台诊断聚合合同测试，覆盖平台能力与证书诊断会进入允许决策输出。
- 补充 `control-runtime` MITM gate 插件结果诊断聚合合同测试，覆盖插件执行返回 warning/info 诊断会进入允许决策输出。
- 补充 `control-runtime` MITM gate manifest 警告诊断放行合同测试，覆盖 warning/info 诊断不会阻断插件执行且会聚合到输出。
- 补充 `control-runtime` MITM gate 权限拒绝审计合同测试，覆盖缺失权限 reason 和禁止调用插件 `load`/`handle_http_event`/`audit` 端口。
- 补充 `control-runtime` MITM gate 远程脚本未知状态合同测试，覆盖未知状态拒绝原因、诊断、审计和禁止调用插件端口。
- 补充 `control-runtime` MITM gate 证书状态拒绝矩阵合同测试，覆盖证书未安装、已安装未信任、已撤销和未知状态，并确认拒绝路径不会调用插件端口。
- 补充 `control-runtime` MITM gate 平台 MITM 不可用合同测试，覆盖平台拒绝原因和禁止调用插件端口。
- 补充 `control-runtime` MITM gate 审计事件聚合合同测试，覆盖 gate 审计、插件结果审计和 `audit` 端口审计的输出边界。
- 补充 `control-runtime` MITM gate manifest validation 合同测试，覆盖 manifest 诊断拒绝路径。
- 扩展 `control-runtime` MITM gate，新增远程脚本执行禁用拒绝路径，并覆盖插件加载与事件处理端口错误传播。
- 新增 `control-runtime` MITM gate 初始用例，组合平台能力与 MITM 插件端口，并覆盖证书未信任、权限拒绝和授权通过路径。
- 新增最小 `control-runtime` crate，组合配置、平台能力和代理引擎领域端口，并覆盖启动成功、平台拒绝和引擎错误传播路径。
- 新增运行层编排设计文档，定义 `control-runtime` 的职责、生命周期、端口组合和首个源码增量验收条件。
- 在 `control-domain` 中新增平台能力状态、MITM 证书状态和 `PlatformCapabilityService` 领域端口。
- 新增发布策略文档，定义真实平台产物进入 release workflow 前的门禁、矩阵和回滚路径。
- 新增 iOS 平台风险评估，覆盖 Network Extension、证书信任、插件脚本权限和 App Review 门禁。
- 新增 Rust dependency/security scan CI job，在 GitHub Actions 中生成 lockfile 并执行 `cargo audit`。
- 新增可插拔代理执行内核适配接口规格，并在 `control-domain` 中加入 `ProxyEngineService` 领域端口。
- 新增最小 Rust workspace 与 `control-domain` crate，提供领域共享类型、端口 trait、单元测试和集成测试。
- 新增控制内核接口草案，覆盖配置、订阅、策略路由、DNS、MITM 插件和控制 API 的首批契约。
- 新增 ADR 0001，选择 Rust 作为首个统一控制内核实现栈，并记录后续 CI/CD 验证策略。
- 新增统一控制内核领域与架构规格，定义首批上下文、端口和后续源码骨架验收条件。
- 建立 `ROADMAP.md`，明确 bootstrap、架构规格、内核骨架、运行能力和客户端集成阶段。
- 建立 `TODO.md`，记录当前最小增量待办和维护规则。
- 将规划治理文件纳入 README 与 CI policy 约束。

## 2026-07-06

### Added

- 建立 bootstrap 阶段的代理规范、贡献规则、CI/CD policy、GitHub Actions skeleton 和人工介入记录。
