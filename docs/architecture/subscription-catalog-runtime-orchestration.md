# Subscription Catalog Runtime Orchestration Design

本文定义 P3 阶段把订阅 catalog 接入运行层前必须遵守的编排边界。它承接
[Control Kernel Interface Draft](control-kernel-interfaces.md)、
[Control Runtime Orchestration Design](control-runtime-orchestration.md)、
[Native Engine Listener And Node Config Design](native-engine-listener-node-config.md) 和
[Linux Native Proxy Engine Start Design](linux-native-proxy-engine-start.md)。

评估时间：2026-07-08。

## 目标

- 定义 `CoreSubscriptionService` 产出的 `NodeCatalog` 如何进入运行层启动请求。
- 固定 `ConfigSnapshot.nodes`、subscription catalog nodes 和 `RuntimeConfigRequest.nodes` 的所有权边界。
- 在策略路由和 DNS 接入前保持稳定、可诊断、可回滚的行为。
- 防止订阅接入引入远程拉取、文件读取、secret 泄漏、系统 DNS/TUN mutation、daemon/control socket 或 release artifact。
- 固定当前英文 CI anchors：duplicate id、no remote subscription fetching、no file subscription loading、
  no system DNS/TUN mutation、no daemon/control socket。

## 非目标

- 不执行远程订阅拉取、认证刷新、文件订阅读取或默认订阅路径扫描。
- 不把 subscription rules 编译成最终策略路由，也不修改 `ConfigSnapshot.policies`。
- 不实现 DNS 策略、TUN、系统代理配置、daemon/control socket 或跨进程 stop/status。
- 不生成、打包、签名或发布 alpha/release artifact。
- 不在本机运行测试、构建、编译、打包或发布验证。

## 当前源码状态

当前仓库已经具备：

- `control-domain::SubscriptionService`，定义 `fetch`、`parse` 和 `normalize` 三段订阅端口。
- `control-domain::SubscriptionSource`、`RawSubscription`、`SubscriptionDocument` 和 `NodeCatalog`，能表达订阅 source、原始 payload、解析结果和归一化节点目录。
- `config-core::CoreSubscriptionService`，当前只接受显式 `inline:` source，把最小 subscription TOML `nodes`/`routes` 子集解析为 `SubscriptionDocument` 并归一化为 `NodeCatalog`。
- `control-runtime::RuntimeConfigRequest`，当前显式携带 `engine_id`、`raw_config`、`nodes` 和 `metadata`。
- `control-runtime::RuntimeOrchestrator::prepare_engine_config`，当前把 `RuntimeConfigRequest.nodes` 直接传给 `ProxyEngineConfig.nodes`。
- `control-runtime::RuntimeSubscriptionCatalogGateResult` 以及 `RuntimeOrchestrator::prepare_runtime_request_with_subscription_catalogs`、`start_runtime_with_subscription_catalogs` 和 `reload_runtime_with_subscription_catalogs`，当前基于调用方显式传入的 `SubscriptionService`/`SubscriptionSource` 把 inline `NodeCatalog.nodes` 编排进 `RuntimeConfigRequest.nodes`，并在运行层拒绝重复 node id、记录 rules deferred 诊断和 unsupported source 拒绝。
- `engine-native::NativeProxyEngineService`，当前把 `ConfigSnapshot.nodes` 与 `ProxyEngineConfig.nodes` 合并为 effective node catalog，并用 `engine.native.config.node_id_duplicate` 拒绝重复 node id。
- `engine-native` 合同测试已覆盖 `validate_config_uses_config_snapshot_nodes_for_route_targets` 和 `validate_config_uses_runtime_request_nodes_for_route_targets`，证明本地配置 nodes 与运行请求 nodes 都能作为 route target。

因此，P3 baseline 源码 gate 已覆盖订阅 catalog 进入 `RuntimeConfigRequest.nodes` 前的运行层所有权、重复 id 处理、诊断和 source 边界；当前 P4 阶段的后续缺口是把该 gate 暴露到具体应用层或 CLI 输入，同时继续禁止默认路径扫描、远程拉取和系统 mutation。

## 所有权模型

订阅 catalog 接入必须保持三层分工：

1. `config-core` 只负责纯解析和归一化。它不得读取默认文件、发起网络请求、访问 secret store、探测平台或执行图校验。
2. `control-runtime` 负责组合配置快照、订阅 catalog 和运行请求。它可以拒绝有歧义的 catalog，但不得重新解析 TOML、访问文件系统或执行网络请求。
3. `engine-native` 继续只消费 `ProxyEngineConfig`。它不得知道订阅来源、不得重新拉取订阅、不得从 metadata 中读取节点主模型。

本地配置节点的所有权保持在 `ConfigSnapshot.nodes`。订阅节点的所有权保持在 subscription catalog，并在进入 engine 前映射到 `RuntimeConfigRequest.nodes`。这两个集合不得通过 metadata 隐式传递。

## 编排数据流

P3 baseline 源码接入按以下顺序执行：

1. 应用层或 CLI 明确提供订阅 source；在当前阶段只允许 `inline:` source。
2. `SubscriptionService::fetch` 返回 `RawSubscription`；unsupported source 必须返回稳定 `DomainError`，不得泄漏 URL token、header、credential 或 payload secret。
3. `SubscriptionService::parse` 返回 `SubscriptionDocument`；解析失败诊断不得包含原始 secret。
4. `SubscriptionService::normalize` 返回 `NodeCatalog`。
5. 运行层对 `NodeCatalog.nodes` 做最小 catalog gate，生成可传给 `RuntimeConfigRequest.nodes` 的 typed nodes。
6. `RuntimeOrchestrator::start_runtime_with_subscription_catalogs` 或 `reload_runtime_with_subscription_catalogs` 继续把 gated `RuntimeConfigRequest.nodes` 传给 `ProxyEngineConfig.nodes`。
7. `engine-native` 对 `ConfigSnapshot.nodes` 和 `ProxyEngineConfig.nodes` 做最终图校验与 native runtime assembly。

当前不允许把 subscription rules 写入 `ConfigSnapshot.policies`。`NodeCatalog.rules` 在策略路由设计完成前只能作为 deferred facts 保留或产生 info 诊断，不参与 route target 决策。
后续 `PolicyRoutingService` 和 `DnsPolicyService` 接入前，本文只约束 catalog node handoff 和 Diagnostic 聚合顺序。

Current blocked anchors for CI governance: no remote subscription fetching, no file subscription loading,
no system DNS/TUN mutation, no daemon/control socket.

## 去重和优先级

节点 id 是策略引用的唯一键。订阅 catalog 接入不得静默覆盖本地配置或其他订阅节点：

- `ConfigSnapshot.nodes` 与 subscription catalog nodes 出现相同 `id` 时，运行层必须拒绝启动或重载。
- 已有 `RuntimeConfigRequest.nodes` 与 subscription catalog nodes 出现相同 `id` 时，运行层必须拒绝启动或重载。
- 同一 `NodeCatalog.nodes` 内重复 `id` 时，运行层必须拒绝。
- 多个 subscription catalog 合并时出现重复 `id`，运行层必须拒绝。
- 不得使用最后写入覆盖、按 source 优先级覆盖或自动改名。
- 本地配置节点继续留在 `ConfigSnapshot.nodes`；订阅节点只进入 `RuntimeConfigRequest.nodes`。

拒绝重复 id 的运行层诊断 code 应使用：

| code | severity | 含义 |
| --- | --- | --- |
| `runtime.subscription.node_id_duplicate` | Error | 本地配置、已有运行请求节点、同一 catalog 或多个 catalog 之间出现重复 node id |
| `runtime.subscription.catalog_empty` | Warning | 订阅 catalog 没有可运行 node；是否阻断由启动配置图决定 |
| `runtime.subscription.rules_deferred` | Info | subscription rules 已解析但策略路由接入前不参与运行 |
| `runtime.subscription.catalog_ready` | Info | 订阅 catalog nodes 已准备进入 `RuntimeConfigRequest.nodes` |
| `runtime.subscription.source_unsupported` | Error | 当前运行层拒绝远程或文件订阅 source |

如果 runtime gate 漏掉重复 id，`engine-native` 仍会用
`engine.native.config.node_id_duplicate` 作为 adapter 侧最后防线；但 P3 订阅接入源码应优先在运行层返回
`runtime.subscription.node_id_duplicate`，以便上层知道冲突来自 catalog merge。

当前 runtime gate 不单独输出 secret redaction 诊断；secret 边界通过在
`runtime.subscription.source_unsupported`、parse/fetch error 和 catalog diagnostics 中不包含完整 source
location、payload、URL token、文件路径或 credential 来实现。

## 诊断和 secret 边界

订阅相关诊断必须满足：

- 不输出完整 subscription URL、query token、Authorization header、password、private key 或 payload 原文。
- source id 可以输出，但必须先 trim 且不能为空。
- 对 `inline:` payload 的解析失败只输出稳定 code 和通用 message。
- 对 unsupported remote/file source 只输出 source kind 或 location scheme，不输出完整 location。
- 诊断聚合顺序应保持：platform diagnostics、configuration diagnostics、subscription diagnostics、engine validation diagnostics、engine runtime diagnostics。

## 与策略路由和 DNS 的边界

P3 subscription catalog 接入只解决 outbound node catalog。策略路由和 DNS 仍保持后续增量：

- `NodeCatalog.rules` 不写入 `ConfigSnapshot.policies`。
- subscription rule 与本地 rule 的冲突策略必须等 policy routing design 决定。
- DNS upstream、DNS cache、system resolver mutation 和 domain policy 仍不由 subscription catalog gate 执行。
- 如果 subscription node endpoint 需要本地 DNS 解析，是否阻断由后续 DNS policy design 和 engine-native DNS plan 决定。

## 首个源码增量验收条件

当前源码实现订阅 catalog runtime gate 已按以下条件验收：

- `control-runtime` 新增纯用例或 request helper，组合 `SubscriptionService`、`ConfigurationService`、`PlatformCapabilityService` 和 `ProxyEngineService` 时仍不依赖 adapter crate。
- 覆盖 inline subscription nodes 进入 `RuntimeConfigRequest.nodes` 的成功路径。
- 覆盖本地 config node 与 subscription node 重复 id 的 `runtime.subscription.node_id_duplicate` 拒绝路径。
- 覆盖 subscription rules deferred 诊断，证明策略路由接入前不修改 `ConfigSnapshot.policies`。
- 覆盖 unsupported remote/file subscription source 不泄漏 secret 的拒绝路径。
- `networkcore-linux start` 在未显式提供 subscription source 前继续只使用本地配置，不扫描默认订阅路径。
- README、TODO、CHANGELOG、架构文档和 CI governance 同步更新。
- 所有 format、lint、test、build 和安全扫描仍只通过 GitHub Actions 验证。

## 当前阶段结论

P3 baseline 已完成 subscription catalog runtime orchestration design 和 `control-runtime` 源码 gate。`RuntimeOrchestrator` 现在可通过显式 `SubscriptionService`/`SubscriptionSource` 把 inline `NodeCatalog.nodes` 接入 `RuntimeConfigRequest.nodes`，并在进入 engine-native 现有 `ProxyEngineConfig.nodes` 消费路径前拒绝重复 id、保留 rules deferred 诊断。当前 P4 阶段仍未让 `networkcore-linux start` 暴露 subscription source，也不会扫描默认订阅路径；当前 CLI 边界是 no default subscription path。远程/文件订阅、系统 DNS/TUN mutation、daemon/control socket 和 release artifact 继续 blocked。
