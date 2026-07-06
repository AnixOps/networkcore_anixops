# Control Kernel Interface Draft

本草案把 [Control Kernel Domain Specification](control-kernel-domain.md) 中的领域上下文收敛为后续 Rust 源码骨架可实现的首批接口。接口名称是稳定意图，不是最终 Rust API 承诺；源码落地时可以调整命名，但必须保持依赖方向、输入输出和错误边界一致。

## 设计约束

- 领域接口只描述能力，不直接绑定文件系统、网络、平台代理进程、UI 或 GitHub Actions runner。
- 所有外部系统通过端口接入，适配器不得反向污染领域模型。
- 每个接口必须有明确输入、输出、错误和审计边界。
- 平台不可用、权限不足、配置不合法、远程内容不可信必须作为一等错误处理。
- MITM、脚本和远程规则相关接口必须为权限声明、拒绝路径和审计事件预留空间。

## 共享类型草案

| 类型 | 责任 | 关键字段 |
| --- | --- | --- |
| `ConfigSnapshot` | 标准化后的只读配置快照 | `version`、`profiles`、`policies`、`dns`、`plugins` |
| `Diagnostic` | 可展示和可记录的诊断信息 | `severity`、`code`、`message`、`source` |
| `NodeDescriptor` | 订阅或本地配置归一化后的代理节点 | `id`、`name`、`protocol`、`endpoint`、`tags` |
| `RuleSet` | 策略路由规则集合 | `id`、`rules`、`default_policy` |
| `RouteContext` | 策略路由输入上下文 | `network`、`source`、`destination`、`metadata` |
| `RouteDecision` | 策略路由结果 | `action`、`node_id`、`reason`、`diagnostics` |
| `DnsQuery` | DNS 策略输入 | `name`、`record_type`、`client_context` |
| `DnsDecision` | DNS 策略结果 | `upstream`、`strategy`、`cache_policy`、`diagnostics` |
| `PluginManifest` | MITM 插件声明 | `id`、`version`、`permissions`、`hooks` |
| `AuditEvent` | 安全敏感操作审计事件 | `time`、`actor`、`action`、`decision`、`reason` |

## 配置模型接口

`ConfigurationService` 负责把多个配置来源合并为标准化快照。

输入：

- 原始配置文档或配置片段。
- 平台能力快照。
- 当前 schema 版本。

输出：

- `ConfigSnapshot`
- `Diagnostic` 列表

错误边界：

- schema 不兼容。
- 必填字段缺失或类型错误。
- 平台不支持某项能力。
- 引用不存在的节点、策略、DNS 上游或插件。

最小操作：

- `validate(raw_config, capabilities) -> diagnostics`
- `normalize(raw_config, capabilities) -> config_snapshot`
- `migrate(raw_config, from_version, to_version) -> migrated_config`

## 订阅解析接口

`SubscriptionService` 负责拉取、解析、去重和归一化外部订阅内容。

输入：

- 订阅来源描述。
- 原始订阅内容。
- 解析策略和可信度限制。

输出：

- `NodeDescriptor` 列表。
- `RuleSet` 候选项。
- 解析诊断和安全警告。

错误边界：

- 来源不可达或内容为空。
- 格式不支持或部分节点不可解析。
- 重复节点、冲突标识或不可信字段。
- 超出大小、数量或时间限制。

最小操作：

- `fetch(source) -> raw_subscription`
- `parse(raw_subscription) -> subscription_document`
- `normalize(subscription_document) -> node_catalog`

## 策略路由接口

`PolicyRoutingService` 负责根据规则、上下文和运行状态输出路由决策。

输入：

- `RouteContext`
- `RuleSet`
- 节点健康状态。
- 平台能力和用户配置。

输出：

- `RouteDecision`
- 决策诊断。

错误边界：

- 规则引用不存在。
- 规则循环或优先级冲突。
- 目标节点不可用。
- 平台能力不足导致策略无法执行。

最小操作：

- `compile(rule_set) -> compiled_rules`
- `decide(route_context, compiled_rules, runtime_state) -> route_decision`
- `explain(route_decision) -> diagnostics`

## DNS 策略接口

`DnsPolicyService` 负责选择 DNS 上游、缓存策略和解析路径。

输入：

- `DnsQuery`
- DNS 策略配置。
- 路由上下文。
- 缓存状态。

输出：

- `DnsDecision`
- 缓存更新建议。

错误边界：

- 域名或记录类型不合法。
- 上游不可用。
- 策略与平台 DNS 能力冲突。
- 缓存污染或过期。

最小操作：

- `plan(dns_query, config, route_context) -> dns_decision`
- `cache_lookup(dns_query) -> cached_result`
- `cache_update(dns_query, result, policy) -> cache_event`

## MITM 插件接口

`MitmPluginService` 负责管理受控插件生命周期、权限和 HTTP 事件处理。

输入：

- `PluginManifest`
- 插件包内容。
- 用户授权状态。
- HTTP 请求或响应事件。

输出：

- 插件加载结果。
- 请求/响应改写结果。
- `AuditEvent` 列表。

错误边界：

- 插件 manifest 不合法。
- 权限未授权或超出平台限制。
- 脚本执行超时、异常或资源超限。
- 插件尝试访问未声明能力。

最小操作：

- `validate_manifest(plugin_manifest) -> diagnostics`
- `load(plugin_package, granted_permissions) -> plugin_instance`
- `handle_http_event(plugin_instance, http_event) -> plugin_result`
- `audit(plugin_result) -> audit_events`

## 控制 API 接口

`ControlApiService` 负责向客户端暴露状态查询和受控操作，不直接承载平台实现。

输入：

- 控制命令。
- 查询请求。
- 调用者身份和权限上下文。

输出：

- 状态快照。
- 操作结果。
- 诊断和审计事件。

错误边界：

- 未授权命令。
- 请求参数不合法。
- 操作与当前生命周期状态冲突。
- 平台或运行时适配器返回不可恢复错误。

最小操作：

- `status(query) -> status_snapshot`
- `apply_config(config_snapshot) -> operation_result`
- `reload(scope) -> operation_result`
- `stop(scope) -> operation_result`
- `diagnostics(scope) -> diagnostics`

## 后续源码映射

首个 Rust 骨架应至少提供：

- 共享类型模块。
- 上述服务的 trait 或等价接口定义。
- 不依赖外部系统的占位实现或测试替身。
- GitHub Actions 中 Rust format、lint、test、build 全部通过。
