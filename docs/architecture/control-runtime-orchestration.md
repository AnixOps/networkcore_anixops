# Control Runtime Orchestration Design

本文件定义后续创建 `control-runtime` crate 前必须遵守的运行层编排边界。它承接
[Control Kernel Domain Specification](control-kernel-domain.md)、
[Control Kernel Interface Draft](control-kernel-interfaces.md) 和
[Proxy Engine Adapter Interface](proxy-engine-adapter.md)，用于约束运行层如何组合领域端口，而不引入平台代理、外部进程、UI 或传输实现。

## 目标

- 定义 `control-runtime` 在统一控制内核中的职责、生命周期和依赖方向。
- 让运行层只编排 `control-domain` 中的纯领域类型与端口 trait。
- 为配置加载、平台能力检查、代理引擎启动、热重载、停止、状态查询和诊断输出建立首批用例边界。
- 为 iOS 嵌入式运行时、MITM 证书信任和远程脚本禁用路径保留显式拒绝逻辑。

## 非目标

- 不实现真实代理协议、DNS 解析、MITM 脚本执行或订阅拉取。
- 不选择 async runtime、HTTP 框架、进程管理库、平台 SDK 或客户端 UI。
- 不启动、打包或管理 `sing-box`、`xray-core`、`mihomo` 等外部二进制。
- 不定义 release artifact、安装器、签名、证书或 App Store Connect 流程。

## 架构位置

`control-runtime` 是应用用例层，不是领域层，也不是平台适配器层。

依赖方向必须保持：

1. `control-domain` 定义领域类型、错误、诊断和端口 trait。
2. `control-runtime` 依赖 `control-domain`，负责把多个领域端口组合成可调用用例。
3. `platform-*`、`engine-*`、`control-api-*` 等后续 adapter 依赖 `control-runtime` 或 `control-domain`，并提供具体端口实现。
4. `control-runtime` 不反向依赖任何 adapter crate。

首个 `control-runtime` crate 应保持 library-only、dependency-light，并优先使用测试替身验证编排顺序和错误传播。

## 运行层职责

运行层负责回答一个问题：在给定配置、平台能力和端口实现的情况下，控制内核应该怎样安全进入、更新或退出运行状态。

首批职责：

- 配置入口：调用 `ConfigurationService` 完成校验、迁移和标准化。
- 平台门禁：调用 `PlatformCapabilityService` 获取隧道、MITM、嵌入式运行时、远程脚本和证书信任状态。
- 引擎编排：调用 `ProxyEngineService` 完成配置校验、启动、热重载、停止、状态查询和事件读取。
- 订阅入口：为后续 `SubscriptionService` 的拉取、解析和归一化预留用例。
- 策略和 DNS：为后续 `PolicyRoutingService`、`DnsPolicyService` 与运行状态组合预留编排点。
- MITM 插件门禁：在调用 `MitmPluginService` 前检查平台 MITM 能力、证书信任和插件权限状态。
- 诊断聚合：把配置、平台、引擎和插件返回的 `Diagnostic` 合并为可展示的运行状态。

运行层不得承担：

- 文件系统读写、网络请求、进程启动、系统代理配置或平台权限探测。
- 外部引擎原生配置格式转换。
- UI 文案、HTTP/gRPC/socket 传输细节或 GitHub Actions runner 行为。
- 绕过平台拒绝原因的 fallback。

## 首批用例

| 用例 | 输入端口 | 输出 | 失败边界 |
| --- | --- | --- | --- |
| `prepare_config` | `ConfigurationService`、`PlatformCapabilityService` | 标准化 `ConfigSnapshot`、诊断 | 配置非法、平台能力不足、schema 不兼容 |
| `start_runtime` | `PlatformCapabilityService`、`ProxyEngineService` | `ProxyEngineStatus`、诊断 | 隧道不可用、嵌入式运行时不可用、引擎配置拒绝、启动失败 |
| `reload_runtime` | `PlatformCapabilityService`、`ProxyEngineService` | `ProxyEngineStatus`、诊断 | 当前状态不允许重载、配置拒绝、引擎重载失败 |
| `stop_runtime` | `ProxyEngineService` | `ProxyEngineStatus`、诊断 | 引擎不存在、停止失败 |
| `runtime_status` | `PlatformCapabilityService`、`ProxyEngineService` | 平台状态、引擎状态、诊断 | 平台状态不可读取、引擎状态不可读取 |
| `runtime_events` | `ProxyEngineService` | `ProxyEngineEvent` 列表 | 引擎事件不可读取 |
| `mitm_gate` | `PlatformCapabilityService`、`MitmPluginService` | 允许或拒绝原因、审计事件 | MITM 不可用、证书未信任、权限未授权、脚本被平台禁用 |

这些名称是用例意图，不是最终 Rust API 承诺。源码落地时可以调整命名，但必须保持输入、输出和拒绝边界一致。

## 生命周期

运行层应把代理执行内核生命周期视为领域状态，而不是进程状态。

| 状态 | 含义 | 允许的下一步 |
| --- | --- | --- |
| `Stopped` | 未运行，允许准备配置或启动 | `prepare_config`、`start_runtime` |
| `Starting` | 已请求启动，等待 adapter 返回状态 | `runtime_status`、`runtime_events` |
| `Running` | 引擎可处理配置和流量 | `reload_runtime`、`stop_runtime`、`runtime_status` |
| `Reloading` | 已请求热重载 | `runtime_status`、`runtime_events` |
| `Stopping` | 已请求停止 | `runtime_status`、`runtime_events` |
| `Failed` | adapter 返回不可恢复错误或关键门禁失败 | `runtime_status`、`runtime_events`、`stop_runtime` |

`control-runtime` 不应假设所有 adapter 都有真实进程。iOS、嵌入式库和测试替身必须能通过同一生命周期表达运行状态。

## 编排数据流

1. 调用平台能力端口，得到 `PlatformCapabilityStatus`。
2. 使用平台能力校验和标准化配置，得到 `ConfigSnapshot` 与诊断。
3. 在启动或重载前调用引擎配置校验，合并引擎诊断。
4. 当平台能力和配置均允许时，调用引擎启动或重载。
5. 将引擎状态、平台能力、诊断和后续事件组合为运行状态快照。
6. 当 MITM 插件用例被调用时，先检查 `mitm_available()` 和插件权限，再调用插件端口。

任一阶段出现 `DomainError` 时，运行层应保留错误 code、message 和已收集诊断，不把 adapter 私有错误类型暴露给上层。

## iOS 运行边界

iOS adapter 接入前，运行层必须按以下规则建模：

- 如果 `tunnel` 不可用，`start_runtime` 必须拒绝启动隧道相关能力。
- 如果 `embedded_runtime` 不可用，iOS 不得 fallback 到外部进程模型。
- 如果 `remote_script_execution` 不可用，运行层不得调用会执行远程脚本源码的插件路径。
- 如果 `mitm_certificate` 未达到 `Trusted`，MITM 相关用例必须返回拒绝原因。
- MITM 默认关闭；只有平台能力、证书信任、配置和插件权限同时允许时才进入插件执行路径。

## 错误、诊断和审计

- 编排失败使用 `DomainError` 表示不可继续的错误。
- 可恢复或可展示的问题使用 `Diagnostic` 聚合。
- 安全敏感路径必须保留 `AuditEvent`，尤其是 MITM、插件权限、远程内容和用户可触发操作。
- 运行层不得吞掉 adapter 诊断；必要时可以补充更稳定的领域 code。
- 上层控制 API 应能区分配置拒绝、平台拒绝、权限拒绝、引擎失败和未知状态。

## 首个源码增量验收条件

创建 `control-runtime` crate 时必须满足：

- workspace 新增 `crates/control-runtime`，只依赖 `control-domain` 和必要的标准库能力。
- 不引入平台代理 SDK、外部代理内核、网络框架、文件系统配置读写或 UI 依赖。
- 提供最小运行层用例类型或 service，用测试替身组合 `ConfigurationService`、`PlatformCapabilityService` 和 `ProxyEngineService`。
- 覆盖至少一个成功启动路径、一个平台能力拒绝路径和一个引擎错误传播路径。
- README、TODO、CHANGELOG 和相关架构文档同步更新。
- 所有 format、lint、test、build 和安全扫描仍只通过 GitHub Actions 验证。

## 当前源码映射

当前 `crates/control-runtime` 提供最小 `RuntimeOrchestrator`，组合
`ConfigurationService`、`PlatformCapabilityService` 和 `ProxyEngineService`，
覆盖配置准备、启动、重载、停止、状态查询和事件读取；同时提供最小
`MitmGateOrchestrator`，组合 `PlatformCapabilityService` 和
`MitmPluginService`，覆盖平台 MITM 可用性、证书状态拒绝矩阵、远程脚本禁用、
manifest 诊断拒绝、插件权限门禁、审计事件聚合和插件端口错误传播。
订阅、策略路由和 DNS 编排仍按后续扩展逐步加入。

## 后续扩展

- 引入订阅、策略路由和 DNS 编排前，先补齐对应用例测试替身。
- 引入 MITM 插件运行路径前，先补齐权限模型、审计事件和 iOS 拒绝路径测试。
- 引入真实 adapter 前，为每个 adapter 单独建立设计文档、错误映射和 GitHub Actions 验证策略。
