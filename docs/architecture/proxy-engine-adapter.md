# Proxy Engine Adapter Interface

本文件定义可插拔代理执行内核的适配边界。目标是让统一控制内核通过稳定端口编排自研执行内核，以及后续可能接入的 `sing-box`、`xray-core`、`mihomo` 等外部执行内核，而不把具体进程模型、配置格式或平台 SDK 泄漏到领域层。

## 目标

- 保持代理执行内核可替换，避免控制内核绑定单一实现。
- 将运行时生命周期、配置校验、热重载、状态查询和事件观测收敛为统一端口。
- 明确外部执行内核只是 adapter，不是领域模型依赖。
- 为 iOS 可嵌入运行形态保留无外部进程的实现路径。

## 非目标

- 不在本阶段实现任何真实代理协议。
- 不启动、管理或打包 `sing-box`、`xray-core`、`mihomo` 二进制。
- 不定义外部内核的原生配置文件格式。
- 不绕过平台权限、Network Extension、签名或 App Review 约束。

## 领域端口

`ProxyEngineService` 是控制内核面向执行内核适配器的领域端口。

最小操作：

- `list_engines() -> engine_descriptors`
- `validate_config(engine_config) -> diagnostics`
- `start(engine_config) -> engine_status`
- `reload(engine_config) -> engine_status`
- `stop(engine_id) -> engine_status`
- `status(engine_id) -> engine_status`
- `events(engine_id) -> engine_events`

领域层只依赖这些输入输出，不依赖外部进程、socket、文件路径、平台代理 API 或内核私有 schema。

## 共享类型

| 类型 | 责任 |
| --- | --- |
| `ProxyEngineKind` | 标识自研、`sing-box`、`xray-core`、`mihomo` 或其他执行内核类型 |
| `ProxyEngineCapability` | 描述 TUN、TCP、UDP、DNS、MITM、热重载、健康检查等能力 |
| `ProxyEngineDescriptor` | 描述一个可用执行内核及其能力 |
| `ProxyEngineConfig` | 承载标准化配置快照、节点目录和适配器元数据 |
| `ProxyEngineStatus` | 描述执行内核当前生命周期状态 |
| `ProxyEngineEvent` | 记录启动、重载、停止、健康变化或失败事件 |

## 适配器规则

- 自研执行内核可以直接消费领域模型，但仍必须通过 `ProxyEngineService` 暴露生命周期。
- 外部内核 adapter 负责把 `ConfigSnapshot`、`NodeDescriptor` 和策略结果转换为外部内核原生配置。
- adapter 必须返回领域诊断，而不是把外部错误原样泄漏给上层。
- adapter 不得在领域 crate 中引入外部内核依赖。
- adapter 不得假设一定存在可执行进程；iOS 路径必须允许嵌入式库或 Extension 内运行。

## 生命周期状态

| 状态 | 含义 |
| --- | --- |
| `Stopped` | 引擎未运行 |
| `Starting` | 引擎正在启动 |
| `Running` | 引擎可接受配置和流量 |
| `Reloading` | 引擎正在热重载 |
| `Stopping` | 引擎正在停止 |
| `Failed` | 引擎进入不可恢复或需人工诊断状态 |

## 后续实现要求

- 先在 `control-domain` 中维护纯领域类型和 trait。
- 真实 adapter 必须放在 `engine-*` crate 中；当前 `engine-native` 首批源码提供配置拒绝、listener/node/route 图校验、native runtime handle 源码合同、真实 loopback TCP listener 绑定/释放和生命周期诊断合同，配置图到 runtime assembly、accept loop 与 outbound 数据面进入前必须遵守 [Native Engine Listener And Node Config Design](native-engine-listener-node-config.md)，`networkcore-linux start` 接线仍必须遵守 [Linux Native Proxy Engine Start Design](linux-native-proxy-engine-start.md)。
- 每个 adapter 必须有测试替身或集成测试覆盖配置校验、生命周期和错误路径。
- GitHub Actions 必须继续执行 Rust format、lint、test、build。
