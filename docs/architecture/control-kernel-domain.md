# Control Kernel Domain Specification

本规格定义统一控制内核的首批领域边界。它是后续创建源码骨架前的约束文件，任何实现都必须保持内核领域逻辑独立于平台 UI、具体代理进程、GitHub Actions runner 和外部订阅服务。

## 目标

- 建立可跨 Linux、macOS、Windows、iOS 复用的统一控制内核边界。
- 先定义接口和领域语言，再选择具体源码结构和技术栈。
- 保留本仓库自研执行内核与 `sing-box`、`xray-core`、`mihomo` 适配空间。
- 为 MITM 插件运行时、DNS、策略路由和跨平台控制 API 提供稳定扩展点。

## 非目标

- 不在本规格中承诺具体语言、框架或包管理器。
- 不定义 UI、安装器、发布产物或账号系统。
- 不绕过 iOS Network Extension、证书安装授权、App Review 或 GitHub Actions 的外部约束。

## 架构原则

- Domain First：核心配置、策略、DNS、订阅和插件概念先作为领域模型存在。
- Hexagonal Boundary：领域层只依赖端口接口，不直接依赖平台代理、文件系统、网络、进程或 UI。
- Interface First：新增能力先定义输入、输出、错误和生命周期，再接入具体适配器。
- Replaceable Runtime：代理执行内核、订阅来源、插件引擎和控制 API 都必须可替换。
- CI/CD Verified：任何源码实现只通过 GitHub Actions 验证，本地只做编辑和静态差异检查。

## 领域上下文

| 上下文 | 职责 | 主要输入 | 主要输出 |
| --- | --- | --- | --- |
| Configuration | 管理用户配置、配置片段合并、版本和校验结果 | 本地配置、远程配置片段、平台能力 | 标准化配置快照、诊断 |
| Subscription | 拉取、解析和归一化订阅内容 | URL、文件、外部适配器数据 | 节点目录、策略候选项、解析警告 |
| Policy Routing | 根据规则、用户意图和平台能力选择路径 | 请求元数据、规则集、节点状态 | 路由决策、拒绝原因 |
| DNS Policy | 管理解析策略、缓存和上游选择 | 域名请求、策略上下文、缓存状态 | DNS 决策、缓存更新 |
| Proxy Runtime | 编排自研或外部代理执行内核 | 标准化配置、路由/DNS 决策 | 运行状态、健康事件、错误 |
| MITM Plugin Runtime | 执行受控脚本和请求/响应改写能力 | 插件包、权限声明、HTTP 事件 | 改写结果、审计事件、拒绝原因 |
| Control API | 暴露跨平台控制平面 | 客户端命令、查询请求 | 状态快照、操作结果 |
| Platform Capability | 描述平台能力和限制 | OS、权限、Network Extension 状态 | 能力矩阵、不可用原因 |

## 端口与适配器

领域层应只依赖以下端口，具体实现由适配器提供：

- `ConfigStorePort`：读取、写入和迁移配置。
- `SubscriptionSourcePort`：获取远程或本地订阅内容。
- `ProxyEnginePort`：启动、停止、重载和观测代理执行内核。
- `DnsResolverPort`：执行平台或自定义 DNS 解析。
- `PluginSandboxPort`：加载插件、执行脚本、限制权限并输出审计事件。
- `ControlTransportPort`：暴露本地 socket、HTTP、gRPC 或平台专用控制通道。
- `PlatformCapabilityPort`：查询平台权限、隧道能力和证书状态。

适配器可以依赖平台 SDK、外部代理内核和系统 API，但不得把这些依赖反向泄漏到领域模型。

## 核心数据流

1. Configuration 生成标准化配置快照。
2. Subscription 将外部节点和规则归一化为领域对象。
3. Platform Capability 给出当前平台可用能力。
4. Policy Routing 和 DNS Policy 基于配置、订阅、平台能力和运行状态做决策。
5. Proxy Runtime 把领域决策转换为具体执行内核配置。
6. MITM Plugin Runtime 在权限模型允许时处理 HTTP 事件。
7. Control API 对客户端暴露状态、诊断和可控操作。

## iOS 边界

iOS 实现必须额外满足：

- 网络隧道入口基于 Apple Network Extension。
- 内核以可嵌入库或 Extension 可运行形态集成，不依赖外部进程模型。
- MITM CA 安装必须由用户明确授权。
- 远程插件、脚本和规则必须具备权限声明、拒绝路径和审计事件。
- 证书、Provisioning Profile 和 App Store Connect 验证不写入仓库，只能通过 GitHub Actions、GitHub Secrets 或 Apple 官方平台处理。

## 后续源码骨架验收条件

创建首个源码骨架前必须满足：

- 选定首个实现语言和模块布局，并说明选择理由。
- 为上述每个领域上下文建立最小接口或占位模块。
- 在 GitHub Actions 中启用对应语言的 build、test、lint 或等效检查。
- README、TODO、CHANGELOG 和相关架构文档同步更新。
- 不引入无法通过 CI 验证的本地专用依赖。
