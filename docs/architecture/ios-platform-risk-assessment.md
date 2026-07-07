# iOS Platform Risk Assessment

本文件记录 iOS 客户端和 Network Extension 落地前的首版风险评估。它约束后续 iOS 代码、发布流程和插件能力设计，避免在源码阶段才发现 App Review、证书安装或权限模型不可接受。

评估时间：2026-07-06。

## 范围

本评估覆盖：

- iOS Network Extension 与 VPN 隧道形态。
- MITM CA 证书安装与信任边界。
- 远程插件、脚本和规则的权限模型。
- App Review、隐私披露、账号和签名发布风险。

本评估不覆盖：

- 具体 Swift、Xcode project 或 iOS UI 实现。
- 真实代理协议、加密协议或流量转发实现。
- 法律意见或特定国家/地区的 VPN 牌照判断。

## 结论

iOS 首版必须采用保守能力集：

- 网络隧道只通过 Apple Network Extension 暴露，优先研究 Packet Tunnel Provider。
- iOS 不能依赖外部代理进程，代理执行内核必须是 Extension 可嵌入形态。
- MITM 默认关闭，只能在用户明确安装并信任 CA 后对用户选定范围生效。
- iOS 首版不支持下载并执行任意远程脚本；远程内容先限制为数据化规则、配置和经过校验的插件清单。
- App Store 版本必须按 VPN App 要求准备组织开发者账号、隐私披露、App Review Notes 和可能的地区牌照材料。

## 风险矩阵

| 领域 | 风险 | 初始等级 | 设计决策 |
| --- | --- | --- | --- |
| Network Extension | 隧道能力依赖 entitlement、App ID、Provisioning Profile 和系统弹窗授权 | 高 | 先把 iOS 视为 platform adapter，不把 Network Extension API 泄漏到领域 crate |
| 执行内核 | iOS Extension 不能假设存在长期运行的外部进程 | 高 | iOS 只接受嵌入式执行内核或 Apple 允许的 Extension 内运行时 |
| 证书安装 | 手动安装的根证书不会自动获得 SSL/TLS 完全信任 | 高 | MITM 状态必须区分未安装、已安装未信任、已信任和已撤销 |
| App Review 5.4 | VPN App 需要使用 Apple VPN API、组织开发者账号、隐私披露和地区合规材料 | 高 | 发布前必须准备组织账号与 App Review Notes 模板 |
| App Review 2.5.2 | 下载并执行会改变功能的代码存在高拒审风险 | 高 | iOS 禁止任意远程脚本执行，插件能力必须可声明、可审计、可拒绝 |
| 隐私与数据 | VPN 能观察敏感网络元数据，数据使用声明不清会阻断审核 | 高 | 默认本地处理，不出售、披露或复用用户流量数据；所有采集必须先显示声明 |
| MDM/配置描述文件 | 如果产品提供 MDM 或 configuration profile 服务，会触发额外审核要求 | 中 | 普通消费版本不提供 MDM 服务；企业部署单独评估 |

## Network Extension 边界

后续 iOS 代码必须满足：

- 使用 `NEPacketTunnelProvider` 或同等 Network Extension Provider 来承载自定义 VPN 隧道。
- 使用 `NETunnelProviderManager` 或 Apple 指定 VPN 管理 API 创建和管理配置。
- 主 App 只负责用户授权、配置、状态展示和控制；实际流量处理在 Extension 中执行。
- 领域层只能看到 `PlatformCapabilities`、配置快照、诊断和审计事件，不能直接依赖 Network Extension framework。
- iOS adapter 必须明确生命周期：配置保存、系统授权、Extension 启动、隧道停止、系统回收和错误恢复。

后续源码验收条件：

- `PlatformCapabilities` 能表达 iOS 隧道、MITM、嵌入式运行时、远程脚本禁用等能力。
- iOS adapter crate 出现前必须有 Network Extension 设计文档和 GitHub Actions macOS 验证策略。
- 任何 iOS 构建、签名、证书、Provisioning Profile 验证只能在 GitHub Actions 或 Apple 官方平台执行。

## MITM 与证书边界

iOS MITM 必须作为显式用户授权能力，而不是默认网络功能：

- CA 安装流程必须由用户发起，并清楚说明用途、影响范围和撤销方式。
- 应用不能假设下载 profile 后即可拦截 TLS；必须检测并展示证书信任状态。
- 对启用证书固定、公钥固定或系统拒绝信任的连接，不提供绕过路径。
- MITM 范围必须最小化，优先按域名、规则集、插件权限和用户选择启用。
- 所有请求/响应读取或改写都必须产生 `AuditEvent`，并能被用户或调试接口查看。

领域模型要求：

- `PlatformCapabilityStatus` 和 `MitmCertificateStatus` 需要报告证书安装、信任状态、MITM 可用性和拒绝原因。
- `MitmPluginService` 后续需要区分读取、改写、网络访问、持久化等权限，并在 iOS 上默认拒绝未授权能力。
- 配置模型必须能表达 MITM 被平台禁止、证书未信任、用户未授权和插件权限不足四类不同诊断。

## 插件和脚本边界

Loon、Quantumult X 类能力在 iOS 上必须拆分为两层：

- 数据层：远程规则、节点、策略和插件清单，可下载、校验、版本化和回滚。
- 执行层：会改变功能或运行脚本的逻辑，iOS 首版不允许从远程任意下载执行。

iOS 插件策略：

- 初始实现只接受内置或随 App 审核提交的插件执行能力。
- 远程插件包在 iOS 上只能先作为声明和数据参与评估，不执行任意脚本源码。
- 后续如引入用户可见、可编辑的脚本能力，必须先单独完成 App Review 风险评审和拒绝路径设计。
- 每个插件必须声明权限、hook、资源限制、网络访问需求和审计策略。

## App Review 和发布门禁

进入 iOS 源码或发布 workflow 前必须完成：

1. 确认 Apple Developer Program 账号类型满足 VPN App 发布要求。
2. 为主 App 和 Network Extension 准备明确 App ID、Bundle ID、entitlement 和 Provisioning Profile 策略。
3. 准备隐私政策，明确 VPN 相关数据是否采集、为何采集、保留多久、是否第三方共享。
4. 准备 App Review Notes，说明 Network Extension 用途、VPN 数据处理、证书安装路径、MITM 默认关闭策略和测试账号或 demo 模式。
5. 确认目标销售地区是否需要 VPN 牌照或额外合规材料；不能确认的地区默认不发布。
6. 在 GitHub Actions 中增加 macOS runner 的 iOS 项目检查后，才能引入 Xcode project 或 Swift package。

## 手工介入边界

以下事项不能由本仓库自动完成，必须在需要时记录到 `docs/manual-intervention.md`：

- Apple Developer Program 组织账号或账号角色确认。
- App ID、Network Extension capability、entitlement 和 Provisioning Profile 配置。
- App Store Connect、TestFlight、App Review Notes 和隐私政策配置。
- 证书、签名密钥和 Apple API 凭据写入 GitHub Secrets。
- 特定国家/地区 VPN 牌照和法律合规确认。

## 后续工作

- 已新增 [iOS Network Extension Design](ios-network-extension-design.md)，后续实现 iOS adapter 前必须补充 `platform-ios` source contract。
- 发布真实平台产物必须遵守 `docs/release-strategy.md` 中的签名、产物矩阵和回滚门禁。
- 后续平台 adapter 必须通过 `PlatformCapabilityService` 提供 iOS 能力和证书信任状态。

## 参考

- Apple Developer Documentation: Network Extension, `https://developer.apple.com/documentation/networkextension`
- Apple Developer Documentation: Packet Tunnel Provider, `https://developer.apple.com/documentation/networkextension/packet-tunnel-provider`
- Apple Developer Documentation: `NEPacketTunnelProvider`, `https://developer.apple.com/documentation/networkextension/nepackettunnelprovider`
- Apple Developer Documentation: `NETunnelProviderManager`, `https://developer.apple.com/documentation/networkextension/netunnelprovidermanager`
- Apple App Review Guidelines, `https://developer.apple.com/app-store/review/guidelines/`
- Apple Support: Trust manually installed certificate profiles in iOS, iPadOS, and visionOS, `https://support.apple.com/en-us/102390`
- Apple Developer Account Help: Provisioning with capabilities, `https://developer.apple.com/help/account/reference/provisioning-with-managed-capabilities/`
