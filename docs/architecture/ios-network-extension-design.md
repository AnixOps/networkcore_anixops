# iOS Network Extension Design

本文件定义 iOS 客户端接入 Network Extension 前必须稳定存在的设计边界。它承接
[iOS Platform Risk Assessment](ios-platform-risk-assessment.md)、
[Control Runtime Orchestration Design](control-runtime-orchestration.md) 和
[Release Strategy](../release-strategy.md)，用于约束后续 Swift、Xcode project、
Rust 嵌入式内核和发布 workflow 的形态。

当前状态：design-only。仓库尚未包含 Swift package、Xcode project、iOS target、
entitlement、Provisioning Profile、签名凭据或 App Store Connect 配置。本地环境不运行
`xcodebuild`、`swift build`、`swift test` 或任何 iOS 构建、测试、打包、签名验证；这些验证只能进入
GitHub Actions 或 Apple 官方平台。

## 目标

- 固定 iOS 首版的 Network Extension 拓扑、配置下发和生命周期边界。
- 保持领域层只依赖 `PlatformCapabilityService`、`PlatformCapabilities`、
  `MitmCertificateStatus`、诊断和审计事件，不依赖 Apple SDK。
- 定义 MITM、证书信任、插件脚本和 App Review 风险的拒绝路径。
- 为后续 `platform-ios` adapter、Swift/iOS target 和 GitHub Actions macOS 验证提供入口。

## 非目标

- 不实现 Swift、Xcode project、Rust FFI、Packet Tunnel Provider 源码或 UI。
- 不申请 Apple Developer Program、Network Extension entitlement、证书或 Provisioning Profile。
- 不定义真实 TestFlight、App Store、签名、notarization 或 release asset 发布流程。
- 不绕过 iOS 系统授权、证书信任、App Review 或地区 VPN 合规要求。

## Provider Topology

iOS 首版采用 Apple Network Extension 的 Packet Tunnel Provider 形态：

- Containing App 负责账号、配置导入、订阅管理、用户授权、状态展示和控制入口。
- Containing App 使用 `NETunnelProviderManager` 创建、保存、启用和停止 VPN 配置。
- Network Extension 使用 `NEPacketTunnelProvider` 作为 `Packet Tunnel Provider`，承载实际 tunnel lifecycle 和流量入口。
- Extension 通过 Apple 允许的 App Group 或 Keychain sharing 读取最小配置快照和必要凭据。
- 代理执行内核必须嵌入 Extension 进程内运行，不能假设 iOS 上存在外部 daemon、CLI 或长期后台进程。
- Rust core 后续只能以静态库、XCFramework 或 Apple 允许的等价嵌入形式进入 Extension；该嵌入形态必须先有单独设计和 GitHub Actions 验证。

领域层不得出现 `NetworkExtension` framework 类型。后续 `platform-ios` 或 Swift adapter 负责把 Apple SDK 状态映射成领域状态。

## Configuration Handoff

配置下发必须采用单向、可审计、可回滚的数据流：

1. Containing App 导入或生成用户配置、订阅和策略。
2. 配置先经过 `ConfigurationService` 标准化，得到领域 `ConfigSnapshot`。
3. iOS adapter 将 `ConfigSnapshot` 转换成 iOS tunnel profile，只保留 Extension 启动所需字段。
4. Containing App 通过 `NETunnelProviderManager` 写入 provider configuration，并记录配置 schema version、profile id、content hash 和创建时间。
5. Extension 启动后重新校验 schema version、profile id 和必需字段，未知 schema 必须拒绝启动。
6. Extension 只读取当前 active profile；reload 失败时必须保留 last-known-good profile，不得静默切换到未校验配置。

配置边界：

- Provider configuration 不写入原始订阅 secret、账号 token、私钥或用户明文凭据。
- 必须使用 Keychain 或 Apple 允许的共享凭据机制保存 secret；App Group 文件只能保存可审计的最小快照。
- 诊断、崩溃日志和 GitHub Actions artifact 不得包含 secret、完整订阅 URL、证书私钥或用户流量内容。
- 配置删除必须清理 active profile、last-known-good profile 指针和相关 Keychain 引用。

## Lifecycle

iOS tunnel lifecycle 必须显式建模为可重入流程：

| 阶段 | 责任 | 失败边界 |
| --- | --- | --- |
| Install configuration | Containing App 使用 `NETunnelProviderManager` 保存配置 | entitlement、系统授权或 Provisioning Profile 不满足 |
| Start tunnel | 用户或系统触发 VPN 启动 | 配置缺失、schema 不兼容、用户撤销授权 |
| `NEPacketTunnelProvider.startTunnel` | Extension 读取配置、设置 tunnel network settings、启动嵌入式 runtime | tunnel settings 拒绝、runtime 配置拒绝、资源不足 |
| Running | Extension 持有 tunnel 与 embedded runtime | 系统回收、网络变化、配置 reload 失败 |
| Stop tunnel | 用户、系统或 Containing App 请求停止 | stop 超时、runtime release 失败、状态回写失败 |
| Recover | Containing App 读取状态和诊断，允许用户重试或回滚配置 | 无 last-known-good profile、授权已撤销 |

Extension 必须假设系统可随时终止进程。`startTunnel`、`stopTunnel`、配置 reload 和状态回写都必须幂等；重复调用不得泄露资源或改变未经确认的配置。

## Capability Mapping

`platform-ios` adapter 后续必须实现 `PlatformCapabilityService`，并把 iOS 状态映射到领域能力：

| 领域字段 | iOS 来源 | 映射规则 |
| --- | --- | --- |
| `PlatformCapabilities.os` | build target 或 adapter target | 固定为 `OperatingSystem::Ios` |
| `supports_tunnel` | Network Extension entitlement、saved VPN configuration、用户授权 | `NEPacketTunnelProvider` 可用且配置已保存时才可用 |
| `supports_embedded_runtime` | Extension 内可加载的 embedded runtime | 不能加载或需要外部进程时必须拒绝 |
| `supports_mitm` | 用户配置、证书状态、平台策略 | MITM 默认不可用，只有显式授权和证书 trusted 时可用 |
| `remote_script_execution` | App policy 和 App Review 风险策略 | iOS 首版固定为 unavailable |
| `mitm_certificate` | 证书安装、信任和撤销探测 | 映射为 `MitmCertificateStatus` |

后续 adapter 诊断应使用稳定 source，例如 `platform.ios.network_extension`、
`platform.ios.vpn_configuration`、`platform.ios.embedded_runtime`、
`platform.ios.remote_script_execution` 和 `platform.ios.mitm_certificate`。

## MITM Certificate Boundary

iOS MITM 默认关闭，且只能在用户明确启用后进入检查路径：

- CA 证书安装必须由用户发起，界面需要说明用途、影响范围和撤销方式。
- 安装 profile 不等于 SSL/TLS 完全信任；adapter 必须区分 `NotInstalled`、`InstalledUntrusted`、`Trusted`、`Revoked` 和 `Unknown`。
- `MitmCertificateStatus` 必须携带可安全展示的 subject、fingerprint 和诊断，不携带私钥或完整证书秘密材料。
- 对证书固定、公钥固定、系统拒绝信任或应用沙箱不允许读取的连接，不提供绕过路径。
- 证书撤销或信任状态未知时，`mitm_gate` 必须拒绝插件执行，并保留平台诊断和审计事件。
- MITM 只允许按用户选择、域名、规则集和插件权限最小化启用。

证书生成、安装、信任检测和撤销检测需要单独设计；在该设计完成前，不得加入 iOS MITM 源码路径。

## Plugin And Script Boundary

iOS 上的插件能力必须拆分为数据和执行：

- 远程规则、节点、策略、插件清单和版本索引可以作为数据下载、校验、缓存和回滚。
- 会改变功能的脚本执行路径在 iOS 首版不可用；`remote_script_execution` 必须报告 unavailable。
- 初始可执行插件只能是随 App 审核提交的内置能力或 Apple 允许的静态资源驱动逻辑。
- 远程插件包在 iOS 首版只能参与 manifest validation、权限声明和拒绝原因展示，不执行任意远程源码。
- 每个插件必须声明 hook、读取/改写权限、网络访问、持久化、证书依赖、资源限制和审计策略。

运行层已经通过 `MitmGateOrchestrator` 在插件端口前检查平台 MITM、证书状态、权限和远程脚本状态。iOS adapter 不得绕过该 gate。

## App Review And Privacy

进入 iOS 源码或 TestFlight/App Store 发布前，必须准备以下人工和文档材料：

- Apple Developer Program 组织账号和具备 Network Extension 能力的 App ID。
- 主 App、Network Extension target、Bundle ID、entitlement 和 Provisioning Profile 策略。
- VPN 数据处理说明、隐私政策、App Privacy 数据类型、日志保留策略和第三方共享说明。
- App Review Notes，说明 `Packet Tunnel Provider` 用途、默认本地处理策略、MITM 默认关闭、证书安装和撤销路径、测试账号或 demo mode。
- 目标销售地区的 VPN 合规材料；不能确认的地区默认不发布。
- GitHub Secrets 或 Apple 官方凭据存储策略，仓库不得提交证书、私钥、Provisioning Profile 或 App Store Connect API key。

这些事项属于 `docs/manual-intervention.md` 管理的人工介入边界。未完成前，CI 可以做静态检查，但不得启用真实签名、上传 TestFlight 或创建 iOS release asset。

## GitHub Actions Validation Entry

当前可验证入口是 `.github/workflows/ci.yml` 的 Repository policy 静态检查：

- 检查本文件存在。
- 检查 `NEPacketTunnelProvider`、`NETunnelProviderManager`、`Packet Tunnel Provider`、`App Group`、`PlatformCapabilityService`、`MitmCertificateStatus`、`App Review`、`GitHub Actions` 和 `macos-26` 等设计锚点。
- 不运行本地构建、测试、签名、打包或发布验证。

后续出现 Swift、Xcode project 或 iOS target 时，验证必须只在 GitHub Actions 中运行：

- Swift package 使用 `swift test` 和 `swift build`，只在 GitHub Actions 中执行。
- Xcode project 或 workspace 使用 `xcodebuild`，只在 GitHub Actions 的 `macos-26` runner 中执行。
- 需要签名的验证必须从 GitHub Secrets 或 Apple 官方平台读取凭据，且不得把签名产物、profile、私钥或 API key 写入仓库。
- iOS signing、TestFlight、App Store Connect upload 和 App Review 状态读取必须先有独立 workflow design 和 manual-intervention 记录。

如果 `macos-26` runner 或 Apple toolchain 暂不可用，只能在 GitHub Actions 日志中记录原因后调整 runner；本地仍不得运行替代构建或测试。

## Release Boundary

iOS release workflow 在满足以下条件前不得定义真实 artifact、TestFlight upload 或 App Store upload job：

- 本设计和 iOS Platform Risk Assessment 已纳入 CI governance。
- `platform-ios` adapter source contract 已定义，并能映射 `PlatformCapabilityService`、`PlatformCapabilities` 和 `MitmCertificateStatus`。
- Swift/Xcode project 已通过 GitHub Actions 的 macOS runner 验证。
- Apple Developer、Network Extension entitlement、Provisioning Profile、GitHub Secrets、隐私政策和 App Review Notes 已完成人工确认。
- MITM 证书设计、插件执行边界和地区 VPN 合规材料已完成。

Linux artifact 发布继续受 license/NOTICE confirmed marker、`package-linux` preflight 和后续 artifact gates 阻断；本设计不得被解释为允许发布 Linux 或 iOS release asset。

## Acceptance Criteria

本设计增量完成时必须满足：

- README、ROADMAP、TODO、CHANGELOG 和 CI/CD policy 链接或记录本文件。
- `.github/workflows/ci.yml` 静态检查本文件存在和关键锚点。
- `docs/architecture/ios-platform-risk-assessment.md` 的后续工作指向下一步 iOS adapter source contract。
- `docs/manual-intervention.md` 保留 Apple Developer、entitlement、Provisioning Profile、GitHub Secrets、App Review 和 VPN 合规人工事项。
- 本地只执行静态文本检查和 git 操作；所有正式验证通过 GitHub Actions 完成。

## References

- Apple Developer Documentation: Network Extension, `https://developer.apple.com/documentation/networkextension`
- Apple Developer Documentation: Packet Tunnel Provider, `https://developer.apple.com/documentation/networkextension/packet-tunnel-provider`
- Apple Developer Documentation: `NEPacketTunnelProvider`, `https://developer.apple.com/documentation/networkextension/nepackettunnelprovider`
- Apple Developer Documentation: `NETunnelProviderManager`, `https://developer.apple.com/documentation/networkextension/netunnelprovidermanager`
- Apple App Review Guidelines, `https://developer.apple.com/app-store/review/guidelines/`
- Apple Support: Trust manually installed certificate profiles in iOS, iPadOS, and visionOS, `https://support.apple.com/en-us/102390`
- Apple Developer Account Help: Provisioning with capabilities, `https://developer.apple.com/help/account/reference/provisioning-with-managed-capabilities/`
