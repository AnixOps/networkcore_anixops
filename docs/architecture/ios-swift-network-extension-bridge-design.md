# iOS Swift Network Extension Bridge Design

本文件定义后续 Apple SDK 层如何把 iOS 运行事实采集为去敏 snapshot，并传入当前
`crates/platform-ios` 的纯 Rust 映射边界。它承接
[iOS Network Extension Design](ios-network-extension-design.md)、
[iOS Platform Adapter Source Contract](ios-platform-adapter-source-contract.md)、
[iOS Swift Xcode Bridge Source Contract](ios-swift-xcode-bridge-source-contract.md)、
[iOS Embedded Runtime FFI Boundary Design](ios-embedded-runtime-ffi-boundary-design.md)、
[iOS MITM Certificate Lifecycle Design](ios-mitm-certificate-lifecycle-design.md) 和
[iOS Platform Risk Assessment](ios-platform-risk-assessment.md)。

当前状态：design-only。仓库仍不包含 Swift package、Xcode project、Network Extension target、
entitlement、Provisioning Profile、签名配置、TestFlight/App Store 上传 job 或 iOS release asset。
本地仍不得运行 `swift build`、`swift test`、`xcodebuild`、签名、打包或发布验证。

## Goals

- 定义 Swift/Apple SDK bridge 的职责、输入事实、输出 snapshot 和错误映射。
- 固定 `NEPacketTunnelProvider`、`NETunnelProviderManager`、App Group、Keychain、embedded runtime
  和 MITM 证书状态如何映射到 `IosPlatformSnapshot`。
- 保持 Apple SDK 类型、Bundle ID、Provisioning Profile、Keychain item、证书内容和用户 secret 不进入
  `control-domain`、`control-runtime` 或 `platform-ios`。
- 为后续 Swift/Xcode 源码和 GitHub Actions `macos-26` 验证入口提供验收锚点。

## Non-Goals

- 不实现 Swift 源码、C ABI、FFI bindings、Xcode project、Packet Tunnel Provider target 或 UI。
- 不申请或配置 Apple Developer Program、App ID、Network Extension entitlement、Provisioning Profile、
  signing certificate、TestFlight、App Store Connect 或 GitHub Secrets。
- 不安装、生成、信任、撤销或读取完整 MITM CA 证书内容。
- 不定义 iOS release workflow、signing job、TestFlight upload、App Store upload 或 iOS release asset。

## Bridge Position

依赖方向必须保持：

1. `control-domain` 只定义领域类型、`PlatformCapabilityService`、诊断和证书状态。
2. `platform-ios` 只接收去敏 `IosPlatformSnapshot`，并把它映射为 `PlatformCapabilityStatus`。
3. Swift bridge 位于 iOS containing app、Network Extension target 或独立 Apple SDK adapter 层。
4. Swift bridge 负责读取 Apple SDK 事实，生成去敏 bridge snapshot，再调用 `platform-ios` 映射边界。
5. `control-runtime` 不直接依赖 Swift、NetworkExtension、Security.framework、Keychain API、UIKit 或 Xcode。

Swift bridge 不得把以下对象传入 Rust 领域层：`NEPacketTunnelProvider`、
`NETunnelProviderManager`、`NETunnelProviderProtocol`、`SecTrust`、`SecCertificate`、Keychain item
reference、App Group file URL、Bundle ID、Team ID、Provisioning Profile UUID、subscription URL、
account token、private key、certificate payload 或用户流量内容。

## Sanitized Snapshot Contract

后续 bridge 应先构造一个 Swift 侧去敏 DTO，再转为 `IosPlatformSnapshot`。该 DTO 只能包含枚举、布尔值、
安全展示元数据和稳定诊断 code。

建议字段：

| 字段 | 来源 | `platform-ios` 映射 |
| --- | --- | --- |
| `network_extension_entitlement` | entitlement/provisioning 可用性事实 | `IosNetworkExtensionEntitlementState` |
| `network_extension_provider` | `NEPacketTunnelProvider` target 可加载事实 | `IosNetworkExtensionProviderState` |
| `vpn_configuration` | `NETunnelProviderManager` saved/enabled/authorization 状态 | `IosVpnConfigurationState` |
| `app_group_available` | App Group container 可读写事实 | `IosSharedStorageProbe.app_group_available` |
| `keychain_access_available` | Keychain sharing 可访问事实 | `IosSharedStorageProbe.keychain_access_available` |
| `embedded_runtime` | Extension 内 Rust runtime/FFI 可加载状态 | `IosEmbeddedRuntimeState` |
| `mitm_user_enabled` | 用户显式 MITM 开关 | `IosPlatformSnapshot.mitm_user_enabled` |
| `mitm_certificate_state` | 项目管理 CA 的安装/信任/撤销事实 | `CertificateTrustState` |
| `mitm_certificate_subject` | 可展示 subject 元数据 | `IosMitmCertificateProbe.subject` |
| `mitm_certificate_fingerprint_sha256` | 可展示 fingerprint 元数据 | `IosMitmCertificateProbe.fingerprint_sha256` |
| `diagnostics` | bridge 采集失败或拒绝原因 | 稳定 `platform.ios.*` diagnostics |

DTO 不得携带 secret、absolute path、Keychain query、certificate DER/PEM、profile payload、traffic sample、
complete subscription URL 或可反推出用户账号的标识。

## Fact Collection Mapping

### Network Extension

Swift bridge 必须把 Network Extension 状态拆成三个独立事实：

- entitlement/provisioning 可用性：缺失时映射为 `platform.ios.network_extension.entitlement_missing`。
- provider 可加载性：target 不存在、bundle 不匹配或不可加载时映射为
  `platform.ios.network_extension.provider_unavailable`。
- VPN configuration 状态：manager 不可用、配置未保存、需要授权或授权被拒绝时映射到
  `platform.ios.vpn_configuration.*`。

Bridge 不得把 `NEPacketTunnelProvider` 实例、manager 对象、provider configuration dictionary 或 bundle
identifier 传给 Rust；只传入枚举状态和安全诊断。

### App Group

App Group 只用于共享最小 tunnel profile、last-known-good profile 指针和非 secret 状态摘要。bridge 必须验证：

- containing app 和 extension 看到同一共享容器。
- active profile 的 schema version、profile id 和 content hash 可读取。
- 写入失败、容器不可用或 schema 不兼容时输出 `platform.ios.app_group.unavailable`。

App Group 文件不得保存账号 token、私钥、证书私钥、完整订阅 URL 或用户流量内容。

### Keychain

Keychain sharing 只保存 secret reference 或凭据本体，Rust snapshot 只能收到可用/不可用事实：

- Keychain sharing 可访问时，`keychain_access_available=true`。
- 权限缺失、access group 不匹配、item 不可读或系统拒绝时，输出
  `platform.ios.keychain.access_denied`。

Bridge 只能传递 secret handle 是否存在、读取是否允许和诊断 code，不得传递 Keychain item value。

### Embedded Runtime

Bridge 必须在 Extension 进程内验证嵌入式 runtime，不能 fallback 到外部进程、CLI 或 daemon。
后续 Rust staticlib、XCFramework、C ABI、owned buffer、panic/error mapping 和 ABI version negotiation
必须遵守 [iOS Embedded Runtime FFI Boundary Design](ios-embedded-runtime-ffi-boundary-design.md)。

映射规则：

- runtime 可加载且 ABI/schema 兼容：`IosEmbeddedRuntimeState::Available`。
- artifact、symbol、link target 或 XCFramework 缺失：`IosEmbeddedRuntimeState::Missing`。
- ABI version、schema version 或 generated binding 不兼容：`IosEmbeddedRuntimeState::AbiMismatch`。
- 初始化、内存限制或 Extension lifecycle handoff 失败：`IosEmbeddedRuntimeState::InitializationFailed`。

### MITM Certificate

MITM 证书状态必须保守采集：

- CA generation、installation prompt、user trust confirmation、fingerprint 校验、expiration/revocation 检测和
  `CertificateTrustState` mapping 必须遵守
  [iOS MITM Certificate Lifecycle Design](ios-mitm-certificate-lifecycle-design.md)。
- 未发现项目管理 CA 元数据：`CertificateTrustState::NotInstalled`。
- 已安装但无法证明 SSL/TLS 信任：`CertificateTrustState::InstalledUntrusted` 或 `Unknown`。
- 只有后续独立证书设计证明可通过受支持路径确认信任时，才可返回 `Trusted`。
- fingerprint 不匹配、过期、撤销或用户移除：`Revoked` 或 `NotInstalled`。
- 任何无法可靠判断的路径：`Unknown`。

Bridge 可传入 subject 和 SHA-256 fingerprint 展示元数据；不得传入私钥、完整证书、profile payload 或信任数据库内容。

## Diagnostic Mapping

Swift bridge 必须复用 `platform-ios` 的稳定 code namespace。最小 code 集合：

- `platform.ios.network_extension.entitlement_missing`
- `platform.ios.network_extension.provider_unavailable`
- `platform.ios.vpn_configuration.manager_unavailable`
- `platform.ios.vpn_configuration.not_saved`
- `platform.ios.vpn_configuration.authorization_required`
- `platform.ios.vpn_configuration.authorization_denied`
- `platform.ios.app_group.unavailable`
- `platform.ios.keychain.access_denied`
- `platform.ios.embedded_runtime.available`
- `platform.ios.embedded_runtime.missing`
- `platform.ios.embedded_runtime.abi_mismatch`
- `platform.ios.embedded_runtime.initialization_failed`
- `platform.ios.remote_script_execution.disabled_by_policy`
- `platform.ios.mitm_certificate.not_installed`
- `platform.ios.mitm_certificate.installed_untrusted`
- `platform.ios.mitm_certificate.trusted`
- `platform.ios.mitm_certificate.revoked`
- `platform.ios.mitm_certificate.unknown`

Bridge 诊断 message 可以面向 UI，但上层只能依赖 code、severity 和 source。所有 message 必须避免泄露 secret、
Bundle ID、Team ID、Provisioning Profile UUID、Keychain item key、absolute path、subscription URL 和用户流量内容。

## Lifecycle Handoff

Bridge 只负责事实采集和 snapshot handoff，不负责绕过运行层门禁：

1. Containing app 保存或更新 VPN configuration。
2. Containing app 采集 manager、App Group、Keychain、证书和用户 MITM 开关事实。
3. Extension 在 `startTunnel` 内重新采集 provider、App Group、Keychain、embedded runtime 和 active profile 事实。
4. Bridge 合并 facts，生成去敏 snapshot。
5. `platform-ios` 把 snapshot 映射为 `PlatformCapabilityStatus`。
6. `control-runtime` 根据 tunnel、embedded runtime、MITM、remote script 和证书状态决定启动或拒绝。

同一 fact 被 containing app 和 extension 重复采集时，extension 侧事实优先；如果无法合并，必须输出诊断并保守拒绝。

## Validation Entry

当前设计只通过 `.github/workflows/ci.yml` Repository policy 静态检查：

- 本文件存在，标题为 `iOS Swift Network Extension Bridge Design`。
- 包含 `NEPacketTunnelProvider`、`NETunnelProviderManager`、App Group、Keychain、
  `IosPlatformSnapshot`、`IosNetworkExtensionProbe`、`IosSharedStorageProbe`、
  `IosEmbeddedRuntimeProbe`、`IosMitmCertificateProbe`、`CertificateTrustState`、
  `platform.ios.keychain.access_denied`、`platform.ios.remote_script_execution.disabled_by_policy`
  和 `macos-26`。
- 仓库仍不包含 `Package.swift`、Xcode project、workspace、entitlement、signing 配置或 iOS release asset。

后续出现 Swift package、Xcode project 或 Network Extension target 时，必须遵守
[iOS Swift Xcode Bridge Source Contract](ios-swift-xcode-bridge-source-contract.md)，并且只在 GitHub
Actions `macos-26` runner 中执行 `swift build`、`swift test`、`xcodebuild`、签名或上传验证。

## Release Boundary

本设计不允许发布 iOS artifact。iOS release workflow 在以下条件满足前不得定义 artifact、signing、
TestFlight upload 或 App Store upload job：

- 本 bridge design 已通过 GitHub Actions static governance。
- Swift/Xcode source contract 已完成并通过 GitHub Actions static governance。
- iOS embedded runtime FFI boundary design 已完成并通过 GitHub Actions static governance。
- iOS MITM certificate lifecycle design 已完成并通过 GitHub Actions static governance。
- Swift bridge、Network Extension target 和 Rust embedded runtime bridge 已在 GitHub Actions `macos-26` runner 验证。
- Apple Developer、App ID、Network Extension entitlement、Provisioning Profile、GitHub Secrets、隐私政策、
  App Review Notes 和目标地区 VPN 合规材料已完成人工确认。
- MITM 证书生成、安装提示、信任确认、fingerprint 校验、过期/撤销检测和 source contract tests 已完成。

Linux artifact 发布继续受 license/NOTICE confirmed marker、`package-linux` preflight 和后续 artifact gates 阻断。

## References

- Apple Developer Documentation: Network Extension, `https://developer.apple.com/documentation/networkextension`
- Apple Developer Documentation: Packet Tunnel Provider, `https://developer.apple.com/documentation/networkextension/packet-tunnel-provider`
- Apple Developer Documentation: `NEPacketTunnelProvider`, `https://developer.apple.com/documentation/networkextension/nepackettunnelprovider`
- Apple Developer Documentation: `NETunnelProviderManager`, `https://developer.apple.com/documentation/networkextension/netunnelprovidermanager`
- Apple App Review Guidelines, `https://developer.apple.com/app-store/review/guidelines/`
- Apple Support: Trust manually installed certificate profiles in iOS, iPadOS, and visionOS, `https://support.apple.com/en-us/102390`
