# iOS Platform Adapter Source Contract

本文件定义 `platform-ios` 源码必须满足的 source contract。它承接
[iOS Network Extension Design](ios-network-extension-design.md)、
[iOS Swift Network Extension Bridge Design](ios-swift-network-extension-bridge-design.md)、
[iOS Swift Xcode Bridge Source Contract](ios-swift-xcode-bridge-source-contract.md)、
[iOS Embedded Runtime FFI Boundary Design](ios-embedded-runtime-ffi-boundary-design.md)、
[iOS MITM Certificate Lifecycle Design](ios-mitm-certificate-lifecycle-design.md)、
[iOS Entitlement Provisioning Source Contract](ios-entitlement-provisioning-source-contract.md)、
[iOS App Review Privacy Release Readiness Design](ios-app-review-privacy-release-readiness-design.md)、
[iOS Platform Risk Assessment](ios-platform-risk-assessment.md) 和
[Control Runtime Orchestration Design](control-runtime-orchestration.md)，用于约束
iOS platform adapter 如何把 Apple 平台事实映射为领域层可消费的能力状态。

当前状态：首个纯 Rust `crates/platform-ios` 映射骨架已落地。仓库仍尚未包含 Swift package、
Xcode project、Network Extension target、entitlement、Provisioning Profile、签名凭据或
TestFlight/App Store Connect 发布配置。本地仍不得运行 `swift build`、`swift test`、
`xcodebuild`、签名、打包或发布验证。

## Goals

- 定义 `platform-ios` crate 或等价模块的职责、依赖方向和源码进入条件。
- 固定 `PlatformCapabilityService`、`PlatformCapabilityStatus`、`PlatformCapabilities` 和
  `MitmCertificateStatus` 的 iOS 映射规则。
- 定义 Network Extension entitlement、VPN 配置、App Group、Keychain、embedded runtime、
  MITM 证书和远程脚本能力的稳定诊断边界。
- 为后续 macOS GitHub Actions 验证入口提供静态和源码验收条件。

## Non-Goals

- 不实现 Swift、Xcode project、Packet Tunnel Provider、FFI bridge、UI 或 iOS runtime。
- 不申请或配置 Apple Developer Program、App ID、Network Extension entitlement、
  Provisioning Profile、证书、App Store Connect 或 TestFlight。
- 不读取、生成、安装或信任 MITM CA 证书。
- 不在 release workflow 中定义 iOS artifact、TestFlight upload、App Store upload 或 signing job。

## Architecture Position

iOS adapter 必须位于 platform adapter 层。依赖方向必须保持：

1. `control-domain` 定义纯领域类型、`PlatformCapabilityService` 和诊断结构。
2. `control-runtime` 只调用 `PlatformCapabilityService`，不依赖 Apple SDK、Swift 或 Xcode。
3. `platform-ios` 只能依赖 `control-domain` 和必要的纯 Rust 支持代码；首个源码增量不得引入
   `NetworkExtension`、UIKit、Swift runtime 或 Xcode project。
4. Swift/Apple SDK 代码后续位于 iOS app、Network Extension target 或专用 bridge 层，负责采集
   `NEPacketTunnelProvider`、`NETunnelProviderManager`、Keychain、App Group 和证书状态事实。
5. Swift/Apple SDK 层只能向 `platform-ios` 传入去敏后的 snapshot；领域层不能直接接触 Apple SDK 类型。

首个 `platform-ios` crate 类似 `platform-linux` 的早期形态：提供静态测试替身、snapshot 类型、
诊断 code 常量和纯映射函数，先证明领域边界稳定，再引入真实 iOS app/extension bridge。

## Proposed Source Layout

当前首个源码增量采用以下最小布局：

```text
crates/platform-ios/
  Cargo.toml
  README.md
  src/lib.rs
  tests/platform_ios_contracts.rs
```

`Cargo.toml` 必须加入 workspace，但 `platform-ios` 首个版本只依赖 `control-domain`。Swift bridge design
已定义 Apple SDK 事实去敏边界；如果后续需要 Swift 源码、C ABI、XCFramework 或 generated bindings，
必须遵守 [iOS Swift Xcode Bridge Source Contract](ios-swift-xcode-bridge-source-contract.md)。

当前公开类型：

- `StaticIosPlatformCapabilityService`：实现 `PlatformCapabilityService` 的测试替身。
- `IosPlatformSnapshot`：保存 iOS 能力快照。
- `IosNetworkExtensionProbe`：表达 entitlement、VPN 配置和用户授权状态。
- `IosEmbeddedRuntimeProbe`：表达 Extension 内嵌 runtime 是否可加载。
- `IosMitmCertificateProbe`：表达证书安装、信任、撤销和 unknown 状态。
- `IosSharedStorageProbe`：表达 App Group 和 Keychain sharing 可用性。
- `ios_diagnostic`：生成稳定 `platform.ios.*` 诊断。

这些类型必须保持 pure data，不携带 `NEPacketTunnelProvider`、`NETunnelProviderManager`、`SecTrust`、
`SecCertificate`、Keychain item reference、file descriptor、URLCredential 或任何 Apple SDK 私有类型。

## Capability Mapping

`platform-ios` 必须把 snapshot 映射为领域层状态：

| 领域字段 | iOS snapshot 来源 | 初始映射 |
| --- | --- | --- |
| `os` | adapter target | 固定为 `OperatingSystem::Ios` |
| `tunnel` | Network Extension entitlement、`NETunnelProviderManager` saved configuration、用户 VPN 授权 | entitlement、配置和授权全部满足才为 `Available` |
| `mitm` | 用户 MITM 开关、证书状态、平台策略 | 默认 `Unavailable`；只有用户启用且证书 `Trusted` 后才可用 |
| `embedded_runtime` | Extension 内 Rust core/FFI/静态库可加载状态 | 不能加载或需要外部进程时必须 `Unavailable` |
| `remote_script_execution` | iOS App Review policy | 首版固定 `Unavailable`，reason 为 `remote script execution is disabled on iOS` |
| `mitm_certificate` | `IosMitmCertificateProbe` | 映射为 `MitmCertificateStatus` |
| `diagnostics` | 所有 iOS probe | 保留稳定 `platform.ios.*` code 和 source |

领域层已有 `PlatformCapabilities` 是粗粒度能力声明；`PlatformCapabilityStatus` 是运行时事实。iOS adapter
不得只设置 `PlatformCapabilities` 后跳过 `PlatformCapabilityStatus`，所有用户授权、entitlement 和证书状态都必须通过
`PlatformCapabilityService::status()` 暴露。

## Network Extension And Entitlement Diagnostics

iOS adapter 必须把 entitlement、Provisioning Profile 和 VPN 配置问题表达为诊断，而不是 panic 或隐藏失败。
后续 `.entitlements`、App ID、Network Extension capability、Provisioning Profile、GitHub Secrets 和 signing
asset redaction 的源码与 workflow 边界必须遵守
[iOS Entitlement Provisioning Source Contract](ios-entitlement-provisioning-source-contract.md)。

推荐诊断 code：

| code | severity | source | 含义 |
| --- | --- | --- | --- |
| `platform.ios.network_extension.entitlement_missing` | Error | `platform.ios.network_extension` | Network Extension capability 或 entitlement 缺失 |
| `platform.ios.network_extension.provider_unavailable` | Error | `platform.ios.network_extension` | `NEPacketTunnelProvider` target 不存在或不可加载 |
| `platform.ios.vpn_configuration.manager_unavailable` | Error | `platform.ios.vpn_configuration` | 无法使用 `NETunnelProviderManager` 读取或保存配置 |
| `platform.ios.vpn_configuration.not_saved` | Warning | `platform.ios.vpn_configuration` | VPN 配置尚未保存 |
| `platform.ios.vpn_configuration.authorization_required` | Warning | `platform.ios.vpn_configuration` | 用户尚未授权 VPN 配置 |
| `platform.ios.vpn_configuration.authorization_denied` | Error | `platform.ios.vpn_configuration` | 用户拒绝或撤销 VPN 授权 |
| `platform.ios.app_group.unavailable` | Error | `platform.ios.app_group` | App Group 无法读写共享配置 |
| `platform.ios.keychain.access_denied` | Error | `platform.ios.keychain` | Keychain sharing 或凭据读取被拒绝 |

诊断 message 可以面向 UI 或日志解释，但上层只能依赖稳定 code 和 source。adapter 不得记录 Bundle ID、
Provisioning Profile UUID、team secret、Keychain item value、订阅 URL 或用户凭据。

## Certificate Status Read Boundary

iOS MITM 证书状态必须保守映射。adapter 不得把“证书文件存在”解释为“系统 SSL/TLS 已信任”。
后续 CA generation、installation prompt、user trust confirmation、fingerprint 校验、expiration/revocation
检测和 `CertificateTrustState` mapping 必须遵守
[iOS MITM Certificate Lifecycle Design](ios-mitm-certificate-lifecycle-design.md)。

证书状态规则：

- 未发现项目管理的 CA 元数据时，返回 `CertificateTrustState::NotInstalled`。
- 已知用户安装了证书但无法证明 SSL/TLS 完全信任时，返回 `InstalledUntrusted` 或 `Unknown`。
- 只有通过 Apple 支持的 API、MDM/Configurator 管理事实、用户明确确认流程和后续独立设计证明后，才能返回 `Trusted`。
- 证书撤销、fingerprint 不匹配、过期或被用户移除时，返回 `Revoked` 或 `NotInstalled`，并输出 Error/Warning 诊断。
- 无法可靠判断时必须返回 `Unknown`，`mitm_gate` 必须保持拒绝。

推荐诊断 code：

| code | severity | source | 含义 |
| --- | --- | --- | --- |
| `platform.ios.mitm_certificate.not_installed` | Warning | `platform.ios.mitm_certificate` | 未发现项目 MITM CA |
| `platform.ios.mitm_certificate.installed_untrusted` | Warning | `platform.ios.mitm_certificate` | 已安装但未确认 SSL/TLS 信任 |
| `platform.ios.mitm_certificate.trusted` | Info | `platform.ios.mitm_certificate` | 已按受支持路径确认可用 |
| `platform.ios.mitm_certificate.revoked` | Error | `platform.ios.mitm_certificate` | 证书被撤销、过期或 fingerprint 不匹配 |
| `platform.ios.mitm_certificate.unknown` | Warning | `platform.ios.mitm_certificate` | 证书状态无法可靠判断 |

`MitmCertificateStatus.subject` 和 `fingerprint_sha256` 只能保存可展示元数据，不保存私钥、证书文件内容或 profile payload。

## Embedded Runtime Boundary

iOS 不能 fallback 到外部进程模型。`platform-ios` 必须显式表达 Extension 内嵌 runtime 状态：

- runtime 静态库、XCFramework 或 FFI bridge 缺失时，`embedded_runtime` 为 `Unavailable`。
- ABI version mismatch、symbol missing、初始化失败或 Extension 资源限制必须产生诊断。
- 后续 Rust staticlib、XCFramework、C ABI、owned buffer、panic/error mapping 和 ABI version negotiation
  必须遵守 [iOS Embedded Runtime FFI Boundary Design](ios-embedded-runtime-ffi-boundary-design.md)。
- adapter 不得启动 CLI、daemon、helper process 或外部代理二进制。
- runtime 可用性只代表可以在 Extension 内加载，不代表 tunnel 已经启动或配置已通过。

推荐诊断 code：

| code | severity | source | 含义 |
| --- | --- | --- | --- |
| `platform.ios.embedded_runtime.available` | Info | `platform.ios.embedded_runtime` | Extension 内嵌 runtime 可加载 |
| `platform.ios.embedded_runtime.missing` | Error | `platform.ios.embedded_runtime` | runtime artifact 或 link target 缺失 |
| `platform.ios.embedded_runtime.abi_mismatch` | Error | `platform.ios.embedded_runtime` | runtime ABI 或 schema 不兼容 |
| `platform.ios.embedded_runtime.initialization_failed` | Error | `platform.ios.embedded_runtime` | runtime 初始化失败 |

## Remote Script Policy

iOS 首版必须固定拒绝任意远程脚本执行：

- `remote_script_execution` 固定为 `PlatformFeatureState::Unavailable`。
- reason 必须稳定为 `remote script execution is disabled on iOS`。
- 远程规则、节点、策略和插件 manifest 可以作为数据参与校验。
- 会执行源码、动态下载代码、解释脚本或改变功能的远程内容必须在 iOS 首版拒绝。

推荐诊断 code：`platform.ios.remote_script_execution.disabled_by_policy`。

## Current Source Mapping

当前 `crates/platform-ios` 已提供首批纯 Rust source contract 实现：

- `StaticIosPlatformCapabilityService` 作为 `PlatformCapabilityService` 测试替身。
- `IosPlatformSnapshot` 把去敏的 iOS 平台事实映射为 `PlatformCapabilityStatus`，并固定
  `OperatingSystem::Ios`。
- `IosNetworkExtensionProbe` 表达 entitlement、provider 和 VPN 配置授权状态。
- `IosEmbeddedRuntimeProbe` 表达 Extension 内嵌 runtime 可加载、缺失、ABI mismatch 和初始化失败。
- `IosMitmCertificateProbe` 保守映射 `MitmCertificateStatus`，保留 subject/fingerprint 展示元数据和证书诊断。
- `IosSharedStorageProbe` 表达 App Group 与 Keychain sharing 可用性。
- 稳定 `platform.ios.*` 诊断 code 常量和 `ios_diagnostic` helper。
- 合同测试覆盖 entitlement missing、VPN configuration not saved、authorization required/denied、embedded runtime
  missing、remote script disabled、shared storage failure 和 certificate not installed/installed untrusted/trusted/revoked/unknown。

该 crate 当前不读取 Apple SDK 类型、不启动 Network Extension、不申请 entitlement、不读取或安装证书、不生成 iOS artifact。
后续 Swift、Xcode 或 Network Extension bridge 源码必须遵守
[iOS Swift Xcode Bridge Source Contract](ios-swift-xcode-bridge-source-contract.md)，再由 GitHub Actions
`macos-26` runner 验证。

## First Source Increment Acceptance

`crates/platform-ios` 的首个源码增量必须满足：

- 新增 `crates/platform-ios` workspace member 和 README。
- 只依赖 `control-domain`，不依赖 `control-runtime`、Apple SDK、Swift、Xcode project 或 UI framework。
- 提供 `StaticIosPlatformCapabilityService`、`IosPlatformSnapshot`、Network Extension/embedded runtime/certificate/shared storage probe 类型。
- 实现 `PlatformCapabilityService`，固定 `OperatingSystem::Ios`。
- 覆盖 tunnel entitlement missing、VPN configuration not saved、authorization required/denied、embedded runtime missing、
  remote script disabled、certificate not installed/installed untrusted/trusted/revoked/unknown 的合同测试。
- README、TODO、CHANGELOG、CI policy 和 governance checks 同步更新。
- Rust format、lint、test、build 和 dependency audit 只通过 GitHub Actions 执行。

## GitHub Actions Validation Entry

当前本合同和 `crates/platform-ios` 通过 Repository policy 做静态检查：

- 合同文件存在。
- 标题为 `iOS Platform Adapter Source Contract`。
- 包含 `platform-ios`、`iOS Swift Network Extension Bridge Design`、`StaticIosPlatformCapabilityService`、`IosPlatformSnapshot`、
  `PlatformCapabilityService`、`PlatformCapabilityStatus`、`MitmCertificateStatus`、
  `NEPacketTunnelProvider`、`NETunnelProviderManager`、`entitlement_missing`、
  `remote_script_execution` 和 `macos-26`。
- `crates/platform-ios/README.md`、workspace member、核心源码类型、稳定 `platform.ios.*`
  诊断 code 和 `platform_ios_contracts.rs` 合同测试存在。

当前 `crates/platform-ios` 的 Rust 验证进入现有 GitHub Actions Rust matrix。后续出现 Swift、
Xcode project 或 Network Extension target 后，只能在 GitHub Actions `macos-26` runner 中执行
`swift build`、`swift test`、`xcodebuild` 或签名相关验证。

## Release Boundary

本合同不允许发布 iOS artifact。iOS release workflow 在以下条件满足前不得定义 artifact、signing、
TestFlight upload 或 App Store upload job：

- `crates/platform-ios` 首个源码增量已通过 GitHub Actions。
- Swift/Network Extension bridge design 已完成并通过 GitHub Actions static governance。
- Swift/Xcode bridge source contract 已完成并通过 GitHub Actions static governance。
- iOS embedded runtime FFI boundary design 已完成并通过 GitHub Actions static governance。
- iOS MITM certificate lifecycle design 已完成并通过 GitHub Actions static governance。
- iOS entitlement/provisioning source contract 已完成并通过 GitHub Actions static governance。
- iOS App Review/privacy release readiness design 已完成并通过 GitHub Actions static governance。
- Apple Developer、App ID、Network Extension entitlement、Provisioning Profile、GitHub Secrets、
  App Privacy disclosure、隐私政策、App Review Notes、TestFlight/App Store Connect 人工确认和目标地区 VPN compliance 已完成。
- MITM 证书生成、安装提示、信任确认、fingerprint 校验、过期/撤销检测和 source contract tests 已完成。

Linux artifact 发布继续受 license/NOTICE confirmed marker、`package-linux` preflight 和后续 artifact gates 阻断。

## References

- Apple Developer Documentation: Network Extension, `https://developer.apple.com/documentation/networkextension`
- Apple Developer Documentation: Packet Tunnel Provider, `https://developer.apple.com/documentation/networkextension/packet-tunnel-provider`
- Apple Developer Documentation: `NEPacketTunnelProvider`, `https://developer.apple.com/documentation/networkextension/nepackettunnelprovider`
- Apple Developer Documentation: `NETunnelProviderManager`, `https://developer.apple.com/documentation/networkextension/netunnelprovidermanager`
- Apple App Review Guidelines, `https://developer.apple.com/app-store/review/guidelines/`
- Apple Support: Trust manually installed certificate profiles in iOS, iPadOS, and visionOS, `https://support.apple.com/en-us/102390`
- Apple Developer Account Help: Provisioning with capabilities, `https://developer.apple.com/help/account/reference/provisioning-with-managed-capabilities/`
