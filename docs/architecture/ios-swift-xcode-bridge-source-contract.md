# iOS Swift Xcode Bridge Source Contract

本文件定义后续 Swift package、Xcode project、Network Extension target、FFI/DTO 文件布局和
GitHub Actions 验证入口的 source contract。它承接
[iOS Network Extension Design](ios-network-extension-design.md)、
[iOS Platform Adapter Source Contract](ios-platform-adapter-source-contract.md)、
[iOS Swift Network Extension Bridge Design](ios-swift-network-extension-bridge-design.md)、
[iOS Embedded Runtime FFI Boundary Design](ios-embedded-runtime-ffi-boundary-design.md)、
[iOS MITM Certificate Lifecycle Design](ios-mitm-certificate-lifecycle-design.md)、
[iOS Entitlement Provisioning Source Contract](ios-entitlement-provisioning-source-contract.md)、
[iOS App Review Privacy Release Readiness Design](ios-app-review-privacy-release-readiness-design.md)、
[iOS Privacy Manifest Source Contract](ios-privacy-manifest-source-contract.md) 和
[iOS App Review Manual Confirmation Source Contract](ios-app-review-manual-confirmation-source-contract.md) 以及
[iOS Platform Risk Assessment](ios-platform-risk-assessment.md)。

当前状态：contract-only。仓库仍不包含 `Package.swift`、Xcode project、workspace、Swift source、
Network Extension target、entitlement、Provisioning Profile、签名配置、TestFlight/App Store 上传 job
或 iOS release asset。本地仍不得运行 `swift build`、`swift test`、`xcodebuild`、签名、打包或发布验证。

## Goals

- 固定后续 Swift package、Xcode source tree 和 Network Extension target 的最小源码布局。
- 定义 Swift DTO、FFI handoff 和 `platform-ios` Rust snapshot 之间的边界。
- 约束 `NEPacketTunnelProvider`、`NETunnelProviderManager`、App Group、Keychain 和 embedded runtime
  事实只能以去敏 DTO 进入 Rust。
- 定义 GitHub Actions `macos-26` 上的 `swift build`、`swift test`、`xcodebuild` 验证入口。
- 明确禁止提交 signing/provisioning secret、证书私钥、Provisioning Profile 或 App Store Connect API key。

## Non-Goals

- 不新增 Swift 源码、`Package.swift`、Xcode project、workspace、Network Extension target 或 UI。
- 不生成 C ABI header、generated bindings、XCFramework、staticlib 或 embedded runtime artifact。
- 不申请或配置 Apple Developer Program、App ID、Network Extension entitlement、Provisioning Profile、
  signing certificate、TestFlight、App Store Connect 或 GitHub Secrets。
- 不启用 iOS signing、TestFlight upload、App Store upload、notarization 或 iOS release asset。

## Dependency Direction

依赖方向必须保持单向：

1. `control-domain` 定义 `PlatformCapabilityService`、领域状态、诊断和 `CertificateTrustState`。
2. `platform-ios` 接收去敏 `IosPlatformSnapshot`，并映射为 `PlatformCapabilityStatus`。
3. Swift bridge 位于 Apple SDK adapter 层，负责读取系统事实并生成 Swift DTO。
4. FFI 层只传递 stable scalar、owned string buffer、diagnostic code 和 ABI/schema version。
5. `control-domain`、`control-runtime` 和 `platform-ios` 不得 import Swift、NetworkExtension、Security.framework、
   UIKit、SwiftUI、Xcode project 文件或 Apple signing 配置。

Apple SDK 对象不得跨过 FFI 边界。`NEPacketTunnelProvider`、`NETunnelProviderManager`、
`NETunnelProviderProtocol`、`SecTrust`、`SecCertificate`、Keychain item reference、App Group file URL、
Bundle ID、Team ID、Provisioning Profile UUID、subscription URL、account token、private key、
certificate payload 和用户流量内容都不能传入 Rust 领域层。

## Future Source Layout

后续如果加入 Apple SDK bridge 源码，默认采用以下单一源码入口。该布局是未来验收目标，不代表当前仓库已经存在这些文件：

```text
apps/ios/
  Package.swift
  Sources/
    NetworkCoreBridge/
      IosPlatformSnapshotDTO.swift
      IosPlatformBridgeMapper.swift
      NetworkExtensionFacts.swift
      SharedStorageFacts.swift
      KeychainFacts.swift
      EmbeddedRuntimeFacts.swift
      MitmCertificateFacts.swift
      NetworkCoreRuntimeFFI.swift
    NetworkCoreApp/
      AppCoordinator.swift
      VpnConfigurationController.swift
    NetworkCorePacketTunnel/
      PacketTunnelProvider.swift
  Tests/
    NetworkCoreBridgeTests/
      IosPlatformBridgeMapperTests.swift
```

如果后续必须引入 Xcode project 或 workspace，它只能引用同一 `apps/ios` 源码树，并且必须保留
`NetworkCorePacketTunnel` 作为 Network Extension target 名称。Xcode project 不能成为唯一事实来源；
源码边界、DTO、FFI header、target membership 和 signing 状态都必须能被 GitHub Actions 静态检查。

## DTO Contract

Swift DTO 只能承载去敏事实，并且字段必须能稳定映射到 `platform-ios`：

| Swift DTO | Rust mapping | 允许字段 |
| --- | --- | --- |
| `IosPlatformSnapshotDTO` | `IosPlatformSnapshot` | feature facts、`mitm_user_enabled`、diagnostics |
| `IosNetworkExtensionFacts` | `IosNetworkExtensionProbe` | entitlement/provider/configuration enum |
| `IosSharedStorageFacts` | `IosSharedStorageProbe` | App Group 可用性、Keychain 可用性 |
| `IosEmbeddedRuntimeFacts` | `IosEmbeddedRuntimeProbe` | available/missing/ABI mismatch/initialization failed |
| `IosMitmCertificateFacts` | `IosMitmCertificateProbe` | `CertificateTrustState`、subject、fingerprint |
| `IosDiagnosticDTO` | `platform.ios.*` diagnostics | code、severity、source、safe message |

DTO 不得携带 secret、absolute path、Bundle ID、Team ID、Provisioning Profile UUID、Keychain query、
Keychain value、certificate DER/PEM、private key、profile payload、traffic sample、完整 subscription URL
或可反推出用户账号的标识。

`IosMitmCertificateFacts` 的 CA generation、installation prompt、user trust confirmation、fingerprint 校验、
expiration/revocation 检测和 `CertificateTrustState` mapping 必须遵守
[iOS MITM Certificate Lifecycle Design](ios-mitm-certificate-lifecycle-design.md)。

## FFI Boundary

后续 FFI 必须遵守 [iOS Embedded Runtime FFI Boundary Design](ios-embedded-runtime-ffi-boundary-design.md)
固定 ABI，再加入源码。最小要求：

- FFI 使用 stable C ABI 或 generated bindings，不能依赖 Swift-only object layout。
- 每次 handoff 必须携带 ABI version、DTO schema version 和 feature set version。
- string 和 binary metadata 必须使用 owned buffer 或 caller/callee 明确释放函数。
- Swift object、Apple SDK object、file descriptor、socket、Keychain reference 和 Security framework handle
  不得跨 FFI。
- Rust panic、Swift throw、OSStatus 和 Apple callback error 必须映射为稳定 diagnostic code。
- ABI mismatch 必须映射到 `IosEmbeddedRuntimeProbe`，并输出 `platform.ios.embedded_runtime.abi_mismatch`。
- 初始化失败必须映射为 `platform.ios.embedded_runtime.initialization_failed`，不能 fallback 到外部进程、
  daemon、CLI 或未审计 helper。

## Network Extension Target Boundary

`NetworkCorePacketTunnel` 是唯一允许引用 `NEPacketTunnelProvider` 的 target。`PacketTunnelProvider.swift`
只能负责 Extension lifecycle handoff：

1. 在 `startTunnel` 内重新读取 App Group、Keychain、embedded runtime 和 active profile facts。
2. 将 `NEPacketTunnelProvider` 和 `NETunnelProviderManager` 事实转换为 `IosNetworkExtensionFacts`。
3. 将共享存储、证书、embedded runtime 和诊断事实合并为 `IosPlatformSnapshotDTO`。
4. 通过 FFI 传入 Rust snapshot mapper 或 runtime entrypoint。
5. 根据 `PlatformCapabilityStatus` 的拒绝原因停止启动或进入受控运行。

Containing app 可以使用 `NETunnelProviderManager` 管理配置，但不能把 manager object、provider configuration
dictionary、Bundle ID、Team ID 或 profile UUID 传给 Rust。Extension target 不能读取完整订阅 secret；
secret 只能通过 Keychain 或 Apple 允许的共享凭据机制读取，并且 Rust snapshot 只能得到可用/不可用事实。

## Secret And Signing Policy

仓库不得提交 signing/provisioning secret。禁止提交内容包括：

- `.mobileprovision`、`.provisionprofile`、`.p12`、`.cer`、`.key`、`.pem` 私钥或导出的 signing certificate。
- App Store Connect API key、issuer id secret、private key、session token 或上传凭据。
- 真实 Provisioning Profile UUID、Team ID secret、Apple account token、Keychain item value 或私有 access group secret。
- 自动签名生成的本地 build setting、DerivedData、archive、export options 或签名产物。

当前仍不提交 `.entitlements` 文件。后续如果需要非 secret entitlement 文件，必须遵守
[iOS Entitlement Provisioning Source Contract](ios-entitlement-provisioning-source-contract.md)，证明文件只包含最小
capability 声明，并且所有证书、profile、Team ID、App Store Connect 凭据仍只能来自 GitHub Secrets、
GitHub Environments 或 Apple 官方平台。

## GitHub Actions Validation Entry

当前本合同只通过 `.github/workflows/ci.yml` Repository policy 静态检查：

- 本文件存在，标题为 `iOS Swift Xcode Bridge Source Contract`。
- 包含 `Package.swift`、`NetworkCorePacketTunnel`、`PacketTunnelProvider.swift`、`IosPlatformSnapshotDTO`、
  `FFI`、`NEPacketTunnelProvider`、`NETunnelProviderManager`、App Group、Keychain、
  `IosPlatformSnapshot`、`IosNetworkExtensionProbe`、`IosSharedStorageProbe`、
  `IosEmbeddedRuntimeProbe`、`IosMitmCertificateProbe`、`CertificateTrustState`、`macos-26`、
  `swift build`、`swift test`、`xcodebuild`、signing/provisioning secret 和 no iOS release asset。
- 仓库仍不包含实际 Swift package、Xcode project、workspace、entitlement、Provisioning Profile、signing 配置、
  TestFlight/App Store upload job 或 iOS release asset。

后续出现 `Package.swift` 时，CI 必须只在 GitHub Actions 中触发 Swift job：

- `swift build` 只在 GitHub Actions runner 执行。
- `swift test` 只在 GitHub Actions runner 执行。
- DTO mapper、FFI error mapping、secret redaction 和 ABI mismatch 必须有 Swift test 覆盖。

后续出现 Xcode project、workspace 或 Network Extension target 时，CI 必须只在 GitHub Actions `macos-26`
runner 执行 `xcodebuild`。需要签名的验证必须由单独 workflow design、manual-intervention 记录和 GitHub
Secrets/Apple 官方平台支持，不能在仓库内保存凭据。

## Acceptance Criteria

本 contract 增量完成时必须满足：

- README、ROADMAP、TODO、CHANGELOG、CI/CD policy 和 release strategy 同步记录本文件。
- `.github/workflows/ci.yml` 检查本文件存在和关键锚点。
- 不新增 `Package.swift`、`.xcodeproj`、`.xcworkspace`、Swift source、Network Extension target、
  `.entitlements`、Provisioning Profile、signing config、TestFlight/App Store upload job 或 iOS release asset。
- Linux artifact 继续等待 license/NOTICE confirmed marker；期间不得定义 `package-linux` 或发布 release asset。

## Release Boundary

本合同不允许发布 iOS artifact。iOS release workflow 在以下条件满足前不得定义 artifact、signing、
TestFlight upload 或 App Store upload job：

- 本合同和相关 iOS design 已通过 GitHub Actions static governance。
- iOS embedded runtime FFI boundary design 已完成并通过 GitHub Actions static governance。
- iOS MITM certificate lifecycle design 已完成并通过 GitHub Actions static governance。
- iOS entitlement/provisioning source contract 已完成并通过 GitHub Actions static governance。
- iOS App Review/privacy release readiness design 已完成并通过 GitHub Actions static governance。
- iOS Privacy Manifest source contract 已完成并通过 GitHub Actions static governance。
- iOS App Review manual confirmation source contract 已完成并通过 GitHub Actions static governance。
- Swift bridge、Network Extension target、FFI boundary 和 embedded runtime 已在 GitHub Actions `macos-26`
  runner 通过 `swift build`、`swift test` 和必要的 `xcodebuild` 验证。
- Apple Developer、App ID、Network Extension entitlement、Provisioning Profile、GitHub Secrets、App Privacy disclosure、
  隐私政策、App Review Notes、demo account、review attachment、TestFlight/App Store Connect 人工确认 marker、
  export compliance、beta app review 和目标地区 VPN compliance 已完成。
- MITM 证书生成、安装提示、信任确认、fingerprint 校验、过期/撤销检测和 source contract tests 已完成。

Linux artifact 发布继续受 license/NOTICE confirmed marker、`package-linux` preflight 和后续 artifact gates 阻断。

## References

- Apple Developer Documentation: Network Extension, `https://developer.apple.com/documentation/networkextension`
- Apple Developer Documentation: Packet Tunnel Provider, `https://developer.apple.com/documentation/networkextension/packet-tunnel-provider`
- Apple Developer Documentation: `NEPacketTunnelProvider`, `https://developer.apple.com/documentation/networkextension/nepackettunnelprovider`
- Apple Developer Documentation: `NETunnelProviderManager`, `https://developer.apple.com/documentation/networkextension/netunnelprovidermanager`
- Apple App Review Guidelines, `https://developer.apple.com/app-store/review/guidelines/`
- GitHub Docs: Using secrets in GitHub Actions, `https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions`
