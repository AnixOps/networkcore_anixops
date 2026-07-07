# iOS Entitlement Provisioning Source Contract

本文件定义后续 iOS `.entitlements`、App ID、Network Extension capability、Provisioning Profile、
GitHub Secrets、signing asset redaction 和 GitHub Actions `macos-26` 验证入口的 source contract。它承接
[iOS Network Extension Design](ios-network-extension-design.md)、
[iOS Platform Adapter Source Contract](ios-platform-adapter-source-contract.md)、
[iOS Swift Network Extension Bridge Design](ios-swift-network-extension-bridge-design.md)、
[iOS Swift Xcode Bridge Source Contract](ios-swift-xcode-bridge-source-contract.md)、
[iOS Embedded Runtime FFI Boundary Design](ios-embedded-runtime-ffi-boundary-design.md)、
[iOS MITM Certificate Lifecycle Design](ios-mitm-certificate-lifecycle-design.md) 和
[iOS App Review Privacy Release Readiness Design](ios-app-review-privacy-release-readiness-design.md) 以及
[iOS Platform Risk Assessment](ios-platform-risk-assessment.md)。

当前状态：contract-only。仓库仍不包含 `.entitlements`、Swift source、`Package.swift`、Xcode project、
workspace、Network Extension target、Provisioning Profile、`.mobileprovision`、signing certificate、
App Store Connect API key、TestFlight/App Store upload job 或 iOS release asset；当前状态明确为 no iOS release asset。
本地仍不得运行 `swift build`、`swift test`、`xcodebuild`、签名、打包、profile 解码或发布验证。

## Goals

- 固定后续 entitlement/provisioning 源码与 secret 的所有权边界。
- 定义 `.entitlements` 文件允许出现的非 secret 内容和禁止提交的 signing/provisioning secret。
- 约束 App ID、Bundle ID、Network Extension capability 和 Provisioning Profile 如何进入 GitHub Actions。
- 定义 signing asset redaction、日志摘要、artifact 和 diagnostic 的脱敏要求。
- 规定 entitlement/provisioning 事实如何映射到 `IosNetworkExtensionProbe`、
  `IosNetworkExtensionEntitlementState`、`NETunnelProviderManager` 授权状态和稳定 diagnostics。
- 为后续 GitHub Actions `macos-26` 上的 `swift build`、`swift test` 和 `xcodebuild` 验证提供入口。

## Non-Goals

- 不新增 `.entitlements`、Swift source、Xcode project、workspace、Network Extension target 或 UI。
- 不创建、下载、提交、解码或验证真实 Provisioning Profile。
- 不申请或配置 Apple Developer Program、App ID、Network Extension capability、signing certificate、
  TestFlight、App Store Connect 或 GitHub Secrets。
- 不启用 iOS signing、TestFlight upload、App Store upload、notarization 或 iOS release asset。
- 不改变当前 `platform-ios` Rust 类型；本合同只约束后续源码和 workflow 进入条件。

## Future Source Shape

后续如果需要非 secret entitlement 文件和 Apple SDK bridge 源码，默认采用以下布局。该布局是未来验收目标，
不代表当前仓库已经存在这些文件：

```text
apps/ios/
  Entitlements/
    NetworkCoreApp.entitlements
    NetworkCorePacketTunnel.entitlements
  Sources/
    NetworkCoreBridge/
      EntitlementProvisioningFacts.swift
      NetworkExtensionFacts.swift
    NetworkCorePacketTunnel/
      PacketTunnelProvider.swift
  Tests/
    NetworkCoreBridgeTests/
      EntitlementProvisioningFactsTests.swift
```

`NetworkCorePacketTunnel.entitlements` 只能随真实 Network Extension target 一起加入。任何 Xcode project、
workspace 或 target membership 都不能成为唯一事实来源；GitHub Actions 必须能静态检查 entitlement 文件内容、
target 名称、Bundle ID 输入、Provisioning Profile 输入来源和 secret redaction 规则。

## Entitlement File Contract

未来 `.entitlements` 文件必须是非 secret plist/XML 文件，只声明 Apple 要求的最小 capability：

- Network Extension target 必须包含 `com.apple.developer.networking.networkextension`。
- Packet Tunnel Provider 形态必须显式包含 `packet-tunnel-provider`。
- App Group 和 Keychain sharing 只能在对应 source contract 完成后加入，并且只能使用最小 access group。
- entitlement 文件不得包含真实 private key、Provisioning Profile UUID、App Store Connect API key、session token、
  certificate fingerprint secret、用户账号、subscription URL 或任何凭据。
- 如果 Team ID 需要进入 entitlement 中的 access group，必须通过模板或 CI 输入渲染；仓库内不得硬编码
  `TEAM_ID` secret 或私有 access group secret。
- entitlement 变更必须同步更新 Swift/Xcode bridge source contract、CI static governance 和 manual intervention 记录。

仓库当前仍不得提交任何 `.entitlements` 文件。加入 entitlement 文件前，必须先有 GitHub Actions `macos-26`
静态检查确认文件只包含允许 key，并且 release boundary 仍保持 no iOS release asset。

## App ID And Bundle ID Contract

App ID、Bundle ID 和 Network Extension capability 必须由人工在 Apple Developer 或 Apple 官方平台完成确认，
并在自动化中只暴露必要的非 secret 或已脱敏输入：

| 输入 | 建议来源 | Secret policy |
| --- | --- | --- |
| `APP_BUNDLE_ID` | GitHub Variables 或 environment input | 可公开时为 variable；不得写入 Rust snapshot |
| `PACKET_TUNNEL_BUNDLE_ID` | GitHub Variables 或 environment input | 必须与主 App Bundle ID 区分 |
| `TEAM_ID` | GitHub Secrets 或 protected environment | 日志、summary 和 artifact 中必须 redacted |
| `Network Extension capability` | Apple Developer manual confirmation | 不在仓库内自动申请 |
| `App ID` | Apple Developer manual confirmation | 只记录 safe identifier 或 redacted marker |

Containing app 和 Network Extension 的 Bundle ID 必须稳定且不同。Swift bridge 可以用这些输入验证 target/provisioning
匹配关系，但不得把 Bundle ID、Team ID、Provisioning Profile UUID 或 Apple account identity 传入
`control-domain`、`control-runtime` 或 `platform-ios`。

## Provisioning Profile Contract

Provisioning Profile 永远不得提交到仓库。后续 signing 验证只能在 GitHub Actions 或 Apple 官方平台中使用
GitHub Secrets 注入：

- `APPLE_PROVISIONING_PROFILE_BASE64`：containing app profile。
- `APPLE_PACKET_TUNNEL_PROVISIONING_PROFILE_BASE64`：Network Extension profile。
- `APPLE_CERTIFICATE_P12_BASE64`：signing certificate。
- `APPLE_CERTIFICATE_PASSWORD`：certificate password。
- `APPLE_KEYCHAIN_PASSWORD`：runner temporary keychain password。

CI 解码 profile 或 certificate 时必须满足：

- 只写入 runner 临时目录或临时 keychain。
- 不把 profile、certificate、private key、decoded plist、Team ID、Provisioning Profile UUID 或 certificate
  fingerprint secret 写入 GitHub Step Summary。
- 不上传 decoded signing asset、derived data、archive、export options、keychain 或 profile 到 artifact。
- job 结束时清理临时 keychain、profile 文件和 decoded signing asset。
- profile 必须匹配 expected Bundle ID、Team ID、entitlement set、profile type 和 expiration；任一不匹配都必须失败。

Profile 过期、capability 缺失、Bundle ID 不匹配或 entitlement 不匹配时，Swift bridge 和 `platform-ios` 只能产生
safe diagnostic，不得输出完整 profile payload。

## GitHub Secrets Contract

未来 iOS signing 或 App Store Connect workflow 至少需要以下 secret 或 protected environment input。定义 secret
名称不代表当前仓库已经配置这些 secret：

- `TEAM_ID`
- `APPLE_CERTIFICATE_P12_BASE64`
- `APPLE_CERTIFICATE_PASSWORD`
- `APPLE_KEYCHAIN_PASSWORD`
- `APPLE_PROVISIONING_PROFILE_BASE64`
- `APPLE_PACKET_TUNNEL_PROVISIONING_PROFILE_BASE64`
- `APP_STORE_CONNECT_API_KEY_ID`
- `APP_STORE_CONNECT_ISSUER_ID`
- `APP_STORE_CONNECT_API_PRIVATE_KEY`

GitHub Secrets 使用规则：

- CI 不得 `echo` secret value、decoded profile、private key 或 API key。
- `set -x`、debug dump、environment dump、profile dump 和 keychain dump 必须在 signing job 中禁用。
- Step Summary 只能输出 `present`、`missing`、`redacted`、`validated`、`expired` 或 `blocked` 等状态。
- secret 缺失时必须 fail closed，不能 fallback 到本地文件、开发者机器、仓库样例 profile 或 unsigned release path。
- App Store Connect API key 只能在独立 upload workflow design 完成后使用；当前合同不允许 TestFlight upload。

## Signing Asset Redaction

signing asset redaction 必须覆盖日志、diagnostics、test fixtures、summary 和 artifacts：

| Asset | Redaction rule |
| --- | --- |
| Team ID | 输出 `redacted-team-id` 或 hash 前缀，不输出原值 |
| Bundle ID | 仅在非 secret policy 允许时输出；Rust snapshot 不携带 |
| Provisioning Profile UUID | 不输出，不进入 diagnostic |
| Certificate common name/fingerprint | 只输出 `present`/`validated`，不输出完整值 |
| `.p12`、`.cer`、`.key`、`.pem` | 不提交、不上传、不写 summary |
| App Store Connect private key | 不提交、不上传、不写 summary |
| Keychain access group | 只输出 redacted group 或 capability status |

`IosDiagnosticDTO`、`ios_diagnostic` 和 GitHub Actions log message 只能包含 safe message、stable code、source、
retry hint 和 redacted status。任何 secret 泄露都必须视为 blocker，并记录 manual intervention 中的轮换动作。

## Diagnostic Mapping

后续 Swift bridge 必须把 entitlement/provisioning 事实映射为当前 `platform-ios` 可以消费的状态：

| Source fact | Rust mapping | Diagnostic |
| --- | --- | --- |
| Network Extension entitlement missing or profile lacks capability | `IosNetworkExtensionEntitlementState::Missing` | `platform.ios.network_extension.entitlement_missing` |
| `NEPacketTunnelProvider` target missing or not loadable | provider unavailable | `platform.ios.network_extension.provider_unavailable` |
| `NETunnelProviderManager` unavailable | manager unavailable | `platform.ios.vpn_configuration.manager_unavailable` |
| VPN configuration not saved | configuration not saved | `platform.ios.vpn_configuration.not_saved` |
| User authorization prompt required | authorization required | `platform.ios.vpn_configuration.authorization_required` |
| User authorization denied or revoked | authorization denied | `platform.ios.vpn_configuration.authorization_denied` |

`IosNetworkExtensionProbe` 必须继续只表达 entitlement、provider 和 VPN configuration enum，不携带 App ID、
Bundle ID、Team ID、Provisioning Profile UUID、profile payload、certificate payload 或 signing secret。

## GitHub Actions Validation Entry

当前本合同只通过 `.github/workflows/ci.yml` Repository policy 静态检查：

- 本文件存在，标题为 `iOS Entitlement Provisioning Source Contract`。
- 包含 `.entitlements`、App ID、Network Extension capability、Provisioning Profile、GitHub Secrets、
  signing asset redaction、`com.apple.developer.networking.networkextension`、`packet-tunnel-provider`、
  `NETunnelProviderManager`、`NEPacketTunnelProvider`、`IosNetworkExtensionProbe`、
  `IosNetworkExtensionEntitlementState`、`platform.ios.network_extension.entitlement_missing`、
  `platform.ios.vpn_configuration.authorization_required`、`platform.ios.vpn_configuration.authorization_denied`、
  `TEAM_ID`、`APP_BUNDLE_ID`、`PACKET_TUNNEL_BUNDLE_ID`、`APPLE_CERTIFICATE_P12_BASE64`,
  `APPLE_PROVISIONING_PROFILE_BASE64`、`APP_STORE_CONNECT_API_KEY_ID`、`macos-26`、`swift build`,
  `swift test`、`xcodebuild` 和 no iOS release asset。
- 仓库仍不包含 `.entitlements`、Swift source、`Package.swift`、Xcode project、workspace、Network Extension target、
  `.mobileprovision`、`.provisionprofile`、`.p12`、`.cer`、`.key`、`.pem`、signing 配置、TestFlight/App Store
  upload job 或 iOS release asset。

后续出现 `.entitlements`、Swift package、Xcode project 或 Network Extension target 时，验证只能在
GitHub Actions `macos-26` runner 中执行：

- entitlement plist 静态检查可以使用 Apple toolchain 或 `plutil`，只在 GitHub Actions 中运行。
- `swift build` 和 `swift test` 只在 GitHub Actions runner 执行。
- Xcode project 或 Network Extension target 使用 `xcodebuild`，只在 GitHub Actions `macos-26` runner 执行。
- signing 验证必须由独立 workflow design、manual-intervention 记录和 GitHub Secrets/Apple 官方平台支持。
- TestFlight/App Store upload 必须等独立 upload/release contract 完成后才能定义。

## Acceptance Criteria

本 contract 增量完成时必须满足：

- README、ROADMAP、TODO、CHANGELOG、CI/CD policy 和 release strategy 同步记录本文件。
- `.github/workflows/ci.yml` 检查本文件存在和关键锚点。
- 相关 iOS design/source contract 指向本 entitlement/provisioning source contract。
- 不新增 Swift source、`Package.swift`、`.xcodeproj`、`.xcworkspace`、`.entitlements`、Provisioning Profile、
  signing config、signing asset、TestFlight/App Store upload job 或 iOS release asset。
- Linux artifact 继续等待 license/NOTICE confirmed marker；期间不得定义 `package-linux` 或发布 release asset。

## Release Boundary

本合同不允许发布 iOS artifact。iOS release workflow 在以下条件满足前不得定义 artifact、signing、
TestFlight upload 或 App Store upload job：

- 本合同和相关 iOS contracts 已通过 GitHub Actions static governance。
- Swift/Xcode bridge、Network Extension target、entitlement plist、Provisioning Profile validation、FFI boundary、
  embedded runtime、certificate lifecycle source 和 Privacy Manifest source 已在 GitHub Actions `macos-26` runner 通过验证。
- Apple Developer、App ID、Network Extension capability、Provisioning Profile、GitHub Secrets、隐私政策、
  App Privacy disclosure、App Review Notes、TestFlight/App Store Connect 人工确认和目标地区 VPN 合规材料已完成人工确认。
- signing asset redaction、secret cleanup、profile expiration handling 和 diagnostic redaction 已有源码合同测试。

Linux artifact 发布继续受 license/NOTICE confirmed marker、`package-linux` preflight 和后续 artifact gates 阻断。

## References

- Apple Developer Documentation: Network Extension, `https://developer.apple.com/documentation/networkextension`
- Apple Developer Documentation: `NEPacketTunnelProvider`, `https://developer.apple.com/documentation/networkextension/nepackettunnelprovider`
- Apple Developer Documentation: `NETunnelProviderManager`, `https://developer.apple.com/documentation/networkextension/netunnelprovidermanager`
- Apple Developer Documentation: Network Extension entitlement,
  `https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension`
- Apple Developer Account Help: Provisioning with capabilities,
  `https://developer.apple.com/help/account/reference/provisioning-with-managed-capabilities/`
- Apple Developer Account Help: Supported capabilities for iOS,
  `https://developer.apple.com/help/account/reference/supported-capabilities-ios/`
- Apple Developer Documentation: Privacy manifest files,
  `https://developer.apple.com/documentation/bundleresources/privacy_manifest_files`
- GitHub Docs: Using secrets in GitHub Actions,
  `https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions`
