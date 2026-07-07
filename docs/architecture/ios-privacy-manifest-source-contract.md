# iOS Privacy Manifest Source Contract

本文件定义后续 iOS `PrivacyInfo.xcprivacy`、`NSPrivacyCollectedDataTypes`、
`NSPrivacyAccessedAPITypes`、Required Reason API、App Privacy answer source 和 GitHub Actions
`macos-26` 静态验证入口的 source contract。它承接
[iOS App Review Privacy Release Readiness Design](ios-app-review-privacy-release-readiness-design.md)、
[iOS Network Extension Design](ios-network-extension-design.md)、
[iOS Swift Xcode Bridge Source Contract](ios-swift-xcode-bridge-source-contract.md)、
[iOS Entitlement Provisioning Source Contract](ios-entitlement-provisioning-source-contract.md) 和
[iOS App Review Manual Confirmation Source Contract](ios-app-review-manual-confirmation-source-contract.md) 以及
[iOS Platform Risk Assessment](ios-platform-risk-assessment.md)。

当前状态：contract-only。仓库仍不包含 `PrivacyInfo.xcprivacy`、Swift source、`Package.swift`、
Xcode project、workspace、Network Extension target、App Store Connect App Privacy answers、privacy policy URL、
App Review manual confirmation marker、TestFlight upload job、App Store upload job、真实签名、Provisioning Profile
或 iOS release asset；当前状态明确为 no PrivacyInfo.xcprivacy、no TestFlight upload 和 no iOS release asset。
本地仍不得运行 `swift build`、`swift test`、`xcodebuild`、`plutil`、签名、打包、上传或发布验证。

## Goals

- 固定未来 `PrivacyInfo.xcprivacy` 文件位置、owner、主 App/Extension 分工和 source ownership。
- 定义 `NSPrivacyCollectedDataTypes`、`NSPrivacyCollectedDataType`、`NSPrivacyCollectedDataTypeLinked`、
  `NSPrivacyCollectedDataTypeTracking` 和 `NSPrivacyCollectedDataTypePurposes` 的数据来源规则。
- 定义 `NSPrivacyAccessedAPITypes`、`NSPrivacyAccessedAPITypeReasons` 和 Required Reason API 审查入口。
- 约束 `NSPrivacyTracking`、`NSPrivacyTrackingDomains`、Data Used to Track You、Data Linked to You 和
  Data Not Linked to You 的默认策略。
- 定义 App Privacy answer source、third-party SDK privacy manifest、SDK signature 和 GitHub Actions `macos-26`
  静态验证入口。
- 继续阻止真实 `PrivacyInfo.xcprivacy`、Swift/Xcode project、Network Extension target、signing、TestFlight upload、
  App Store upload 或 iOS release asset 进入当前阶段。

## Non-Goals

- 不新增 `PrivacyInfo.xcprivacy`、Swift source、Xcode project、workspace、Network Extension target 或 UI。
- 不回答、导出或提交 App Store Connect App Privacy answers。
- 不创建 privacy policy URL、App Review Notes、review attachment、demo account 或 TestFlight group。
- 不启用 TestFlight upload、App Store upload、App Review submission、signing、notarization 或 iOS release asset。
- 不改变当前 `platform-ios` Rust 类型；本合同只约束后续 iOS source 和 workflow 进入条件。

## Future Source Shape

后续如果加入 iOS source tree，Privacy Manifest 默认采用以下布局。该布局是未来验收目标，不代表当前仓库已经存在这些文件：

```text
apps/ios/
  Privacy/
    AppPrivacyAnswerSources.md
    PrivacyManifestDataInventory.md
    RequiredReasonApiInventory.md
  Sources/
    NetworkCoreApp/
      Resources/
        PrivacyInfo.xcprivacy
    NetworkCorePacketTunnel/
      Resources/
        PrivacyInfo.xcprivacy
  Tests/
    NetworkCorePrivacyTests/
      PrivacyManifestContractTests.swift
```

主 App 和 `Packet Tunnel Provider` 的 manifest ownership 必须分开：

- `NetworkCoreApp` manifest 只声明 containing app 直接采集的数据和直接访问的 required-reason API。
- `NetworkCorePacketTunnel` manifest 只声明 Extension tunnel runtime 直接采集的数据和直接访问的 required-reason API。
- shared Swift package、embedded runtime 或 third-party SDK 的 privacy manifest 必须按 Apple 规则参与合并检查。
- Xcode project 或 target membership 不能成为唯一事实来源；GitHub Actions 必须能从源码树直接找到 manifest、
  inventory 和 App Privacy answer source。

当前仓库仍不得提交任何 `PrivacyInfo.xcprivacy` 文件。加入真实文件前，必须先有 GitHub Actions `macos-26`
静态检查确认 source tree、manifest scope、inventory、App Privacy answer source 和 no secret policy。

## Collected Data Types Contract

未来 `NSPrivacyCollectedDataTypes` 必须从 `PrivacyManifestDataInventory.md` 或等价机器可读 inventory 生成或校验，
不得凭 App Store Connect 手工记忆维护。每个数据项至少声明：

| Field | Requirement |
| --- | --- |
| `NSPrivacyCollectedDataType` | 使用 Apple 定义的数据类型；未知或自定义类型必须 fail closed |
| `NSPrivacyCollectedDataTypeLinked` | 明确是否 linked to user；不能确定时按 linked 处理或阻止发布 |
| `NSPrivacyCollectedDataTypeTracking` | 默认 `false`；任何 tracking 必须先有独立风险评审 |
| `NSPrivacyCollectedDataTypePurposes` | 必须对应真实功能目的，不能用宽泛目的掩盖数据流 |
| owner | `NetworkCoreApp`、`NetworkCorePacketTunnel`、embedded runtime 或 third-party SDK |
| retention | local-only、session、diagnostic window 或 user-controlled deletion |
| upload boundary | no upload、support bundle、crash/diagnostic backend 或 future service |

首版 iOS 默认策略：

- VPN traffic content 不默认上传，不进入 diagnostics artifact，不作为 analytics 数据采集。
- MITM traffic content 在 MITM default off 状态下不采集；用户启用后也只在用户选择范围内本地处理。
- crash、performance、diagnostics、connection state、subscription/account state 如果被采集，必须明确是否 linked。
- Data Used to Track You 默认 blocked；任何 tracking domain、广告标识或跨 app/site tracking 都必须先更新本合同、
  App Review/privacy readiness design、privacy policy 和 manual intervention marker。

## Required Reason API Contract

未来 `NSPrivacyAccessedAPITypes` 必须从 `RequiredReasonApiInventory.md` 或等价机器可读 inventory 生成或校验。
每个 accessed API 项至少声明：

| Field | Requirement |
| --- | --- |
| `NSPrivacyAccessedAPIType` | 使用 Apple 定义的 required-reason API category |
| `NSPrivacyAccessedAPITypeReasons` | 使用 Apple 当前允许的 reason code；不得使用占位 reason |
| source owner | Swift file、embedded runtime bridge、third-party SDK 或 generated code |
| target owner | containing app、Packet Tunnel Provider 或 shared package |
| test owner | Swift contract test、source scan 或 manifest validation job |
| data exposure | 确认不会输出 secret、absolute path、subscription URL、certificate payload 或 traffic sample |

当前必须在合同中覆盖以下 Apple required-reason API category，未来如 Apple 增删 category，必须更新合同和 CI anchors：

- `NSPrivacyAccessedAPICategoryFileTimestamp`
- `NSPrivacyAccessedAPICategorySystemBootTime`
- `NSPrivacyAccessedAPICategoryDiskSpace`
- `NSPrivacyAccessedAPICategoryActiveKeyboards`
- `NSPrivacyAccessedAPICategoryUserDefaults`

NetworkCore 首版 iOS source 出现前，任何 required-reason API use 都保持 blocked。后续 Swift/Xcode source 加入时，
如果源码或 third-party SDK 访问 required-reason API，但 manifest 没有对应 `NSPrivacyAccessedAPITypeReasons`，
GitHub Actions 必须失败并输出 `platform.ios.privacy_manifest.accessed_api_reason_missing`。

## Tracking Contract

`NSPrivacyTracking` 默认必须为 `false`，`NSPrivacyTrackingDomains` 默认必须为空：

- 不允许默认写入 tracking domain、广告网络、cross-app identifier 或 cross-site tracking endpoint。
- 如未来业务需求引入 tracking，必须先完成独立 App Review/privacy 风险评审、用户授权设计、privacy policy 更新、
  App Privacy disclosure 更新、GitHub Actions source scan 和 manual intervention 确认。
- App Privacy answers 中的 Data Used to Track You 必须与 `NSPrivacyTracking` 和 `NSPrivacyTrackingDomains` 一致。
- 任一 manifest、third-party SDK privacy manifest 或 App Privacy answer source 声明 tracking 时，release workflow
  必须 fail closed，直到独立 tracking contract 完成。

## App Privacy Answer Source

App Privacy answer source 是仓库内未来连接源码事实和 App Store Connect 人工问卷的单一来源。最小字段：

```text
ios-app-privacy-answer-source-status=pending|confirmed
ios-app-privacy-answer-source-file=apps/ios/Privacy/AppPrivacyAnswerSources.md
ios-app-privacy-data-used-to-track-you=no|yes|blocked
ios-app-privacy-data-linked-to-you=declared|blocked
ios-app-privacy-data-not-linked-to-you=declared|blocked
ios-app-privacy-answers-owner=redacted-owner-or-role
ios-app-privacy-answers-confirmed-at=YYYY-MM-DD|pending
```

规则：

- App Store Connect App Privacy answers 仍由人工填写；仓库只能提供 answer source 和
  [iOS App Review Manual Confirmation Source Contract](ios-app-review-manual-confirmation-source-contract.md)
  定义的 safe marker。
- `confirmed` 前不得启用 TestFlight external testing、App Store submission 或 iOS release asset。
- `Data Linked to You` 和 `Data Not Linked to You` 必须能追溯到 manifest inventory、privacy policy 和 source owner。
- 缺失 answer source 或 marker 时必须输出 `platform.ios.privacy_manifest.app_privacy_answers_missing`。
- App Privacy answer source 不得包含用户账号、真实 tester email、subscription URL、App Store Connect API key 或私钥。

## Third-Party SDK Boundary

未来加入 Apple 列表内或任何采集数据的 third-party SDK 时，必须先完成以下检查：

- third-party SDK privacy manifest 必须存在、版本固定、source 可追踪。
- SDK signature 或 Apple 要求的签名验证策略必须有 GitHub Actions `macos-26` 验证入口。
- SDK manifest 中的 collected data、tracking 和 required-reason API 必须合并进 App Privacy answer source。
- SDK 更新必须同步更新 `PrivacyManifestDataInventory.md`、`RequiredReasonApiInventory.md`、CHANGELOG 和 CI anchors。
- SDK 如果引入 tracking、广告、analytics upload 或 remote code capability，默认阻断 iOS release，直到独立风险评审完成。

当前仓库未引入 iOS third-party SDK，因此本合同只定义 future boundary。

## Secret And Diagnostic Redaction

Privacy Manifest、inventory、App Privacy answer source、CI log 和 diagnostics 不得包含：

- Bundle ID secret、Team ID、Provisioning Profile UUID、App Store Connect API key、private key 或 signing asset。
- certificate DER/PEM、private key、fingerprint secret、Keychain item value 或 profile payload。
- subscription URL、account token、tester email、support ticket private content 或用户流量样本。
- runner absolute path、DerivedData、archive path 或 decoded signing asset path。

未来稳定 diagnostics source：

- `platform.ios.privacy_manifest`

未来稳定 diagnostic code：

- `platform.ios.privacy_manifest.missing`
- `platform.ios.privacy_manifest.invalid`
- `platform.ios.privacy_manifest.collected_data_mismatch`
- `platform.ios.privacy_manifest.accessed_api_reason_missing`
- `platform.ios.privacy_manifest.tracking_disallowed`
- `platform.ios.privacy_manifest.app_privacy_answers_missing`
- `platform.ios.privacy_manifest.third_party_sdk_manifest_missing`
- `platform.ios.privacy_manifest.sdk_signature_missing`

diagnostic message 只能输出 safe status、target owner、missing key、redacted file owner 和 retry hint。

## GitHub Actions Validation Entry

当前本合同只通过 `.github/workflows/ci.yml` Repository policy 静态检查：

- 本文件存在，标题为 `iOS Privacy Manifest Source Contract`。
- 包含 `PrivacyInfo.xcprivacy`、`NSPrivacyCollectedDataTypes`、`NSPrivacyCollectedDataType`、
  `NSPrivacyCollectedDataTypeLinked`、`NSPrivacyCollectedDataTypeTracking`、
  `NSPrivacyCollectedDataTypePurposes`、`NSPrivacyAccessedAPITypes`、`NSPrivacyAccessedAPITypeReasons`、
  `NSPrivacyAccessedAPICategoryFileTimestamp`、`NSPrivacyAccessedAPICategorySystemBootTime`、
  `NSPrivacyAccessedAPICategoryDiskSpace`、`NSPrivacyAccessedAPICategoryActiveKeyboards`、
  `NSPrivacyAccessedAPICategoryUserDefaults`、`NSPrivacyTracking`、`NSPrivacyTrackingDomains`、
  `Data Used to Track You`、`Data Linked to You`、`Data Not Linked to You`、App Privacy answer source、
  third-party SDK privacy manifest、SDK signature、`platform.ios.privacy_manifest.accessed_api_reason_missing`、
  `platform.ios.privacy_manifest.app_privacy_answers_missing`、`plutil`、`macos-26`、no PrivacyInfo.xcprivacy、
  no TestFlight upload 和 no iOS release asset。
- 仓库仍不包含真实 `PrivacyInfo.xcprivacy`、Swift source、`Package.swift`、Xcode project、workspace、
  Network Extension target、signing material、Provisioning Profile、TestFlight upload job 或 iOS release asset。

后续出现 iOS source tree 或 manifest 文件时，验证只能在 GitHub Actions `macos-26` runner 中执行：

- `plutil` 或 Apple toolchain manifest lint 只在 GitHub Actions 中运行。
- `swift build`、`swift test` 和 `xcodebuild` 只在 GitHub Actions runner 执行。
- source scan 必须校验 manifest path、target owner、required-reason API inventory、App Privacy answer source 和
  third-party SDK privacy manifest。
- upload workflow 必须继续等待独立 upload/release contract、manual intervention marker 和 protected environment。

## Acceptance Criteria

本 contract 增量完成时必须满足：

- README、ROADMAP、TODO、CHANGELOG、CI/CD policy 和 release strategy 同步记录本文件。
- `.github/workflows/ci.yml` 检查本文件存在和关键锚点。
- 相关 iOS readiness/design/source contract 指向本 Privacy Manifest source contract。
- `docs/manual-intervention.md` 保留 App Privacy、privacy policy、Required Reason API review 和 VPN compliance 人工事项。
- 不新增 Swift source、`Package.swift`、`.xcodeproj`、`.xcworkspace`、Network Extension target、
  `PrivacyInfo.xcprivacy`、Provisioning Profile、signing config、TestFlight upload、App Store upload 或 iOS release asset。
- Linux artifact 继续等待 license/NOTICE confirmed marker；期间不得定义 `package-linux` 或发布 release asset。

## Release Boundary

本合同不允许发布 iOS artifact。iOS release workflow 在以下条件满足前不得定义 TestFlight upload、App Store
upload、App Review submission 或 iOS release asset：

- 本合同和相关 iOS contracts 已通过 GitHub Actions static governance。
- 真实 Swift/Xcode bridge、Network Extension target、embedded runtime、certificate lifecycle、entitlement/provisioning
  和 `PrivacyInfo.xcprivacy` source 已在 GitHub Actions `macos-26` runner 通过验证。
- App Privacy answer source、privacy policy URL、App Review Notes、demo account、review attachment、TestFlight group、
  App Store Connect app record、export compliance、beta app review、App Review submission 和 VPN compliance materials
  已按 App Review manual confirmation source contract 完成人工确认。
- third-party SDK privacy manifest、SDK signature、Required Reason API inventory、tracking policy 和 secret redaction
  已有源码合同测试或 CI static gate。

Linux artifact 发布继续受 license/NOTICE confirmed marker、`package-linux` preflight 和后续 artifact gates 阻断。

## References

- Apple Developer Documentation: Privacy manifest files,
  `https://developer.apple.com/documentation/bundleresources/privacy_manifest_files`
- Apple Developer Documentation: Describing use of required reason API,
  `https://developer.apple.com/documentation/bundleresources/privacy_manifest_files/describing_use_of_required_reason_api`
- Apple Developer: App privacy details on the App Store,
  `https://developer.apple.com/app-store/app-privacy-details/`
- Apple Developer Support: Third-party SDK requirements,
  `https://developer.apple.com/support/third-party-SDK-requirements/`
