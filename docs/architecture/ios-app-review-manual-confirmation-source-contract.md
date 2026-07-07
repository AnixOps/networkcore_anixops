# iOS App Review Manual Confirmation Source Contract

本文件定义 iOS 进入 TestFlight、App Store Connect、beta app review 或 App Review submission 前，
人工确认事项的机器可读 source contract。它承接
[iOS App Review Privacy Release Readiness Design](ios-app-review-privacy-release-readiness-design.md)、
[iOS Privacy Manifest Source Contract](ios-privacy-manifest-source-contract.md)、
[iOS Entitlement Provisioning Source Contract](ios-entitlement-provisioning-source-contract.md)、
[iOS Network Extension Design](ios-network-extension-design.md) 和
[iOS Platform Risk Assessment](ios-platform-risk-assessment.md)。

当前状态：contract-only。仓库仍不包含 Swift source、`Package.swift`、Xcode project、Network Extension
target、`PrivacyInfo.xcprivacy`、App Store Connect 配置导出、App Privacy answers、privacy policy URL、
App Review Notes、demo account、review attachment、Provisioning Profile、真实签名、TestFlight upload job、
App Store upload job 或 iOS release asset；当前状态明确为 no PrivacyInfo.xcprivacy、no TestFlight upload
和 no iOS release asset。本地仍不得运行 `swift build`、`swift test`、`xcodebuild`、签名、打包、上传或发布验证。

## Goals

- 固定 App Privacy answers、privacy policy URL、App Review Notes、demo account、demo mode、review attachment、
  VPN compliance marker、TestFlight group 和 App Store Connect app record 的机器可读 marker。
- 定义 export compliance、encryption declaration、beta app review 和 App Review submission 的人工确认边界。
- 约束 `docs/manual-intervention.md` 作为当前阶段的 safe marker source of truth。
- 为未来 GitHub Actions `macos-26` 上的 App Review manual confirmation static gate 和 upload workflow gate
  提供 fail closed 入口。
- 继续阻止 Swift/Xcode project、Network Extension target、真实 signing、TestFlight upload、App Store upload
  或 iOS release asset 过早进入仓库。

## Non-Goals

- 不新增 Swift source、Xcode project、Network Extension target、`PrivacyInfo.xcprivacy` 或 Apple project 文件。
- 不回答、导出或提交 App Store Connect App Privacy answers。
- 不创建或发布 privacy policy URL、App Review Notes、review attachment、demo account、demo mode 或 VPN 合规材料。
- 不配置 TestFlight group、external tester、beta app review、export compliance、App Review submission 或 App Store Connect app record。
- 不启用 TestFlight upload、App Store upload、signing、notarization 或 iOS release asset。
- 不提供法律意见；VPN 牌照、地区销售限制、隐私政策文本和出口合规判断必须由人工或法律/合规 owner 确认。

## Manual Confirmation Source

当前阶段的 source of truth 是 `docs/manual-intervention.md` 中的机器可读 marker。未来可以迁移到
`apps/ios/Release/AppReviewManualConfirmation.md` 或等价机器可读文件，但迁移必须先更新本合同和 CI anchors。

最小 marker schema：

```text
ios-app-review-manual-confirmation-status=pending|confirmed
ios-app-review-manual-confirmation-source-contract=docs/architecture/ios-app-review-manual-confirmation-source-contract.md
ios-app-review-app-privacy-answers=pending|confirmed|blocked
ios-app-review-privacy-policy-url=pending|confirmed|blocked
ios-app-review-notes=pending|confirmed|blocked
ios-app-review-demo-account=pending|confirmed|not-required|blocked
ios-app-review-demo-mode=pending|confirmed|not-required|blocked
ios-app-review-review-attachment=pending|confirmed|not-required|blocked
ios-app-review-vpn-compliance=pending|confirmed|blocked
ios-app-review-testflight-group=pending|confirmed|blocked
ios-app-review-app-store-connect-app-record=pending|confirmed|blocked
ios-app-review-export-compliance=pending|confirmed|blocked
ios-app-review-beta-app-review=pending|confirmed|blocked
ios-app-review-app-review-submission=pending|confirmed|blocked
ios-app-review-testflight-upload=blocked|enabled
ios-app-review-release-assets=blocked|enabled
ios-app-review-confirmed-at=YYYY-MM-DD|pending
ios-app-review-confirmed-by=redacted-owner-or-role|pending
```

规则：

- `ios-app-review-manual-confirmation-status=confirmed` 前，`ios-app-review-testflight-upload` 必须保持 `blocked`。
- `ios-app-review-release-assets` 在真实 iOS release workflow、signing、upload 和 App Review submission gate
  完成前必须保持 `blocked`。
- `confirmed-by` 只能记录角色或脱敏 owner，不得记录私人邮箱、Apple ID、tester email、账号 token 或 App Store Connect API key。
- 任何 marker 缺失、未知值或 pending/blocked 状态都必须被未来 upload/release workflow 视为 fail closed。
- 从 `pending` 切换到 `confirmed` 必须是独立人工确认提交；同一提交不得同时启用 TestFlight upload 或 iOS release asset。

## Required Manual Inputs

| Marker | Owner | Required before |
| --- | --- | --- |
| `ios-app-review-app-privacy-answers` | release owner + privacy owner | TestFlight external testing 或 App Store submission |
| `ios-app-review-privacy-policy-url` | privacy owner | App Store Connect metadata 完成 |
| `ios-app-review-notes` | release owner | 每次 App Review submission |
| `ios-app-review-demo-account` | release owner | 需要登录才能复现核心能力时 |
| `ios-app-review-demo-mode` | release owner | 不提供真实 demo account 时 |
| `ios-app-review-review-attachment` | release owner | VPN/MITM 审核说明需要附件时 |
| `ios-app-review-vpn-compliance` | legal/compliance owner | 目标地区开放或 App Review submission |
| `ios-app-review-testflight-group` | release owner | TestFlight 初次分发 |
| `ios-app-review-app-store-connect-app-record` | release owner | upload workflow 激活 |
| `ios-app-review-export-compliance` | release owner + legal/compliance owner | build 分发或提交审核 |
| `ios-app-review-beta-app-review` | release owner | 外部 TestFlight 分发 |
| `ios-app-review-app-review-submission` | release owner | App Store submission |

自动化只能检查 marker、文档和 safe status；不能代表人工完成 Apple 控制台、法律判断、隐私政策发布或审核材料维护。

## App Privacy And Privacy Policy Confirmation

App Privacy answers 必须与以下来源一致：

- [iOS Privacy Manifest Source Contract](ios-privacy-manifest-source-contract.md) 中的 App Privacy answer source。
- `PrivacyInfo.xcprivacy`、`NSPrivacyCollectedDataTypes`、`NSPrivacyAccessedAPITypes` 和 Required Reason API inventory。
- privacy policy URL、App Review Notes、VPN 数据处理说明、MITM default off 策略和 diagnostics/logging 边界。

`ios-app-review-app-privacy-answers=confirmed` 只表示人工已在 App Store Connect 或 Apple 官方流程中确认
answers；它不表示仓库可以自动上传。`ios-app-review-privacy-policy-url=confirmed` 只允许记录公开 URL 已可用、
版本已确认和 owner 已确认；仓库不得保存未发布隐私政策草稿中的私人联系信息、法律意见或用户数据样本。

缺失 App Privacy answers 或 privacy policy URL 时，未来 upload workflow 必须输出
`platform.ios.app_review_manual_confirmation.missing` 或
`platform.ios.app_review_manual_confirmation.pending`。

## App Review Notes, Demo Account, And Attachment

App Review Notes 必须覆盖：

- `Packet Tunnel Provider`、`Network Extension` 和 VPN tunnel 的用途。
- VPN 数据默认本地处理、最小日志、无出售或复用用户流量数据。
- MITM default off、certificate installation、full trust、revocation、expiration 和 fingerprint 展示路径。
- 远程脚本策略：iOS 首版不执行任意远程脚本，远程内容仅作为数据化规则或清单。
- demo account 或 demo mode、sample configuration、review attachment 和复现步骤。
- App Privacy answers、privacy policy URL 和 VPN compliance marker 已确认。

demo account 或 demo mode 必须让 reviewer 能复现 VPN 配置、启动、停止、错误展示和证书说明路径。review attachment
可以是截图、短视频、测试配置或合规说明，但不得包含 signing secret、Provisioning Profile、private key、
真实用户账号、subscription secret、完整流量内容、未脱敏日志或 tester email 列表。

## VPN Compliance Marker

`ios-app-review-vpn-compliance=confirmed` 只能在人工或法律/合规 owner 确认以下事项后设置：

- Apple Developer Program 组织账号、App ID、Bundle ID、Network Extension capability 和 Provisioning Profile
  已确认。
- 目标销售地区的 VPN license、备案、企业资质、local representative、出口合规或额外说明已确认。
- 不能确认的地区保持不可发布状态，App Store Connect territory 和 release notes 不暗示已获许可。
- 如产品区分个人、企业、教育或 managed distribution，已分别评估 disclosure、license 和 App Review Notes。

CI 不能证明 VPN 合规，只能读取 `pending|confirmed|blocked` marker。未知或 pending 时必须保持 release blocked。

## TestFlight And App Store Connect Confirmation

TestFlight group、App Store Connect app record、export compliance、encryption declaration、beta app review 和
App Review submission 仍属于 manual confirmation：

- App Store Connect app record、Bundle ID 绑定、category、age rating、privacy policy URL 和 App Privacy answers
  由人工完成。
- TestFlight internal/external group、tester invite、beta review information、export compliance 和 encryption declaration
  由人工确认。
- 外部 TestFlight 分发前必须确认 beta app review 所需信息；App Store submission 前必须确认 App Review Notes。
- App Store Connect API key 只能在独立 upload workflow source contract 完成后使用。
- 当前不定义 TestFlight upload、App Store upload、App Review submission 或 iOS release asset。

未来 upload workflow 必须在同一 GitHub Actions run 中读取 marker，并且在任一 marker 为 pending、blocked 或缺失时
拒绝 upload。

## Secret And Diagnostic Redaction

manual confirmation marker、CI log、Step Summary 和 diagnostics 不得包含：

- Apple ID、App Store Connect API key、issuer id secret、private key、session token 或 upload credential。
- Team ID secret、Provisioning Profile UUID、certificate fingerprint secret、`.p12`、`.cer`、`.key`、`.pem` 内容。
- demo account password、tester email、真实用户账号、subscription URL、account token 或 support ticket private content。
- privacy policy 未发布草稿、法律意见全文、VPN license 私密编号、完整流量内容或未脱敏日志。

未来稳定 diagnostics source：

- `platform.ios.app_review_manual_confirmation`

未来稳定 diagnostic code：

- `platform.ios.app_review_manual_confirmation.missing`
- `platform.ios.app_review_manual_confirmation.pending`
- `platform.ios.app_review_manual_confirmation.blocked`
- `platform.ios.app_review_manual_confirmation.invalid_marker`
- `platform.ios.app_review_manual_confirmation.secret_detected`
- `platform.ios.app_review_manual_confirmation.upload_blocked`

diagnostic message 只能输出 safe status、marker key、redacted owner role 和 next action。

## GitHub Actions Static Gate

当前 `.github/workflows/ci.yml` 只做 Repository policy static gate：

- 检查本文件存在，标题为 `iOS App Review Manual Confirmation Source Contract`。
- 检查 `App Review Notes`、`manual confirmation`、`machine-readable marker`、`App Privacy answers`、
  `privacy policy URL`、`demo account`、`demo mode`、`review attachment`、`VPN compliance marker`、
  `TestFlight group`、`App Store Connect app record`、`export compliance`、`beta app review`、
  `encryption declaration`、`App Review submission`、`manual intervention`、`GitHub Actions`、`macos-26`、
  no PrivacyInfo.xcprivacy、no TestFlight upload 和 no iOS release asset。
- 检查 `docs/manual-intervention.md` 包含 `ios-app-review-manual-confirmation-status=pending`、
  `ios-app-review-manual-confirmation-source-contract=docs/architecture/ios-app-review-manual-confirmation-source-contract.md`、
  `ios-app-review-testflight-upload=blocked` 和 `ios-app-review-release-assets=blocked`。
- 检查当前仓库仍不包含 `PrivacyInfo.xcprivacy`、Swift/Xcode project、Network Extension target、signing material、
  Provisioning Profile、TestFlight upload job 或 iOS release asset。

后续出现 iOS upload workflow 时，验证只能在 GitHub Actions 或 Apple 官方平台执行：

- `swift build`、`swift test` 和 `xcodebuild` 只允许在 GitHub Actions runner 执行。
- App Store Connect API、TestFlight upload、export compliance 和 App Review submission 只能在受保护环境中执行。
- Upload workflow 必须先完成独立 source contract、manual approval、protected environment 和 explicit release gate。

## Release Boundary

本合同不允许发布 iOS artifact。iOS release workflow 在以下条件满足前不得定义 TestFlight upload、App Store
upload、App Review submission 或 iOS release asset：

- 本合同和相关 iOS contracts 已通过 GitHub Actions static governance。
- `docs/manual-intervention.md` 的 iOS App Review manual confirmation marker 已从 `pending` 独立切换到
  `confirmed`，且 upload/release blocked marker 已由独立 upload workflow source contract 解除。
- 真实 Swift/Xcode bridge、Network Extension target、embedded runtime、certificate lifecycle、entitlement/provisioning
  和 `PrivacyInfo.xcprivacy` source 已在 GitHub Actions `macos-26` runner 通过验证。
- App Privacy answers、privacy policy URL、App Review Notes、demo account 或 demo mode、review attachment、
  TestFlight group、App Store Connect app record、export compliance、beta app review、App Review submission 和
  VPN compliance materials 已完成人工确认。
- GitHub Secrets、signing asset redaction、App Store Connect API key、protected environment、manual approval 和
  upload workflow source contract 已完成。

Linux artifact 发布继续受 license/NOTICE confirmed marker、`package-linux` preflight 和后续 artifact gates 阻断；本合同不得被解释为允许发布 Linux 或 iOS release asset。

## Acceptance Criteria

本 contract 增量完成时必须满足：

- README、ROADMAP、TODO、CHANGELOG、CI/CD policy 和 release strategy 同步记录本文件。
- `.github/workflows/ci.yml` 检查本文件存在、关键锚点和 `docs/manual-intervention.md` marker。
- `docs/manual-intervention.md` 明确 iOS App Review manual confirmation pending/blocked marker。
- 相关 iOS readiness/design/source contract 指向本 manual confirmation source contract，后续工作推进到
  TestFlight/App Store Connect upload workflow source contract。
- 不新增 Swift source、`Package.swift`、`.xcodeproj`、`.xcworkspace`、Network Extension target、
  `PrivacyInfo.xcprivacy`、Provisioning Profile、signing config、TestFlight upload、App Store upload 或 iOS release asset。
- Linux artifact 继续等待 license/NOTICE confirmed marker；期间不得定义 `package-linux` 或发布 release asset。

## References

- Apple App Review Guidelines, `https://developer.apple.com/app-store/review/guidelines/`
- Apple Developer: App privacy details on the App Store, `https://developer.apple.com/app-store/app-privacy-details/`
- Apple Developer Documentation: Privacy manifest files, `https://developer.apple.com/documentation/bundleresources/privacy_manifest_files`
- Apple Developer Documentation: Describing use of required reason API,
  `https://developer.apple.com/documentation/bundleresources/privacy_manifest_files/describing_use_of_required_reason_api`
- Apple Developer Account Help: Provisioning with capabilities, `https://developer.apple.com/help/account/reference/provisioning-with-managed-capabilities/`
- Apple Developer Help: TestFlight overview, `https://developer.apple.com/help/app-store-connect/test-a-beta-version/testflight-overview/`
