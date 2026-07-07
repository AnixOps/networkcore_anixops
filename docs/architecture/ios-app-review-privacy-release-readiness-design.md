# iOS App Review Privacy Release Readiness Design

本文件定义 iOS 进入 TestFlight、App Store Connect 或 App Review 前必须满足的 privacy 和审核准备边界。它承接
[iOS Platform Risk Assessment](ios-platform-risk-assessment.md)、
[iOS Network Extension Design](ios-network-extension-design.md)、
[iOS Swift Xcode Bridge Source Contract](ios-swift-xcode-bridge-source-contract.md)、
[iOS Embedded Runtime FFI Boundary Design](ios-embedded-runtime-ffi-boundary-design.md)、
[iOS MITM Certificate Lifecycle Design](ios-mitm-certificate-lifecycle-design.md) 和
[iOS Entitlement Provisioning Source Contract](ios-entitlement-provisioning-source-contract.md)、
[iOS Privacy Manifest Source Contract](ios-privacy-manifest-source-contract.md)。

当前状态：design-only。仓库仍不包含 Swift source、`Package.swift`、Xcode project、Network Extension target、
`PrivacyInfo.xcprivacy`、App Store Connect 配置、App Privacy 问卷、privacy policy URL、App Review Notes、
TestFlight upload job、App Store upload job、真实签名、Provisioning Profile 或 iOS release asset；当前状态明确为
no TestFlight upload 和 no iOS release asset。本地仍不得运行 `swift build`、`swift test`、`xcodebuild`、签名、
打包、上传或发布验证。

## Goals

- 固定 iOS 发布前 Privacy Manifest、App Privacy、隐私政策和 App Review Notes 的输入来源。
- 定义 VPN compliance、MITM default off、certificate installation、review attachment、demo account 和 TestFlight
  人工确认边界。
- 约束 `Packet Tunnel Provider`、`Network Extension`、VPN 数据处理、日志保留和 App Store Connect disclosure
  如何保持一致。
- 为未来 GitHub Actions `macos-26` 上的 privacy manifest static validation、App Review readiness static gate 和
  upload 前检查提供入口。
- 继续阻止 Swift/Xcode project、Network Extension target、真实 signing、TestFlight upload、App Store upload 和
  iOS release asset 过早进入仓库。

## Non-Goals

- 不新增 `PrivacyInfo.xcprivacy`、Swift source、Xcode project、Network Extension target、UI 或 Apple project 文件。
- 不回答或提交 App Store Connect App Privacy 问卷。
- 不创建 privacy policy URL、App Review Notes、review attachment、demo account 或地区 VPN compliance 材料。
- 不启用 TestFlight、App Store Connect upload、App Review submission、signing、notarization 或 iOS release asset。
- 不提供法律意见；VPN 牌照、地区销售限制和隐私政策文本必须由人工或法律/合规 owner 确认。

## Readiness Inputs

以下输入必须在 iOS upload 或 App Review submission 前由人工确认，并记录到 `docs/manual-intervention.md` 或后续
source contract 指定的机器可读 marker：

| Input | Owner | Required before upload |
| --- | --- | --- |
| Privacy Manifest 字段来源 | iOS source owner | `PrivacyInfo.xcprivacy` 加入前 |
| App Privacy answers | release owner + privacy owner | TestFlight external testing 或 App Store submission 前 |
| privacy policy URL | privacy owner | App Store Connect metadata 完成前 |
| App Review Notes | release owner | 每次 App Review submission 前 |
| VPN compliance materials | legal/compliance owner | 目标地区开放前 |
| demo account 或 demo mode | release owner | 审核可复现前 |
| review attachment | release owner | 涉及 VPN/MITM 审核说明时 |
| TestFlight group | release owner | TestFlight 初次分发前 |
| App Store Connect app record | release owner | upload workflow 激活前 |

自动化只能检查这些输入是否有约定 marker、文档或 safe status；不能代表人工完成 Apple 控制台、法律判断或隐私政策发布。

## Privacy Manifest Contract

未来 `PrivacyInfo.xcprivacy` 只能随真实 iOS source tree 一起加入，默认位置为：

```text
apps/ios/Sources/NetworkCoreApp/PrivacyInfo.xcprivacy
apps/ios/Sources/NetworkCorePacketTunnel/PrivacyInfo.xcprivacy
```

加入前必须先完成独立 source contract，至少固定：

- `NSPrivacyCollectedDataTypes` 的来源、用途、linked status、tracking status 和 retention policy。
- `NSPrivacyAccessedAPITypes` 与每个 Required Reason API 的调用来源、reason code 和 test coverage。
- `NSPrivacyTracking` 和 `NSPrivacyTrackingDomains` 的默认值；当前策略为不跟踪，除非未来有单独审核合同。
- 主 App 与 `Packet Tunnel Provider` 是否需要分别声明 manifest，以及 third-party SDK manifest 的聚合规则。
- `PrivacyInfo.xcprivacy` 不得包含 secret、Bundle ID secret、Team ID、Provisioning Profile UUID、API key、
  certificate payload、subscription URL、account token 或用户流量样本。

当前仓库不得提交 `PrivacyInfo.xcprivacy`。后续如果加入 manifest，必须只在 GitHub Actions `macos-26` runner
中使用 Apple toolchain 或等价静态校验；本地仍不得运行 Apple build/test/validation 命令。

## App Privacy Disclosure Contract

App Store Connect 的 App Privacy disclosure 必须与代码、Privacy Manifest、隐私政策和 App Review Notes 一致。
发布前必须显式回答以下维度：

- `Data Used to Track You`：当前目标为 no tracking；任何广告追踪、跨 app/site 追踪或 tracking domain 都必须先有
  单独风险评审。
- `Data Linked to You`：账号、订阅、设备标识、purchase/account 状态、support contact 或诊断如与用户身份关联，
  必须在 disclosure 中声明。
- `Data Not Linked to You`：崩溃日志、性能指标、VPN 连接状态、功能使用统计如去标识化采集，也必须声明用途和保留期。
- VPN traffic：默认本地处理，不上传用户流量内容；如果未来上传连接日志、DNS 查询、domain metadata、proxy error
  或 traffic sample，必须先更新 App Privacy、privacy policy、App Review Notes 和 source contract。
- MITM traffic：MITM default off；仅用户显式启用并选择范围后处理。不得默认采集、上传或复用 decrypted content。
- diagnostics：GitHub Actions artifact、App Review attachment 和 support bundle 只能包含 safe diagnostic code、
  redacted state 和非 secret summary。

不能确定是否采集时必须按更保守的方式披露或阻止发布；不得为了通过审核而用不完整 disclosure 替代真实数据流审查。

## Privacy Policy Contract

公开 privacy policy URL 是 iOS 发布前置条件。隐私政策至少覆盖：

- NetworkCore 是 VPN/Network Extension 产品，说明 tunnel 处理的数据类型和目的。
- 账号、订阅、配置、节点、诊断、crash、support bundle 和日志的采集范围。
- VPN 数据默认本地处理，说明是否上传、保留多久、是否关联身份、是否第三方共享。
- MITM default off、certificate installation、用户 trust confirmation、撤销方式和 scope limitation。
- 远程规则、插件清单和脚本能力边界；iOS 首版不执行任意远程脚本。
- 用户删除、导出、撤回同意、关闭 MITM、删除证书和联系 privacy owner 的路径。
- 适用地区、VPN compliance 限制和不能确认地区默认不发布的策略。

隐私政策发布或更新属于 manual intervention；仓库只能记录 URL、版本、确认日期和下一步自动化动作。

## App Review Notes Contract

每次 App Review submission 前必须准备 App Review Notes，至少包含：

- `Packet Tunnel Provider` 和 `Network Extension` 用途：自定义 VPN tunnel，非 MDM，非绕过系统安全策略。
- VPN 数据处理：默认本地处理、最小日志、无出售或复用用户流量数据。
- MITM default off：只有用户显式启用并完成 certificate installation 和 trust confirmation 后才对选定范围生效。
- certificate installation、full trust、revocation、expiration 和 fingerprint 展示路径。
- 远程脚本策略：iOS 首版不执行任意远程脚本，远程内容仅作为数据化规则或清单。
- demo account、demo mode、sample configuration、review attachment 和复现步骤。
- App Privacy disclosure 与 privacy policy URL 已确认。
- 目标地区 VPN compliance 状态；不能确认的地区默认不开放。

review attachment 可以是截图、短视频、测试配置或合规说明，但不得包含 signing secret、Provisioning Profile、
private key、真实用户账号、subscription secret、完整流量内容或未脱敏日志。

## VPN Compliance Boundary

VPN compliance 是人工确认事项，不能由 CI 自动证明：

- 必须确认 Apple Developer Program 组织账号、Network Extension entitlement、App ID、Bundle ID 和 Provisioning Profile。
- 必须确认目标销售地区是否需要 VPN license、备案、企业资质、local representative 或额外说明。
- 不能确认地区必须保持不可发布状态；release notes 和 App Store Connect territory 不能暗示已获许可。
- 如果产品区分个人、企业、教育或 managed distribution，必须分别评估 disclosure、license 和 App Review Notes。
- 后续如加入 MDM、configuration profile 分发或企业管理能力，必须先新增独立风险评审。

## TestFlight And App Store Connect Manual Confirmation

TestFlight 和 App Store Connect 仍属于 manual intervention：

- App Store Connect app record、Bundle ID 绑定、category、age rating、privacy policy URL 和 App Privacy answers 由人工完成。
- TestFlight internal/external group、tester invite、beta review info、export compliance 和 encryption declaration 由人工确认。
- App Review Notes、demo account、review attachment 和 VPN compliance materials 由人工维护。
- GitHub Secrets 中的 App Store Connect API key 只能在独立 upload workflow contract 完成后使用。
- 当前不定义 TestFlight upload、App Store upload、App Review submission 或 iOS release asset。

自动化后续只能读取 safe marker，例如 `ios-app-review-privacy-status=confirmed`；缺失或 pending 时必须 fail closed。

## GitHub Actions Static Gate

当前 `.github/workflows/ci.yml` 只做 Repository policy static gate：

- 检查本文件存在，标题为 `iOS App Review Privacy Release Readiness Design`。
- 检查 `Privacy Manifest`、`PrivacyInfo.xcprivacy`、`NSPrivacyCollectedDataTypes`、`NSPrivacyAccessedAPITypes`、
  `Required Reason API`、`App Privacy`、`Data Used to Track You`、`Data Linked to You`、`Data Not Linked to You`、
  `privacy policy`、`App Review Notes`、`VPN compliance`、`App Store Connect`、`TestFlight`、
  `Packet Tunnel Provider`、`Network Extension`、`MITM default off`、`certificate installation`、`demo account`、
  `review attachment`、`manual intervention`、`GitHub Actions`、`macos-26`、no TestFlight upload 和
  no iOS release asset。
- 检查当前仓库仍不包含 `PrivacyInfo.xcprivacy`、Swift/Xcode project、Network Extension target、signing material、
  Provisioning Profile、TestFlight upload job 或 iOS release asset。

后续加入 iOS source 后，验证只能在 GitHub Actions 中运行：

- `swift build`、`swift test` 和 `xcodebuild` 只允许在 GitHub Actions runner 执行。
- Privacy Manifest static validation、plist lint、source scan 和 App Privacy answer source check 只允许在
  `macos-26` 或 Apple 官方平台执行。
- Upload workflow 必须有独立 design、manual intervention marker、protected environment 和 explicit approval。

## Release Boundary

iOS release workflow 在以下条件满足前不得定义 TestFlight upload、App Store upload、App Review submission 或 iOS
release asset：

- 本设计、iOS risk assessment、Network Extension design、Swift/Xcode bridge source contract、embedded runtime FFI
  boundary、MITM certificate lifecycle design、entitlement/provisioning source contract 和 Privacy Manifest source
  contract 已通过 CI static governance。
- 真实 Swift/Xcode bridge、Network Extension target、embedded runtime、certificate lifecycle、entitlement/provisioning
  和 Privacy Manifest source 已通过 GitHub Actions `macos-26` 验证。
- App Store Connect App Privacy answers、privacy policy URL、App Review Notes、demo account、review attachment、
  TestFlight group 和 VPN compliance materials 已完成人工确认。
- GitHub Secrets、signing asset redaction、App Store Connect API key 和 upload workflow source contract 已完成。

Linux artifact 发布继续受 license/NOTICE confirmed marker、`package-linux` preflight 和后续 artifact gates 阻断；本设计不得被解释为允许发布 Linux 或 iOS release asset。

## Acceptance Criteria

本设计增量完成时必须满足：

- README、ROADMAP、TODO、CHANGELOG、CI/CD policy 和 release strategy 同步记录本文件。
- `.github/workflows/ci.yml` 静态检查本文件存在和关键锚点。
- `docs/manual-intervention.md` 明确 App Privacy、privacy policy、App Review Notes、demo account、review attachment、
  TestFlight/App Store Connect 和 VPN compliance 人工事项。
- 相关 iOS docs 指向本 readiness design 和 Privacy Manifest source contract，后续工作推进到 App Review Notes/manual confirmation source contract。
- 不新增 Swift source、`Package.swift`、`.xcodeproj`、`.xcworkspace`、Network Extension target、
  `PrivacyInfo.xcprivacy`、Provisioning Profile、signing config、TestFlight upload、App Store upload 或 iOS release asset。
- Linux artifact 继续等待 license/NOTICE confirmed marker；期间不得定义 `package-linux` 或发布 release asset。

## References

- Apple App Review Guidelines, `https://developer.apple.com/app-store/review/guidelines/`
- Apple Developer Documentation: Privacy manifest files, `https://developer.apple.com/documentation/bundleresources/privacy_manifest_files`
- Apple Developer Documentation: Describing use of required reason API,
  `https://developer.apple.com/documentation/bundleresources/privacy_manifest_files/describing_use_of_required_reason_api`
- Apple Developer: App privacy details on the App Store, `https://developer.apple.com/app-store/app-privacy-details/`
- Apple Developer Documentation: Network Extension, `https://developer.apple.com/documentation/networkextension`
- Apple Developer Documentation: Packet Tunnel Provider, `https://developer.apple.com/documentation/networkextension/packet-tunnel-provider`
- Apple Developer Account Help: Provisioning with capabilities, `https://developer.apple.com/help/account/reference/provisioning-with-managed-capabilities/`
