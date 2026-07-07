# iOS TestFlight App Store Connect Upload Workflow Source Contract

本文件定义后续 iOS archive/export、App Store Connect API、TestFlight group、manual approval、App Review
submission gate、GitHub Actions `macos-26` 验证入口和 release/upload 阻断的 source contract。它承接
[iOS Swift Xcode Bridge Source Contract](ios-swift-xcode-bridge-source-contract.md)、
[iOS Embedded Runtime FFI Boundary Design](ios-embedded-runtime-ffi-boundary-design.md)、
[iOS Entitlement Provisioning Source Contract](ios-entitlement-provisioning-source-contract.md)、
[iOS Privacy Manifest Source Contract](ios-privacy-manifest-source-contract.md)、
[iOS App Review Privacy Release Readiness Design](ios-app-review-privacy-release-readiness-design.md) 和
[iOS App Review Manual Confirmation Source Contract](ios-app-review-manual-confirmation-source-contract.md)，并由
[iOS Upload Workflow Activation Validation Contract](ios-upload-workflow-activation-validation-contract.md) 将当前 release
workflow placeholder summary、manual marker 读取和 blocked 输出接入 GitHub Actions。

当前状态：contract-only。仓库仍不包含 Swift source、`Package.swift`、Xcode project、Network Extension target、
`PrivacyInfo.xcprivacy`、ExportOptions.plist、`.ipa`、`.xcarchive`、`.xcresult`、dSYM bundle、App Store Connect
API key、TestFlight upload job、App Store upload job、App Review submission job、真实签名、Provisioning Profile
或 iOS release asset；当前状态明确为 no PrivacyInfo.xcprivacy、no TestFlight upload、no App Store upload、
no App Review submission 和 no iOS release asset。本地仍不得运行 `swift build`、`swift test`、`xcodebuild`、
`xcodebuild -archive`、`xcodebuild -exportArchive`、签名、打包、上传或发布验证。

## Goals

- 固定后续 iOS upload workflow 的 job 边界、runner、inputs、outputs、manual approval 和 protected environment。
- 定义 `xcodebuild archive`、`xcodebuild -exportArchive`、ExportOptions.plist、`.ipa`、`.xcarchive`、
  `.xcresult` 和 dSYM 的 future source ownership。
- 定义 App Store Connect API key、issuer id、private key、Team ID、Provisioning Profile 和 signing asset
  的 secret redaction 规则。
- 约束 TestFlight upload、App Store upload、App Review submission gate、build processing status、beta app review、
  export compliance 和 encryption declaration 的 release/upload 阻断。
- 为未来 GitHub Actions `macos-26` iOS upload static gate、release workflow placeholder summary 和 activation
  validation contract 提供入口。
- 继续阻止 Swift/Xcode project、Network Extension target、真实 signing、archive/export、TestFlight upload、
  App Store upload、App Review submission 或 iOS release asset 过早进入仓库。

## Non-Goals

- 不新增 Swift source、Xcode project、Network Extension target、`PrivacyInfo.xcprivacy`、ExportOptions.plist、
  `.ipa`、`.xcarchive`、`.xcresult`、dSYM bundle 或 Apple project 文件。
- 不创建、解码、上传或验证真实 Provisioning Profile、certificate、private key 或 App Store Connect API key。
- 不启用 `xcodebuild archive`、`xcodebuild -exportArchive`、TestFlight upload、App Store upload、
  App Review submission、notarization 或 iOS release asset。
- 不读取 App Store Connect 状态、不提交 beta app review、不提交 App Review，也不修改 TestFlight group。
- 不提供法律意见；export compliance、encryption declaration、VPN compliance 和地区可用性必须由人工或合规 owner 确认。

## Upload Workflow Source Markers

当前阶段的 source of truth 是 `docs/manual-intervention.md` 中的机器可读 marker。最小 marker schema：

```text
ios-upload-workflow-status=pending|enabled
ios-upload-workflow-source-contract=docs/architecture/ios-testflight-app-store-connect-upload-workflow-source-contract.md
ios-upload-workflow-archive-export=blocked|enabled
ios-upload-workflow-app-store-connect-api=blocked|enabled
ios-upload-workflow-protected-environment=blocked|enabled
ios-upload-workflow-manual-approval=blocked|enabled
ios-upload-workflow-testflight-upload=blocked|enabled
ios-upload-workflow-app-store-upload=blocked|enabled
ios-upload-workflow-app-review-submission=blocked|enabled
ios-upload-workflow-release-assets=blocked|enabled
ios-upload-workflow-macos-runner=blocked|enabled
ios-upload-workflow-build-processing-check=blocked|enabled
ios-upload-workflow-confirmed-at=YYYY-MM-DD|pending
ios-upload-workflow-confirmed-by=redacted-owner-or-role|pending
```

规则：

- `ios-upload-workflow-status=enabled` 前，所有 upload、submission 和 release asset marker 必须保持 `blocked`。
- `ios-app-review-manual-confirmation-status=confirmed` 前，`ios-upload-workflow-status` 必须保持 `pending`。
- 从 `pending` 切换到 `enabled` 必须是独立提交；同一提交不得同时新增真实 upload job、App Store Connect API call
  或 iOS release asset。
- `confirmed-by` 只能记录角色或脱敏 owner，不得记录 Apple ID、tester email、Team ID、issuer id、API key id、
  private key、certificate fingerprint、Provisioning Profile UUID 或账号 token。
- 任何 marker 缺失、未知值或 pending/blocked 状态都必须被未来 release workflow 视为 fail closed。

## Future Workflow Shape

后续真实 workflow 必须拆分为独立 job，不能把 signing、archive、upload、submission 和 publish 混在一个不可回滚步骤：

| Job | Runner | Responsibility | Current status |
| --- | --- | --- | --- |
| `ios-upload-readiness` | `ubuntu-latest` 或 `macos-26` | 读取 CI gate、manual marker、source contracts 和 protected environment 状态 | blocked |
| `ios-archive-export` | `macos-26` | 受控 signing、`xcodebuild archive`、`xcodebuild -exportArchive`、archive/export metadata | blocked |
| `ios-upload-testflight` | `macos-26` | 使用 Apple 官方上传路径或 App Store Connect API 辅助上传 build | blocked |
| `ios-build-processing-gate` | `macos-26` | 读取 App Store Connect build processing status、build number 和 safe metadata | blocked |
| `ios-app-review-submission-gate` | `macos-26` | 在 manual approval 后提交 App Review 或保持 submission blocked | blocked |
| `ios-release-summary` | `ubuntu-latest` | 输出 safe summary、rollback path、manual next action 和 release asset blocked 状态 | blocked |

真实 workflow 加入前必须先完成 activation validation contract，定义 placeholder summary、required needs、permissions、
environment、secrets、outputs、failure modes 和 rollback behavior。当前合同不允许直接新增上述 job。

## Archive And Export Contract

未来 `ios-archive-export` 只能在 GitHub Actions `macos-26` runner 中执行。最小命令形态必须由后续 activation
validation contract 固定，至少覆盖：

- `xcodebuild archive` 只能针对真实 Xcode project 或 workspace、明确 scheme、configuration、destination、
  archive path 和 derived data path 执行。
- `xcodebuild -exportArchive` 只能使用受控 ExportOptions.plist 或 CI 生成的等价文件，且不得提交包含 Team ID secret、
  signing certificate name、profile UUID、API key 或 private key 的 ExportOptions.plist。
- `.xcarchive`、`.ipa`、`.xcresult`、dSYM bundle 和 export logs 只能存在于 runner 临时目录或受控 workflow artifact；
  当前仓库不得提交这些文件。
- archive/export metadata 至少输出 app bundle id、packet tunnel bundle id、marketing version、build number、
  archive status、export status、ipa file name、checksum algorithm、checksum value 和 redacted signing status。
- 任何 archive/export 失败都必须停止 upload，不能 fallback 到本地产物、开发者机器产物或旧 workflow artifact。

当前仓库没有 iOS source tree，因此 archive/export remains blocked。

## App Store Connect API And Upload Contract

App Store Connect API 和上传凭据只能在 protected environment 中使用。后续至少需要以下 secret 或 environment input：

```text
APP_STORE_CONNECT_API_KEY_ID
APP_STORE_CONNECT_ISSUER_ID
APP_STORE_CONNECT_API_PRIVATE_KEY
TEAM_ID
APPLE_CERTIFICATE_P12_BASE64
APPLE_CERTIFICATE_PASSWORD
APPLE_KEYCHAIN_PASSWORD
APPLE_PROVISIONING_PROFILE_BASE64
APPLE_PACKET_TUNNEL_PROVISIONING_PROFILE_BASE64
```

建议的非 secret variable：

```text
APP_BUNDLE_ID
PACKET_TUNNEL_BUNDLE_ID
APP_STORE_CONNECT_APP_ID
TESTFLIGHT_GROUP_ID
IOS_UPLOAD_ENVIRONMENT_NAME
```

规则：

- App Store Connect API key、issuer id、private key、certificate、profile 和 temporary keychain 只能来自 GitHub
  Secrets、GitHub Environments 或 Apple 官方平台。
- CI 不得输出 secret value、decoded profile、private key、Team ID、Provisioning Profile UUID、certificate
  fingerprint secret、archive local absolute path、API response token 或 upload credential。
- Step Summary 只能输出 `present`、`missing`、`redacted`、`validated`、`blocked`、`uploaded` 或 `processing`
  等 safe status。
- Upload 必须绑定同一 release run 生成的 `.ipa` 和 checksum；不得上传旧 run、外部下载、本地产物或手工替换的 `.ipa`。
- App Store Connect API call 必须有重试上限、safe error mapping、rate limit handling 和 no secret log policy。

## TestFlight And App Review Gates

TestFlight upload、external testing、App Store upload 和 App Review submission 必须分开处理：

- TestFlight upload 只表示 build 已提交给 App Store Connect；不表示 beta app review、external testing 或 App Review 已通过。
- External TestFlight testing 需要 TestFlight group、beta app review information、export compliance 和 manual confirmation marker。
- Build processing status 必须由 App Store Connect 或 Apple 官方平台确认；unknown、processing、failed 或 expired
  状态必须保持 downstream gate blocked。
- App Review submission 只能在 manual approval、App Review Notes、privacy policy URL、App Privacy answers、
  export compliance、VPN compliance 和 release notes rollback path 已确认后触发。
- Future App Review submission gate 必须支持 hold-only 模式；默认只验证 readiness，不自动提交审核。

当前所有 TestFlight/App Store Connect upload 和 App Review submission 状态保持 blocked。

## Protected Environment And Approval

真实 iOS upload workflow 必须使用 protected environment：

- environment 名称建议为 `ios-app-store-connect`，实际名称必须由后续 activation validation contract 固定。
- environment 必须要求 manual approval 或等价 deployment protection rule。
- secret 只能作为 environment secret 暴露给需要的 job；readiness job 不得读取 upload secret value。
- `ios-archive-export` 可以使用 signing secret；`ios-upload-testflight` 可以使用 App Store Connect API secret；
  `ios-release-summary` 不得读取任何 signing 或 upload secret。
- 并发必须按 app id、version 和 target environment 限制，避免多个 upload run 写入同一个 App Store Connect build。

如果 protected environment、manual approval 或 required secret 缺失，future workflow 必须输出
`platform.ios.upload_workflow.protected_environment_missing` 或 `platform.ios.upload_workflow.secret_missing`，并停止。

## Secret And Artifact Redaction

禁止提交或上传到仓库的内容包括：

- `.ipa`、`.xcarchive`、`.xcresult`、dSYM bundle、ExportOptions.plist、DerivedData、temporary keychain 或 decoded profile。
- `.mobileprovision`、`.provisionprofile`、`.p12`、`.cer`、`.key`、`.pem`、App Store Connect private key、
  API token、session token 或 upload credential。
- Team ID secret、Provisioning Profile UUID、certificate fingerprint secret、Apple account identity、tester email、
  demo account password、subscription URL、account token、support private content 或 traffic sample。

未来 stable diagnostics source：

- `platform.ios.upload_workflow`

未来 stable diagnostic code：

- `platform.ios.upload_workflow.source_contract_missing`
- `platform.ios.upload_workflow.manual_confirmation_pending`
- `platform.ios.upload_workflow.protected_environment_missing`
- `platform.ios.upload_workflow.secret_missing`
- `platform.ios.upload_workflow.archive_export_blocked`
- `platform.ios.upload_workflow.upload_blocked`
- `platform.ios.upload_workflow.build_processing_unknown`
- `platform.ios.upload_workflow.app_review_submission_blocked`
- `platform.ios.upload_workflow.release_asset_blocked`

diagnostic message 只能输出 safe status、marker key、job name、redacted owner role 和 next action。

## GitHub Actions Static Gate

当前 `.github/workflows/ci.yml` 只做 Repository policy static gate：

- 检查本文件存在，标题为 `iOS TestFlight App Store Connect Upload Workflow Source Contract`。
- 检查 `archive/export`、`xcodebuild archive`、`xcodebuild -exportArchive`、ExportOptions.plist、`.ipa`、
  `.xcarchive`、`.xcresult`、dSYM bundle、App Store Connect API、TestFlight group、manual approval、
  protected environment、App Review submission gate、build processing status、beta app review、export compliance、
  encryption declaration、GitHub Actions、`macos-26`、no TestFlight upload、no App Store upload、
  no App Review submission 和 no iOS release asset。
- 检查 `docs/manual-intervention.md` 包含 `ios-upload-workflow-status=pending`、
  `ios-upload-workflow-source-contract=docs/architecture/ios-testflight-app-store-connect-upload-workflow-source-contract.md`、
  `ios-upload-workflow-archive-export=blocked`、`ios-upload-workflow-app-store-connect-api=blocked`、
  `ios-upload-workflow-protected-environment=blocked`、`ios-upload-workflow-manual-approval=blocked`、
  `ios-upload-workflow-testflight-upload=blocked`、`ios-upload-workflow-app-store-upload=blocked`、
  `ios-upload-workflow-app-review-submission=blocked`、`ios-upload-workflow-release-assets=blocked`、
  `ios-upload-workflow-macos-runner=blocked`、`ios-upload-workflow-build-processing-check=blocked`、
  `ios-upload-workflow-confirmed-at=pending` 和 `ios-upload-workflow-confirmed-by=pending`。
- 检查当前仓库仍不包含 `PrivacyInfo.xcprivacy`、Swift/Xcode project、Network Extension target、signing material、
  Provisioning Profile、ExportOptions.plist、`.ipa`、`.xcarchive`、`.xcresult`、dSYM bundle、TestFlight upload job、
  App Store upload job、App Review submission job 或 iOS release asset。

当前 activation validation contract 只允许修改 release workflow placeholder summary 和 `ios-upload-readiness` blocked
placeholder；真实 upload job 仍必须等 iOS source、signing、manual confirmation 和 protected environment 全部完成后独立启用。

## Release Boundary

本合同不允许发布 iOS artifact。iOS release workflow 在以下条件满足前不得定义 TestFlight upload、App Store
upload、App Review submission 或 iOS release asset：

- 本合同和相关 iOS contracts 已通过 GitHub Actions static governance。
- iOS upload workflow activation validation contract 已完成，并在 release workflow placeholder summary 中保持 blocked。
- 真实 Swift/Xcode bridge、Network Extension target、embedded runtime、certificate lifecycle、entitlement/provisioning
  和 `PrivacyInfo.xcprivacy` source 已在 GitHub Actions `macos-26` runner 通过验证。
- iOS App Review manual confirmation marker 已从 `pending` 独立切换到 `confirmed`。
- GitHub protected environment、manual approval、App Store Connect API key、signing asset redaction、secret cleanup、
  archive/export validation、build processing check 和 App Review submission hold-only gate 已完成。

Linux artifact 发布继续受 license/NOTICE confirmed marker、`package-linux` preflight 和后续 artifact gates 阻断；
本合同不得被解释为允许发布 Linux 或 iOS release asset。

## Acceptance Criteria

本 contract 增量完成时必须满足：

- README、ROADMAP、TODO、CHANGELOG、CI/CD policy 和 release strategy 同步记录本文件。
- `.github/workflows/ci.yml` 检查本文件存在、关键锚点和 `docs/manual-intervention.md` marker。
- `docs/manual-intervention.md` 明确 iOS upload workflow pending/blocked marker。
- 相关 iOS readiness/design/source contract 指向本 upload workflow source contract 和 activation validation contract，
  后续工作推进到 iOS Swift/Xcode source tree activation preflight contract。
- 不新增 Swift source、`Package.swift`、`.xcodeproj`、`.xcworkspace`、Network Extension target、
  `PrivacyInfo.xcprivacy`、ExportOptions.plist、`.ipa`、`.xcarchive`、`.xcresult`、dSYM bundle、Provisioning Profile、
  signing config、TestFlight upload、App Store upload、App Review submission 或 iOS release asset。
- Linux artifact 继续等待 license/NOTICE confirmed marker；期间不得定义 `package-linux` 或发布 release asset。

## References

- Apple Developer Help: Upload builds, `https://developer.apple.com/help/app-store-connect/manage-builds/upload-builds/`
- Apple Developer Documentation: Distributing your app for beta testing and releases,
  `https://developer.apple.com/documentation/xcode/distributing-your-app-for-beta-testing-and-releases`
- Apple Developer Documentation: App Store Connect API, `https://developer.apple.com/documentation/appstoreconnectapi`
- Apple Developer Help: TestFlight overview,
  `https://developer.apple.com/help/app-store-connect/test-a-beta-version/testflight-overview/`
- Apple Developer Help: Provide export compliance information for beta builds,
  `https://developer.apple.com/help/app-store-connect/test-a-beta-version/provide-export-compliance-information-for-beta-builds/`
- Apple Developer Help: Submit an app,
  `https://developer.apple.com/help/app-store-connect/manage-submissions-to-app-review/submit-an-app/`
- GitHub Docs: Managing environments for deployment,
  `https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments`
- GitHub Docs: Using secrets in GitHub Actions,
  `https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets`
