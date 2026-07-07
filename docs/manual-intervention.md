# Manual Intervention List

本文件记录当前无法由本地自动化完成、需要人工处理的事项。

## 当前待处理

- Linux artifact license/NOTICE 文本确认仍为 pending；完成前不得定义真实 `package-linux` artifact job、
  上传 workflow artifact 或发布 Linux release asset。
- iOS App Review manual confirmation 仍为 pending；完成前不得启用 TestFlight upload、App Store upload、
  App Review submission 或 iOS release asset。
- iOS TestFlight/App Store Connect upload workflow 仍为 pending；完成前不得执行 archive/export、
  TestFlight upload、App Store upload、App Review submission 或 iOS release asset。当前 release workflow 仅允许
  `ios-upload-readiness` blocked placeholder 读取这些 marker，输出 source tree preflight 和 safe summary。

## 已完成的人工/外部事项

1. 已确认 GitHub 远端地址：`https://github.com/AnixOps/networkcore_anixops.git`。
2. 已初始化本地仓库并绑定远端。
3. 已为 GitHub CLI 授权 `workflow` scope，使其可以推送 GitHub Actions workflow。
4. 已推送 bootstrap 文件并打通 CI。

## 后续 CI 观察命令

需要观察 CI 时运行：

```bash
gh workflow run ci.yml
gh run list --workflow ci.yml --limit 5
```

如果 GitHub CLI 不可用，可在 GitHub 网页端进入 `Actions`，选择 `CI`，手动触发 `workflow_dispatch`。

## 后续预计人工事项

后续涉及 iOS 时，还需要人工处理：

- Apple Developer Program 组织账号和账号角色确认
- App ID、Bundle ID、Network Extension capability、entitlement 与 Provisioning Profile 配置
- 证书、signing asset redaction 和 Provisioning Profile 轮换策略确认
- App Store Connect 或 TestFlight 初次配置、App Privacy 问卷、Privacy Manifest/Required Reason API review、privacy policy URL、TestFlight group 和 export compliance 确认
- GitHub Secrets 写入 Apple 相关凭据
- App Review Notes、demo account、review attachment、隐私政策和目标地区 VPN compliance/VPN 牌照材料确认

后续涉及真实 release artifact 时，还需要人工处理：

- 项目 license 或 artifact 内置许可/NOTICE 文本确认；完成前不得实现真实 `package-linux` artifact job 或发布 Linux release asset
- GitHub Environments、protected tags、branch protection 和 release approval policy 配置
- Windows 代码签名证书、时间戳服务和商店账号确认
- 第三方发布渠道账号、API token、税务或合规材料确认

## Linux Artifact License/NOTICE Confirmation

以下字段是 release readiness 读取的机器状态。当前仍未完成 license/NOTICE 人工确认，
因此 Linux artifact 发布保持阻断。

```text
linux-artifact-license-notice-status=pending
linux-artifact-license-notice-source-contract=docs/architecture/linux-artifact-license-notice-confirmation.md
linux-artifact-license-notice-package-linux=blocked
linux-artifact-license-notice-release-assets=blocked
```

人工确认完成前，不得实现真实 `package-linux` artifact job 或发布 Linux release asset。
未来从 pending 切换到 confirmed 时，必须遵守
`docs/architecture/linux-package-license-notice-transition-validation-contract.md` 中的独立提交、
字段和 LICENSE/NOTICE 文件存在性检查规则。

## iOS App Review Manual Confirmation

以下字段是后续 iOS upload/release readiness 读取的机器状态。当前仍未完成 App Privacy answers、
privacy policy URL、App Review Notes、demo account、review attachment、VPN compliance、TestFlight group、
App Store Connect app record、export compliance、beta app review 和 App Review submission 人工确认，
因此 iOS upload 和 release asset 发布保持阻断。

```text
ios-app-review-manual-confirmation-status=pending
ios-app-review-manual-confirmation-source-contract=docs/architecture/ios-app-review-manual-confirmation-source-contract.md
ios-app-review-app-privacy-answers=blocked
ios-app-review-privacy-policy-url=blocked
ios-app-review-notes=blocked
ios-app-review-demo-account=blocked
ios-app-review-demo-mode=blocked
ios-app-review-review-attachment=blocked
ios-app-review-vpn-compliance=blocked
ios-app-review-testflight-group=blocked
ios-app-review-app-store-connect-app-record=blocked
ios-app-review-export-compliance=blocked
ios-app-review-beta-app-review=blocked
ios-app-review-app-review-submission=blocked
ios-app-review-testflight-upload=blocked
ios-app-review-release-assets=blocked
ios-app-review-confirmed-at=pending
ios-app-review-confirmed-by=pending
```

人工确认完成前，不得定义 TestFlight upload、App Store upload、App Review submission 或 iOS release asset。
未来从 pending 切换到 confirmed 时，必须遵守
`docs/architecture/ios-app-review-manual-confirmation-source-contract.md` 中的独立人工确认提交、
字段、脱敏和 upload/release 阻断规则。

## iOS TestFlight/App Store Connect Upload Workflow

以下字段是后续 iOS release readiness 读取的机器状态。当前没有真实 Swift/Xcode source、signing、
archive/export、App Store Connect API、protected environment 或 manual approval，因此 upload/release 保持阻断。

```text
ios-upload-workflow-status=pending
ios-upload-workflow-source-contract=docs/architecture/ios-testflight-app-store-connect-upload-workflow-source-contract.md
ios-upload-workflow-archive-export=blocked
ios-upload-workflow-app-store-connect-api=blocked
ios-upload-workflow-protected-environment=blocked
ios-upload-workflow-manual-approval=blocked
ios-upload-workflow-testflight-upload=blocked
ios-upload-workflow-app-store-upload=blocked
ios-upload-workflow-app-review-submission=blocked
ios-upload-workflow-release-assets=blocked
ios-upload-workflow-macos-runner=blocked
ios-upload-workflow-build-processing-check=blocked
ios-upload-workflow-confirmed-at=pending
ios-upload-workflow-confirmed-by=pending
```

当前 workflow activation validation 仍是 blocked placeholder：`ios-upload-readiness` 只读取本节 marker、
检查 source contract、输出 source tree preflight、protected environment/manual approval/App Store Connect API secret status/
archive/export/upload/submission/release asset 的 blocked 状态，不读取 secret、不定义真实 upload job。

iOS Swift/Xcode source tree activation preflight 也保持 blocked：仓库只允许 `apps/ios/README.md` 作为 source tree
governance placeholder，仍没有真实 `apps/ios` Swift source tree、`Package.swift`、Swift source、Xcode project、
Network Extension target、`PrivacyInfo.xcprivacy`、entitlement/provisioning source 或 iOS release asset。
`ios-upload-workflow-status` 不得切换为 `enabled`，直到 source tree、manual confirmation、protected environment
和 secret setup 都按合同完成并通过 GitHub Actions。`Package.swift` source ownership preflight contract 已补充，当前
Package.swift ownership gate 仍是 blocked-placeholder；下一步 source tree gate 是补充 manifest-only activation
validation contract，仍不得新增真实 `Package.swift` 或 Swift source。

人工确认和 workflow activation enabled marker 完成前，不得定义 archive/export、TestFlight upload、App Store upload、
App Review submission 或 iOS release asset。未来从 pending 切换到 enabled 时，必须遵守
`docs/architecture/ios-testflight-app-store-connect-upload-workflow-source-contract.md` 和
`docs/architecture/ios-upload-workflow-activation-validation-contract.md`、
`docs/architecture/ios-swift-xcode-source-tree-activation-preflight-contract.md` 中的独立启用提交、protected environment、
manual approval、secret redaction、source tree gate 和 upload/release 阻断规则。
