# Manual Intervention List

本文件记录当前无法由本地自动化完成、需要人工处理的事项。

## 当前待处理

- Linux artifact license/NOTICE 文本确认仍为 pending；完成前不得定义真实 `package-linux` artifact job、
  上传 workflow artifact 或发布 Linux release asset。

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
- App Store Connect 或 TestFlight 初次配置
- GitHub Secrets 写入 Apple 相关凭据
- App Review Notes、隐私政策和目标地区 VPN 牌照材料确认

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
