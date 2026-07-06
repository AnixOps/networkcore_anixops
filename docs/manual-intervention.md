# Manual Intervention List

本文件记录当前无法由本地自动化完成、需要人工处理的事项。

## 当前待处理

当前 bootstrap 阶段无阻塞项。

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

- Apple Developer Program 账号确认
- App ID 与 Network Extension entitlement 配置
- 证书与 Provisioning Profile 配置
- App Store Connect 或 TestFlight 初次配置
- GitHub Secrets 写入 Apple 相关凭据
