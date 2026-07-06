# Manual Intervention List

本文件记录当前无法由本地自动化完成、需要人工处理的事项。

## 当前待处理

1. 当前目录最初不是 Git 仓库，需要人工确认是否要把 `/home/dev/anixops/networkcore_AnixOps` 初始化并绑定到目标 GitHub 仓库。
2. 需要人工提供或确认 GitHub 远端地址。
3. 需要人工确认 GitHub CLI 是否已登录到正确账号，或手动在 GitHub 网页端观察 Actions。
4. 首次 GitHub Actions 运行需要在文件推送到 GitHub 后触发。

## 人工完成后的下一步

完成 GitHub 仓库绑定并推送后，运行：

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
