# Contributing

## 基本原则

本项目不接受本地测试或本地构建作为有效验证结果。所有验证必须来自 GitHub Actions。

贡献者和自动化代理应遵守：

- 本机只编辑代码、文档、配置和 workflow。
- 不在本机运行测试、构建、编译、打包、发布命令。
- 每次变更通过 GitHub Actions 验证。
- CI/CD 失败时，只根据 GitHub Actions 日志修复。

## 推荐流程

1. 创建功能分支。
2. 修改代码或文档。
3. 查看 `git diff`，确认没有无关变更。
4. 提交并推送分支。
5. 记录当前 commit 的 GitHub Actions run；自动化代理按 `AGENT.md` 使用非阻塞 `pending_ci` 交接，不持续轮询。
6. 根据 CI/CD 日志修复问题。
7. CI/CD 通过后再合并。

## 许可证与签署（DCO）

本仓库以 Apache-2.0 发布（见 `LICENSE`）。提交到本仓库的贡献按 Apache-2.0 第 5 条以同一许可证授权，不需要另签 CLA。

每个 commit 需要按 [Developer Certificate of Origin 1.1](https://developercertificate.org/) 签署，在提交信息末尾加上：

```
Signed-off-by: 你的名字 <你的邮箱>
```

使用 `git commit -s` 会自动添加。签署表示你有权以 Apache-2.0 提交这段代码。

不要提交与 Apache-2.0 不兼容的代码或依赖（例如 GPL、AGPL、SSPL 或源码可见类许可证）。新增 Rust 依赖必须通过 `deny.toml` 的许可证检查；如需放宽白名单，在 PR 中单独说明理由。

NetworkCore、AnixOps 的名称和图标不在 Apache-2.0 授权范围内（Apache-2.0 第 6 条）。

## Pull Request 要求

PR 应说明：

- 本次改动目标
- 影响范围
- 对应的 GitHub Actions 运行结果
- 是否存在需要人工介入的事项

如果 GitHub Actions 无法运行，必须在 `docs/manual-intervention.md` 记录阻塞原因。

## 禁止事项

禁止把本地测试、构建或打包结果作为合并依据。禁止提交本地构建产物，除非它是明确需要版本化的源码资产。
