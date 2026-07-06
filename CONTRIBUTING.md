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
5. 等待 GitHub Actions 运行。
6. 根据 CI/CD 日志修复问题。
7. CI/CD 通过后再合并。

## Pull Request 要求

PR 应说明：

- 本次改动目标
- 影响范围
- 对应的 GitHub Actions 运行结果
- 是否存在需要人工介入的事项

如果 GitHub Actions 无法运行，必须在 `docs/manual-intervention.md` 记录阻塞原因。

## 禁止事项

禁止把本地测试、构建或打包结果作为合并依据。禁止提交本地构建产物，除非它是明确需要版本化的源码资产。
