# Agents

本文件用于兼容常见 AI 编码工具。项目主规范见 [AGENT.md](AGENT.md)。

必须遵守的最高优先级项目规则：

- 本机只负责代码和文档编写。
- 所有测试、构建、编译、打包、发布验证都必须在 GitHub Actions 中运行。
- 不得在本机运行本地测试或构建命令。
- 无法通过自动化完成的事项必须记录到 `docs/manual-intervention.md`。

开始任何任务前，请先阅读 [AGENT.md](AGENT.md) 和 [docs/ci-cd-policy.md](docs/ci-cd-policy.md)。
