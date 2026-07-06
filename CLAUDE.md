# Claude Instructions

本项目的统一代理规范见 [AGENT.md](AGENT.md)。

Claude 或其他 AI 编码助手在本仓库工作时必须遵守：

- 只在本机编辑代码、文档和 workflow。
- 不在本机执行测试、构建、编译、打包或发布。
- 通过 GitHub Actions 触发和观察所有验证结果。
- 将无法自动完成的事项记录到 `docs/manual-intervention.md`。
