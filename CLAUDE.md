# Claude Instructions

本项目的统一代理规范见 [AGENT.md](AGENT.md)。

Claude 或其他 AI 编码助手在本仓库工作时必须遵守：

- 只在本机编辑代码、文档和 workflow。
- 不在本机执行测试、构建、编译、打包或发布。
- 通过 GitHub Actions 触发和观察所有验证结果。
- 将无法自动完成的事项记录到 `docs/manual-intervention.md`。
- 推送后只对当前 commit 的 run 做一次、最多两次非阻塞查询；不得使用 `gh run watch`、无限循环或长时间轮询。
- `queued`/`in_progress` 时记录 commit SHA、workflow、run ID、run URL 和状态，以 `task_state: pending_ci`、`next_action: resume_after_ci_completion` 交接后结束当前回合。
- 失败时只读取失败 job/step 日志；只有对应 run `completed` 且 `success` 时才能声称 CI 通过。
