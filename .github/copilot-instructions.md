# Copilot Instructions

本项目主规范见 [AGENT.md](../AGENT.md)。

关键规则：

- 本机只负责代码和文档编写。
- 测试、构建、编译、打包、发布验证全部由 GitHub Actions 执行。
- 不建议生成任何要求开发者在本机运行测试或构建的说明。
- 需要人工处理的外部系统事项应记录到 `docs/manual-intervention.md`。
- 推送后只对当前 commit 的 run 做一次、最多两次非阻塞查询；禁止 `gh run watch`、无限循环和长时间轮询。
- `queued`/`in_progress` 时记录 commit SHA、workflow、run ID、run URL 和状态，以 `task_state: pending_ci`、`next_action: resume_after_ci_completion` 交接并结束当前回合。
- CI 失败时只读取失败 job/step 日志；只有对应 run `completed` 且 `success` 才能声明验证通过。
