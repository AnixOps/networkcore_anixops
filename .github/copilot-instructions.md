# Copilot Instructions

本项目主规范见 [AGENT.md](../AGENT.md)。

关键规则：

- 本机只负责代码和文档编写。
- 测试、构建、编译、打包、发布验证全部由 GitHub Actions 执行。
- 不建议生成任何要求开发者在本机运行测试或构建的说明。
- 需要人工处理的外部系统事项应记录到 `docs/manual-intervention.md`。
- 推送后只对当前 commit 的 run 做一次、最多两次非阻塞查询；禁止 `gh run watch`、无限循环和长时间轮询。
- `queued`/`in_progress` 时记录 commit SHA、workflow、run ID、run URL 和状态；`pending_ci` 只是状态记录，不是停止条件，不等待、不轮询、不重复读取未变化文件，继续不依赖 CI 的后续工作。
- CI 失败时只读取失败 job/step 日志；只有对应 run `completed` 且 `success` 才能声明验证通过。

CI 根据本次提交的修改范围选择验证任务：纯文档不构建所有平台，Linux 专属修改只运行 Linux 验证，Windows 专属修改只运行 Windows 验证，共享代码或 workflow 变化运行完整矩阵。

`pending_ci` 只是状态记录，不是停止条件。`queued`/`in_progress` 时不等待、不轮询、不重复读取未变化文件或重复输出状态，继续不依赖该 run 的后续工作；只有明确 `failure` 才暂停新增功能并读取失败 job/step 日志。
