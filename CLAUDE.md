# Claude Instructions

本项目的统一代理规范见 [AGENT.md](AGENT.md)。

Claude 或其他 AI 编码助手在本仓库工作时必须遵守：

- 只在本机编辑代码、文档和 workflow。
- 不在本机执行测试、构建、编译、打包或发布。
- 通过 GitHub Actions 触发和观察所有验证结果。
- 将无法自动完成的事项记录到 `docs/manual-intervention.md`。
- 推送后只对当前 commit 的 run 做一次、最多两次非阻塞查询；不得使用 `gh run watch`、无限循环或长时间轮询。
- `queued`/`in_progress` 时记录 commit SHA、workflow、run ID、run URL 和状态；`pending_ci` 只是状态记录，不是停止条件，不等待、不轮询、不重复读取未变化文件，继续不依赖 CI 的后续工作。
- 失败时只读取失败 job/step 日志；只有对应 run `completed` 且 `success` 时才能声称 CI 通过。

CI 根据本次提交的修改范围选择验证任务：纯文档不构建所有平台，Linux 专属修改只运行 Linux 验证，Windows 专属修改只运行 Windows 验证，共享代码或 workflow 变化运行完整矩阵。tag 发布和手动触发始终运行完整验证。

`pending_ci` 只是状态记录，不是停止条件。`queued`/`in_progress` 时不等待、不轮询、不重复读取未变化文件或重复输出状态，继续不依赖该 run 的后续工作；只有明确 `failure` 才暂停新增功能并读取失败 job/step 日志。
