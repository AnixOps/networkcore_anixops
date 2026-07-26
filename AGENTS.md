# Agents

本文件用于兼容常见 AI 编码工具。项目主规范见 [AGENT.md](AGENT.md)。

必须遵守的最高优先级项目规则：

- 本机只负责代码和文档编写。
- 所有测试、构建、编译、打包、发布验证都必须在 GitHub Actions 中运行。
- 不得在本机运行本地测试或构建命令。
- 无法通过自动化完成的事项必须记录到 `docs/manual-intervention.md`。
- 推送后只允许对当前 commit 的 CI 进行一次、最多两次非阻塞查询；禁止 `gh run watch`、无限循环和长时间轮询。
- CI 为 `queued` 或 `in_progress` 时，必须记录 commit SHA、workflow、run ID、run URL 和状态；`pending_ci` 只是状态记录，不是停止条件，不等待、不轮询、不重复读取未变化文件，继续不依赖 CI 的后续工作。
- CI 失败时只读取失败 job/step 日志；只有 `completed` 且 `success` 才能声称 GitHub Actions 验证通过。

开始任何任务前，请先阅读 [AGENT.md](AGENT.md) 和 [docs/ci-cd-policy.md](docs/ci-cd-policy.md)。

`pending_ci` 只记录外部状态，不是停止条件。`queued`/`in_progress` 时不等待、不轮询、不重复读取未变化文件，继续不依赖 CI 的后续工作；只有明确 `failure` 才暂停新增功能并读取失败 job/step 日志。
