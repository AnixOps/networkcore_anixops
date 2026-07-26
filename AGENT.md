# Agent Operating Guide

本文件是本项目对自动化代理、AI 编码助手和人工协作者的主执行规范。

## 核心规则

本机只负责代码编写、文档编写和仓库文件编辑。所有测试、构建、编译、打包、发布验证都必须在 GitHub Actions 的 CI/CD 中完成。

不得在本机运行以下类型命令：

- `go test`、`go build`、`go run`
- `cargo test`、`cargo build`、`cargo run`
- `npm test`、`npm run build`、`pnpm test`、`pnpm build`
- `swift test`、`swift build`、`xcodebuild`
- `flutter test`、`flutter build`
- `gradle test`、`gradle build`
- 任何等价的本地编译、测试、打包、发布命令

允许在本机运行的命令仅限于：

- 查看文件和仓库状态：`ls`、`find`、`rg`、`sed`、`git status`、`git diff`
- 编辑代码和文档
- Git 提交、分支、推送等版本控制操作
- GitHub CLI 的 workflow 触发与结果查询
- 不产生本地构建产物的静态仓库检查

如必须验证代码，应提交或推送到 GitHub，并通过 GitHub Actions 执行。

## 项目方向

本项目目标是规划并逐步实现一个面向 Linux、macOS、Windows、iOS 的全平台网络内核与客户端体系。

长期架构方向：

- 自研统一控制内核，负责配置模型、订阅解析、策略路由、DNS、MITM 插件运行时和跨平台控制 API。
- 支持可插拔代理执行内核，优先支持本仓库内核，同时保留 `sing-box`、`xray-core`、`mihomo` 等适配能力。
- 支持类似 Loon、Quantumult X 的 MITM 插件能力，优先兼容 Loon 插件格式的高频子集。
- 建设全平台客户端，其中 iOS 必须重点验证 Network Extension、App Review、证书安装、插件脚本能力边界。

## 工作流

所有工作按以下顺序推进：

1. 修改代码、配置、文档或 workflow。
2. 查看 `git diff` 确认变更内容。
3. 提交并推送到 GitHub。
4. 触发 GitHub Actions，并按下述异步交接规则进行非阻塞状态查询。
5. 只根据 GitHub Actions 的失败日志修复问题。
6. 反复推送，直到 CI/CD 通过。

禁止用本地测试结果替代 GitHub Actions 结果。

## GitHub Actions 异步交接

编码 Agent 推送后不得占用一个长回合等待 CI：

- 只允许对当前 commit 对应的 workflow run 进行一次、最多两次非阻塞状态查询；两次查询之间不得长时间 `sleep`。
- 禁止使用 `gh run watch`、无限 `while`/`until` 循环、定时刷新全部历史 run 或其他长时间阻塞轮询。
- 状态为 `queued` 或 `in_progress` 时，记录 commit SHA、workflow 名称、run ID、run URL 和当前状态，然后以 `pending_ci` 结束当前编码回合。
- 后续 Agent 回合、workflow completion 事件或人工重新触发负责继续处理；当前回合不得持续等待。
- CI 失败时只读取失败 job 和失败 step 的必要日志，不重复下载成功 job 日志。
- 只有对应 commit 的 GitHub Actions 状态为 `completed` 且结论为 `success` 时，才可以声称 CI 验证通过。

等待 CI 的交接结构固定为：

```json
{
  "task_state": "pending_ci",
  "commit_sha": "<sha>",
  "workflow": "CI",
  "run_id": "<id>",
  "run_url": "<url>",
  "status": "queued|in_progress",
  "next_action": "resume_after_ci_completion"
}
```

## CI/CD 约束

`.github/workflows/ci.yml` 是主验证入口，必须覆盖：

- 仓库治理文件检查
- Linux、macOS、Windows 基础工作区验证
- Go 项目出现后的 Go 构建与测试
- Rust 项目出现后的 Rust 构建与测试
- Node 项目出现后的 Node 构建与测试
- Swift 或 Apple 项目出现后的 macOS/iOS 相关验证

`.github/workflows/release.yml` 是发布入口，发布流程必须通过手动触发或 tag 触发，不允许在本机打包发布。

## iOS 特殊规则

iOS 相关实现必须遵守：

- 网络隧道能力必须基于 Apple Network Extension。
- 内核必须以 iOS 可嵌入库或 Extension 可运行形态集成，不能依赖外部进程模型。
- MITM CA 安装必须由用户明确授权。
- 远程插件、脚本、规则必须有权限模型和审核风险评估。
- App Store、TestFlight、证书、Provisioning Profile 相关验证只在 GitHub Actions 或 Apple 官方平台完成。

## 失败处理

如果当前环境无法完成某项自动化操作，应把问题写入 `docs/manual-intervention.md`，包括：

- 需要人工介入的事项
- 为什么自动化无法完成
- 人工完成后的下一步自动化动作

一旦 GitHub Actions 打通，后续应尽量减少人工介入，按计划依次推进。
