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
4. 触发或等待 GitHub Actions。
5. 只根据 GitHub Actions 的失败日志修复问题。
6. 反复推送，直到 CI/CD 通过。

禁止用本地测试结果替代 GitHub Actions 结果。

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
