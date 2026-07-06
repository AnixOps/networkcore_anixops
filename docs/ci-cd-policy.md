# CI/CD Policy

## 总原则

本仓库采用 GitHub Actions 作为唯一测试、构建、编译、打包、发布验证环境。

本地环境的职责是：

- 编写代码
- 编写文档
- 修改配置
- 查看差异
- 提交和推送
- 触发和观察 GitHub Actions

本地环境不承担：

- 单元测试
- 集成测试
- 编译
- 打包
- 发布
- 任何形式的构建验证

## Workflow 分工

### CI

`.github/workflows/ci.yml` 是主验证入口。

它应覆盖：

- 治理文件存在性检查
- Roadmap、TODO、CHANGELOG 等规划治理文件检查
- 关键架构规格与接口草案文件检查
- 可插拔代理执行内核适配接口检查
- 运行层编排设计文件检查
- Linux artifact 发布前设计文件检查
- Linux platform adapter 设计文件检查
- Linux platform adapter crate README 和 Rust workspace 覆盖检查
- Linux CLI entrypoint 设计文件检查
- Linux CLI crate README 和 Rust workspace 覆盖检查
- Linux CLI artifact 安装、卸载与回滚设计文件检查
- Release workflow Linux artifact readiness gate 检查
- 架构决策记录检查
- Linux、macOS、Windows 基础工作区检查
- Go 代码出现后的 Go 构建与测试
- Rust 代码出现后的 Rust 构建与测试
- Rust 代码出现后的依赖安全扫描
- Node 代码出现后的 Node 构建与测试
- Swift、Xcode 或 iOS 代码出现后的 Apple 平台验证

CI summary job 必须显式输出 Go、Rust、Node、Swift、Apple 项目检测开关，写入 GitHub Step Summary 表格，并门禁已启用的关键结果；当检测到 Rust workspace 时，summary 必须同时检查 Rust build/test 矩阵和 Rust dependency security audit；当检测到 Go、Node、Swift 或 Apple 项目时，summary 必须检查对应语言或平台 job。

### Release

`.github/workflows/release.yml` 是发布入口。

发布规则：

- 只能通过 tag 或 `workflow_dispatch` 触发。
- 不允许在本机打包 release artifact。
- 产物必须由 GitHub-hosted runner 或后续配置的受控 runner 生成。
- 真实平台产物加入前必须满足 [Release Strategy](release-strategy.md) 中定义的门禁、矩阵和回滚策略。
- 首个 Linux CLI artifact 加入前必须满足安装、卸载与回滚设计，且继续由 GitHub Actions 生成、校验和发布。
- release policy job 必须检查版本格式与触发来源一致性；`workflow_dispatch` placeholder release 必须从 `main` 分支发起，tag release 的版本必须与 tag 名一致。
- placeholder 阶段必须包含 `release-ci-gate` job，记录真实 artifact 加入前必须关联 `main` 上同 commit 的成功 CI 结果。
- placeholder 阶段必须包含 `release-artifact-contract` job，记录首个真实 artifact job 的 checksum 算法和输出字段契约。
- placeholder 阶段必须包含 `release-signing-contract` job，记录真实平台 artifact 发布前必须声明签名或 attestation 策略。
- placeholder 阶段必须包含 `release-rollback-contract` job，记录真实 artifact 发布说明必须输出的回滚字段。
- placeholder 阶段必须包含 `linux-artifact-readiness` job，检查 Linux CLI 源码、platform adapter、安装/回滚设计和 license/NOTICE 人工确认记录，且不得生成 artifact。
- placeholder 阶段必须通过 release summary job 显式输出发布来源、policy、release-ci-gate、artifact contract、signing contract、rollback contract、Linux artifact readiness、placeholder、artifact 状态和后续 artifact 门禁。

## 多平台目标

首期 CI/CD 目标平台：

- `ubuntu-latest`
- `macos-26`
- `windows-latest`

iOS 相关验证只允许在 macOS runner 中执行。为优先支持最新 Apple 平台能力，默认使用 `macos-26`；如 GitHub hosted runner 暂不可用或特定工具链存在兼容问题，必须在 GitHub Actions 日志中确认后再调整。涉及签名、证书、Provisioning Profile 的内容必须使用 GitHub Secrets 或 Apple 官方流程，不得写入仓库。

## 内核与客户端演进

后续出现具体代码栈时，应把验证规则加入 GitHub Actions：

- Go 内核：`go test ./...`、`go build ./...`
- Rust 内核：`cargo fmt --all -- --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace --all-targets`、`cargo build --workspace --all-targets`、`cargo generate-lockfile`、`cargo audit`
- Node 或 Web 客户端：`npm test`、`npm run build`
- Swift 或 iOS 客户端：`swift test`、`swift build`、`xcodebuild`

这些命令只能在 GitHub Actions 中运行。

## 人工介入边界

允许人工介入的事项：

- 首次创建 GitHub 仓库或配置远端
- 首次推送 bootstrap 文件
- GitHub CLI 登录或授权
- Apple Developer 账号、证书、Provisioning Profile、App Store Connect 配置
- GitHub Secrets 配置
- 第一次确认 GitHub Actions 权限

人工完成后，应继续由 CI/CD 自动推进。
