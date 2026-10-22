# CI/CD Policy

## 总原则

本仓库采用 GitHub Actions 作为唯一的测试、构建、编译、打包和发布验证环境。

- 本地只负责：编写代码与文档、修改配置、查看差异、提交和推送、触发和观察 GitHub Actions。
- 本地不承担：单元/集成测试、编译、打包、发布或任何形式的构建验证。
- `Cargo.lock` 必须随源码受版本控制；CI、依赖审计与 tag 发布均使用 `--locked`，发布工作流不得临时生成或改写依赖图。

## Workflow 分工

### CI

`.github/workflows/ci.yml` 是主验证入口。

#### Fast CI、Full CI 与路径门控

整体验证分为 Fast CI、Full CI 和下文独立的 Release CI；`ci.yml` 保留顶层 `CI summary`
作为稳定的最终门禁名称。启动顺序：

1. `changes`：根据 PR base/head、push before/head 或触发类型计算变更范围，输出 `docs`、
   `governance`、`go`、`rust`、`node`、`windows`、`linux`、`ios`、`apple`、`workflow`、
   `release_sensitive` 和 `full_matrix`。无法取得可靠 diff、出现未知路径、tag 或
   `workflow_dispatch` 时安全回退到完整矩阵。
2. `policy-fast`：五分钟预算内运行 `.github/scripts/verify-repository-policy.sh fast`，检查关键治理文件和
   manifest、已提交的 `Cargo.lock`、本地构建产物、签名/私钥文件、明显凭据模式、workflow 入口以及与变更平台对应的最小合同。
3. `policy-full`：运行 `.github/scripts/verify-repository-policy.sh full`，保留全部文档一致性、架构 marker、
   源码合同和 release 状态断言；只依赖 `changes`，与 `policy-fast` 和平台验证并行，不作为平台 job 的串行前置条件。
4. `detect-projects`：检测 Go、Rust、Node、Swift、Apple 项目，仅作信息参考；实际 job 执行完全由
   `changes` 的路径分类决定，不因“仓库存在 Cargo.toml”就无条件运行全部 Rust 平台。

路径门控：

| 变更路径 | 触发 |
|---|---|
| 仅 Markdown、普通 `docs/**` 或 Agent 治理文件 | fast/full policy，跳过无关三平台构建 |
| 根 `Cargo.toml`、`Cargo.lock`、共享 `crates/**`（非平台特定）、`.github/workflows/**`、CI 脚本、发布关键合同、无法分类的路径 | `full_matrix`（Linux、macOS、Windows 完整 Rust 矩阵） |
| `apps/windows-*`、`crates/platform-windows/**`、`installer/windows/**`、Windows 架构源码文件 | Windows Rust、Node 前端合同和 MSI 验证 |
| `apps/linux-cli/**`、`crates/platform-linux/**`、Linux 架构文件 | Ubuntu Rust 验证 |
| `apps/ios/**`、`crates/platform-ios/**`、Swift/Package.swift/Xcode/entitlement/privacy manifest、Apple workflow 文件 | macOS/iOS 验证 |
| `package.json`、`pnpm-lock.yaml`、`apps/windows-gui/ui/**` | Node 验证 |
| tag 与手动触发 | 始终完整验证，不允许被路径过滤跳过 |

Full CI 保留 Linux、macOS、Windows Rust 覆盖、Rust dependency audit、Node lint/test/build、
Windows managed-client/MSI、Swift/Apple 及既有合同检查。PR 矩阵使用 `fail-fast: true` 尽快反馈；
main、tag 和手动完整验证使用 `fail-fast: false`，保留全部平台兼容性结果。

#### Windows GUI 前端产物复用

Windows GUI 前端在独立的 `windows-gui-frontend` Ubuntu producer job 中构建一次，以
`windows-gui-ui-<commit-sha>` 上传同一 workflow run 的短期 artifact（保留一天）；Windows Rust 与 MSI
job 显式等待 producer 完成，只从当前 run 下载 artifact 并检查 `index.html`。Node lint/test 仍覆盖三个
runner，与 producer 解耦。该复用只用于普通 CI；Release workflow 必须独立安装 frozen dependencies、
构建前端和生成发布产物，不得信任或复用普通 CI artifact。

`apps/windows-gui/ui/pnpm-lock.yaml` 必须随源码提交，Node CI 和 release 均使用
`pnpm install --frozen-lockfile`；两者不共享 `dist` 或发布产物缓存，release 不共享 Rust target 缓存。
pnpm lockfile 只能由 `.github/workflows/refresh-pnpm-lock.yml` 在 GitHub Actions 中生成，经 artifact 审查后提交。

#### Job 超时预算

所有 job 必须有明确 timeout：

| Job | 预算 |
|---|---|
| 范围检测、fast policy、project detection、summary | 5 分钟 |
| full policy | 15 分钟 |
| workspace smoke | 10 分钟 |
| Rust | Ubuntu 30 / macOS 40 / Windows 45 分钟 |
| Node | 25 分钟 |
| Windows MSI | 45 分钟 |
| dependency audit | 20 分钟 |
| Swift/Apple | 45 分钟 |
| Release 轻量 policy/summary / package / attestation | 5–15 / 45 / 20 分钟 |

调整预算必须基于 GitHub Actions 运行证据，不能用无限等待规避失败。

#### CI 覆盖范围

CI 的静态治理检查（`verify-repository-policy.sh` 与 `ci.yml` 中的文本断言）覆盖以下类别。具体合同文件见
[docs/README.md](README.md) 的主题索引和 `docs/architecture/` 下的各 source contract。

- **治理与阶段**：治理文件存在性；Roadmap、TODO、CHANGELOG 等规划文件；当前阶段 source of truth
  （README、ROADMAP、TODO 和架构文档固定为 P4 Client And Platform Integration，P3 只作为 completed baseline
  或历史条目）；P4 backlog buckets（订阅/客户端兼容、MITM 数据面和证书生命周期、浏览器捕获用户闭环）在
  README、ROADMAP、TODO、Linux CLI README、`mitm-policy` README 和相关 source contract 中保持同步；架构决策记录。
- **内核与架构**：关键架构规格与接口草案；可插拔代理执行内核适配接口；公有执行内核优先与三层维护框架 ADR；
  运行层编排设计；Native engine listener/node 配置；Linux native proxy engine start；engine-native、
  engine-singbox（latest release 下载、checksum/extraction 诊断、订阅 URL 到 sing-box run、Linux CLI
  `install-sing-box`/`run-url`/`help`）和 Linux CLI crate README 与 Rust workspace 覆盖。
- **订阅与托管会话**：config-core README 与 subscription parser source contract（Trojan/VLESS/VMess URL、
  Clash YAML、sing-box JSON、Surge、Loon、Quantumult X parser gates）；subscription catalog runtime
  orchestration design 与 runtime gate；persistent subscription catalog（`CommandSubscriptionCatalogStore`
  的 add/list/remove/select/update/rollback、显式 `run-catalog` foreground handoff、无默认/后台刷新）；managed
  foreground session status/rollback/event/log 合同（`managed-status`、`managed-event`、`managed-log`
  的显式路径、expected-state transition、`liveness_verified=false`，无 PID/port/socket liveness、无
  daemon/control socket、无 runtime control）。
- **MITM**：`mitm_anixops` adapter 设计；`mitm-anixops-sys` crate、submodule 固定和 FFI version 测试；
  `mitm-policy` safe wrapper、`networkcore.adblock`、`HttpMitmEvent`/`HttpMitmOutcome` rich mutation plan、
  `NativeHttpMitmPluginHook`、native SOCKS5 CONNECT plugin reject 与 browser proof 诊断、plain HTTP live data
  plane 及 Linux CLI `mitm` 机器字段；Linux trust-file source contract（`trust-apply`/`trust-rollback`、显式
  `--trust-file`/`--snapshot`/`--confirm`、原子写入与读回、`update-ca-certificates` adapter；NSS、p11-kit、
  Firefox 等 trust backend 保持 blocked）；third-party plugin onboarding process（pinned source、license/NOTICE、
  permission、safe wrapper、CI governance、upgrade procedure）。
  - Linux MITM certificate lifecycle source contract：CA certificate/private key PEM artifact、dedicated profile CA
    PEM copy、snapshot、apply/rollback 诊断。
  - Linux MITM browser capture source contract：dedicated-profile launch-plan/session-plan/launch、target route
    verify、proof-log-token traffic proof、traffic-proof default proof binding、CONNECT authority binding mismatch、
    `--proxy-scheme socks5` native plugin proxy mode、PAC/browser policy/Firefox profile prefs apply/rollback。
  - Linux MITM HTTP rewrite source contract：explicit HTTP proxy live plain HTTP 改写、CONNECT tunnel、TLS
    ClientHello/SNI observation、controlled TLS termination plan、HTTPS request/response rewrite preview、
    content-type/body-size/buffering guard、`http_rewrite` report。
  - Gate 状态：
    - `MITM_CLI_COMMAND_GATE` partial-active
    - `MITM_CERTIFICATE_LIFECYCLE_GATE` artifact-lifecycle-active/profile-trust-artifact-active/trust-mutation-blocked
    - `MITM_BROWSER_CAPTURE_GATE` pac-policy-profile-prefs-active/system-mutation-blocked
    - `MITM_HTTP_TLS_DATA_PLANE_GATE` plain-http-live-data-plane-active/tls-decryption-blocked
- **iOS**：Network Extension design；platform adapter source contract、crate README、workspace 与合同测试；
  Swift/Network Extension bridge design 与 Swift/Xcode bridge source contract；embedded runtime FFI boundary；
  MITM certificate lifecycle design；entitlement/provisioning；App Review/privacy release readiness、Privacy
  Manifest 和 App Review manual confirmation；TestFlight/App Store Connect upload workflow 与 upload workflow
  activation validation；Swift/Xcode source tree activation preflight、Package.swift source ownership activation
  preflight 和 Package.swift manifest-only activation validation。
- **Linux 发布链路**：Linux artifact 发布前设计、platform adapter 设计与 crate README、CLI entrypoint 与 runtime
  wiring、artifact 安装/卸载/回滚、package artifact manifest、license/NOTICE confirmation source contract；
  Linux artifact release state consistency（README、ROADMAP、TODO、CHANGELOG、release strategy、license/NOTICE
  contracts、manual marker、CI governance 和 release workflow 都保持
  `linux-artifact-release-state=confirmed-release-path`）；Release CI success source contract；Linux package
  runner/toolchain/target、archive staging、checksum/manifest checksum、publish/upload boundary、
  signing/attestation policy binding、release notes/rollback policy binding、publish eligibility aggregate、
  license/NOTICE transition 和 release CI gate activation/execution/API implementation 合同；artifact job
  preflight、build command、staging file、archive creation、checksum execution、manifest generation、manifest
  checksum、workflow artifact bundle upload、attestation execution、release notes/rollback execution 和 publish
  eligibility execution validation contracts；Release workflow Linux artifact readiness gate 与 manifest output summary。
- **版本与 Windows 发布**：Alpha Release Feature Matrix（README、ROADMAP、TODO、Release Strategy 和
  `docs/alpha-release-feature-matrix.md` 同步记录各已发布版本与已拍板的版本边界）；历史 Windows CLI artifact
  gate（`windows-cli-artifact-readiness` 对 `v0.1.1-alpha.2` zip 的 source identity、`package-windows`、
  `attest-windows`、release notes/rollback、publish eligibility 和 system mutation blocked marker）；当前
  Windows managed client MSI gate（`apps/windows-gui`、`apps/windows-service`、`apps/windows-cli`、
  `platform-windows`、WiX 4.0.6、MSI validation、checksum/manifest、attestation、release notes/rollback 和
  managed system mutation eligibility，只有 JavaScript script dispatch 仍 blocked）；Alpha placeholder release
  version policy、Windows manual smoke 测试清单、confirmed marker 与 release placeholder/summary 输出。
- **构建与测试**：Linux、macOS、Windows 基础工作区；出现对应代码后的 Go 构建与测试、Rust 构建/测试与依赖安全扫描、
  Node 构建与测试、Swift/Xcode/iOS Apple 平台验证。

#### CI summary

CI summary job 必须显式输出 commit SHA、workflow run ID/URL、变更来源和路径分组、Go/Rust/Node/Swift/Apple
项目检测开关，以及运行、跳过、失败的 job 和下一步建议，并写入 GitHub Step Summary。

- 无关 job 的 `skipped` 是合法结果；应运行 job 的 `skipped`、任何 `failure`、任何非并发替代 run 的
  `cancelled` 都必须使 summary 失败。
- 检测到 Rust workspace 且 Rust 路径需要验证时，summary 必须同时检查 Rust build/test 矩阵和 Rust dependency
  security audit；Go、Node、Swift 或 Apple 路径需要验证时，必须检查对应 job。
- Rust 路径或完整矩阵变化时，summary 还必须检查 `REALITY interop (Linux)`：该 job 在 Ubuntu runner 上下载
  Xray-core 与 sing-box 官方 release 二进制（`XRAY_VERSION`/`SINGBOX_VERSION`，默认解析为最新正式 release，
  并写入 Step Summary），每次生成新的 REALITY 密钥、UUID 与 short id，只监听 127.0.0.1，再以 `--ignored`
  运行 `outbound-vless` 的互通测试。

### CI 缓存策略

缓存只能加速普通 CI，不能改变验证结论：缓存未命中时，每个 job 仍必须能从源码完整安装、构建和测试；release 必须可复现。

- 普通 CI 允许的缓存（仅限 `ci.yml` 的验证 job）：
  - Rust：`Swatinem/rust-cache` 缓存 cargo registry、git 依赖和 `target/`。key 由 job、runner OS 与架构、rustc
    版本、相关 `CARGO_*` 环境变量、`Cargo.lock`、`Cargo.toml`、`.cargo/config.toml` 与 `rust-toolchain` 决定。
    只有成功的 run 保存缓存。Rust 验证 job 设置 `CARGO_INCREMENTAL=0`。Windows MSI job 先安装工具链再恢复缓存，
    保证 key 中的 rustc 版本与实际构建一致；构建前清除恢复出的 `webview2-com-sys` 构建输出，使 WebView2
    加载器唯一性校验只看到本次构建的产物。
  - Node：`setup-node` 的 pnpm store 缓存，key 绑定 `apps/windows-gui/ui/pnpm-lock.yaml`。
  - CI 工具：`cargo-audit` 通过 `taiki-e/install-action` 安装预编译二进制。
  - Go：`setup-go` 的模块缓存。
- 禁止的缓存：
  - `release.yml`（含 tag 触发的打包）中的 `dist`、Rust `target`、发布产物、DerivedData 或任何编译输出。
    `ci.yml` 的 tag 触发运行属于验证，可用普通 CI 缓存，但其产物不得作为发布产物。
  - 把普通 CI 的 artifact 或 `target/` 复用到 release。
  - 缓存中保存凭据、token 或 secret 派生内容。
- `release.yml` 目前不加缓存：它的构建命令受 `ci.yml` 字符串校验约束，且只在 tag 时运行，收益小却落在发布路径上；
  以后若要引入依赖缓存须单独评估。

### Release

`.github/workflows/release.yml` 是发布入口，发布门禁、矩阵和回滚策略以 [Release Strategy](release-strategy.md) 为准。

触发与版本：

- 只能通过 tag 或 `workflow_dispatch` 触发；不允许在本机打包 release artifact；产物必须由 GitHub-hosted
  runner 或后续配置的受控 runner 生成。
- release policy job 检查版本格式与触发来源一致性：允许稳定版本和 `alpha.N`、`beta.N`、`rc.N` 预发布，N 为无前导零的
  正整数，为保持 Windows Installer 版本排序分别限制为 `1-499`、`1-399` 和 `1-98`；`workflow_dispatch`
  placeholder release 必须从 `main` 发起，tag release 版本必须与 tag 名一致。
- `release-ci-gate` 使用 `actions: read` 读取 `main` 上同 commit 的成功 CI，校验 `CI summary` job，并输出 CI
  run/source 字段及 release CI gate activation/execution/API implementation 字段。

产物 job（`package-linux`、`package-windows`、`attest-linux`、`attest-windows`、`post-release-summary`、
`windows-release-summary`、`publish-eligibility-gate`、`windows-publish-eligibility-gate`、`publish-github-release`）
全部受 GitHub Actions gates 约束：

- `linux-artifact-readiness` 检查 Linux CLI 源码、platform adapter、native listener/node 配置、foreground
  stop/release 源码与合同测试、artifact manifest、license/NOTICE、release CI gate 以及上文“Linux 发布链路”列出的全部
  package 合同和安装/回滚设计；`docs/manual-intervention.md` 的 license/NOTICE marker 仍为 pending 时必须失败，且不得进入构建、打包、上传或发布。
- 历史 `windows-cli-artifact-readiness` 负责 `v0.1.1-alpha.2` zip 合同；当前 Windows managed client gate 验证
  `apps/windows-gui`、`apps/windows-service`、WiX MSI、managed system mutation 和 source identity。
- `package-linux` 在 GitHub Actions 中安装 Rust stable/minimal toolchain、验证已提交的 `Cargo.lock`，用
  `cargo build --locked --release --package networkcore-linux --bin networkcore-linux --target x86_64-unknown-linux-gnu`
  构建，把 pinned `mitm_anixops` 的 `libexec/anixops-runner.js` 一同放入单顶层目录 tarball；生成 archive sha256、
  manifest JSON 和 manifest sha256，并通过 `actions/upload-artifact` 上传只含这四个文件的同 run bundle。runner
  仅支持显式本地 script map，不能成为远程脚本下载通道。
- `attest-linux` 从同 run bundle 下载四个文件、重新校验 checksum，并用 GitHub artifact attestation 证明它们；权限必须包含
  `contents: read`、`id-token: write` 和 `attestations: write`。
- `publish-eligibility-gate` 聚合 license/NOTICE、同 commit CI、runner/toolchain、archive staging、
  checksum/manifest、artifact manifest、publish/upload、signing/attestation 和 release notes/rollback；只有输出
  `package_publish_eligibility_status=eligible` 后，tag 触发的 `publish-github-release` 才能创建 GitHub Release 并上传 assets。

合同与占位 job：

- `release-artifact-contract`、`release-signing-contract`、`release-rollback-contract` 分别记录 artifact checksum
  算法与输出字段、签名或 attestation 策略、发布说明回滚字段。
- `ios-upload-readiness` 保持 blocked：检查 iOS upload workflow activation、Swift/Xcode source tree、Package.swift
  ownership 和 manifest-only 合同、`ios-upload-workflow` pending/blocked marker、protected environment/manual
  approval blocked、App Store Connect API secret status not-read-blocked 以及 archive/export/upload/submission
  blocked 输出；不得读取 secret、定义真实 iOS upload job 或生成 iOS release asset。
- release placeholder 与 release summary job 显式输出发布来源、policy、release-ci-gate、上述各合同与 readiness 状态、
  Linux artifact manifest output fields、license/NOTICE status、Alpha Windows manual smoke 清单与 confirmed 状态、artifact
  状态和后续门禁，以及 iOS 源码树、Package.swift、Xcode project、Network Extension target、`PrivacyInfo.xcprivacy`、
  entitlement/provisioning、`macos-26` source scan、upload workflow enabled marker、protected environment、manual
  approval、App Store Connect API secret status、archive/export、TestFlight/App Store upload、App Review submission、
  build processing check 和 iOS release asset 的 blocked 状态。

## 多平台目标

CI/CD 目标平台：`ubuntu-latest`、`macos-26`、`windows-latest`。

- iOS Apple SDK、Swift/Xcode、archive/export、签名、TestFlight、App Store Connect 和 App Review submission 验证只在
  macOS runner 中执行，默认 `macos-26`；如 hosted runner 不可用或工具链不兼容，须在 GitHub Actions 日志中确认后再调整。
- 纯文档、manual marker 和 release placeholder 的静态治理检查可以在 `ubuntu-latest` 执行，但不得读取 secret、运行 Apple
  工具链或生成 iOS artifact。
- 签名、证书、Provisioning Profile 必须使用 GitHub Secrets 或 Apple 官方流程，不得写入仓库。

iOS 当前状态：`apps/ios/` 已有 Swift package（`Package.swift`）、`Sources`/`Tests`、`project.yml`、Entitlements 与
Privacy 目录，包括 NetworkCorePacketTunnel target，在 `macos-26` 上做 Swift package 验证。上文 iOS 各 design/source
contract 仍定义 FFI、证书生命周期、entitlement/provisioning、Privacy Manifest、App Review 和上传流程的边界；签名、
archive/export、TestFlight/App Store upload、App Review submission 和 iOS release asset 仍 blocked，计划见
[ROADMAP.md](../ROADMAP.md)。相关 `cargo build`、`swift build`、`swift test`、`xcodebuild`、archive/export、签名、TestFlight、
App Store Connect 或 App Review submission 验证只能在 GitHub Actions 或 Apple 官方平台执行。

## 内核与客户端验证命令

以下命令只能在 GitHub Actions 中运行：

- Go：`go test ./...`、`go build ./...`
- Rust：`cargo fmt --all -- --check`、`cargo clippy --locked --workspace --all-targets -- -D warnings`、
  `cargo test --locked --workspace --all-targets`、`cargo build --locked --workspace --all-targets`、
  `cargo metadata --locked --offline --no-deps --format-version=1`、`cargo audit`
- Node / Web：`npm test`、`npm run build`
- Swift / iOS：`swift test`、`swift build`、`xcodebuild`

## Agent CI 状态交接

- 编码 Agent 推送后只能对当前 commit 的 workflow run 做一次、最多两次非阻塞查询；禁止 `gh run watch`、无限循环、长时间
  `sleep` 或重复刷新全部历史 run。
- 状态仍为 `queued` 或 `in_progress` 时，记录 commit SHA、workflow、run ID、run URL 和状态，以
  `task_state=pending_ci`、`next_action=resume_after_ci_completion` 记录；`pending_ci` 不是停止条件。不得等待、轮询、
  重复读取未变化文件或重复输出相同状态，应继续不依赖该 run 的源码、合同、文档和后续切片。
- 只有 CI 明确 `failure` 才暂停新增功能，并只读取失败 job/step 的必要日志，不重复获取成功日志。
- 只有对应 commit 的 run 已 `completed` 且 conclusion 为 `success`，才能写为 GitHub Actions 已通过；排队或运行中状态、
  本地静态检查和历史 commit 的成功 run 都不能替代该结论。

## 人工介入边界

允许人工介入的事项（完成后继续由 CI/CD 自动推进，记录在 [manual-intervention.md](manual-intervention.md)）：

- 首次创建 GitHub 仓库或配置远端、首次推送 bootstrap 文件
- GitHub CLI 登录或授权、第一次确认 GitHub Actions 权限、GitHub Secrets 配置
- Apple Developer 账号、证书、Provisioning Profile、App Store Connect 配置
- App Store Connect App Privacy 问卷、Privacy Manifest/Required Reason API review、隐私政策 URL、App Review Notes、
  TestFlight group 和 VPN compliance 材料
- iOS archive/export、App Store Connect API、protected environment、manual approval、build processing 和 App Review
  submission gate 确认
- Linux artifact license/NOTICE 文本确认

## 首批运维诊断边界验证

`maintenance-contracts` job 对 `control-domain` 的严格 event/batch wire contract 和 `control-runtime` 的显式诊断适配运行
真实 Rust 合同测试，CI summary 将其列为必需结果。覆盖 schema/枚举/版本/时间/UTF-8 字节/批量边界、重复及未知字段、
已认证节点匹配、坏事件隔离、共享 fixture 序列化、故障与恢复的双阈值，以及诊断凭据最小化。既有 Linux/macOS/Windows
Rust 全量测试与构建继续承担业务回归。

源码函数存在、同提交 CI 成功和真实运行时接入分别验收。该 job 不宣称 NetworkCore 进程事件已接入 Agent，不发送邮件/Telegram，
也不证明外部监控或生产环境可用。记录入口为 `docs/P4_EXECUTION_STATUS.md`。
