# Roadmap

本路线图把 `networkcore_AnixOps` 推进为可验证、可维护的全平台网络内核与客户端体系。所有阶段都遵守 [AGENT.md](AGENT.md) 和 [docs/ci-cd-policy.md](docs/ci-cd-policy.md)：本机只编辑文件，验证只在 GitHub Actions 中运行。各版本精确能力边界见 [docs/alpha-release-feature-matrix.md](docs/alpha-release-feature-matrix.md)，全部设计文档见 [docs/README.md](docs/README.md)。

下列 P0–P4 是本仓库历史阶段，不表示跨仓库或生产验收完成；源码、CI 与真实环境证据分别记录在 [交付证据](docs/P4_EXECUTION_STATUS.md)。首批运维交付只包含诊断事件校验、JSON 序列化与显式适配边界（见 [P0 维护手册](docs/MAINTENANCE_P0.md)）。

## 当前阶段：P4 Client And Platform Integration

P0–P3 已完成，当前仓库不再处于 P3。当前迭代、发布说明和 source contract 的 source of truth 是下方 P4 backlog buckets；P3 只在已完成章节、历史 TODO 或 CHANGELOG 中保留审计语境。

```text
current-main-release-state=released
current-main-source-candidate=v0.2.0
current-main-latest-published-tag=v0.2.0
current-main-latest-stable-tag=v0.2.0
current-main-subscription-foreground=embedded-engine-run-url-and-run-catalog-active
current-main-subscription-background=linux-systemd-oneshot-timer-and-windows-opt-in-single-source-active
```

当前 main 概况：

- **发布**：最新 stable `v0.2.0`（2026-10-26，Linux CLI tarball + Linux 图形客户端 tarball/.deb + Windows MSI + Windows portable ZIP，各四件套；rc.1/rc.2 为候选，rc.2 通过真机验收），全部须通过同 commit CI、checksum、manifest、attestation、release notes、rollback 和 publish eligibility。Linux artifact marker：`linux-artifact-release-state=confirmed-release-path`。
- **订阅与运行**：所有平台都在进程内运行自研嵌入式引擎（`engine-embedded`），协议按 crate 和 cargo feature 模块化；第三方内核 adapter 已于 2026-10-26 移除。解析层包含 Hysteria2/TUIC share-link parser gate、Clash YAML parser gate、sing-box JSON parser gate、Surge proxy line parser gate、Loon proxy line parser gate 和 Quantumult X proxy/server line parser gate；Hysteria2/TUIC 前台路径不启用 HTTP/3 MITM。
- **持久订阅与刷新**：`v0.1.2-alpha.1` 起的显式本地 catalog（add/list/remove/select/update/rollback，见 [Persistent Subscription Catalog Source Contract](docs/architecture/subscription-catalog-persistence-source-contract.md)）；`subscription update` 先验证候选再写 snapshot，失败保留旧 catalog。Linux `subscription refresh schedule` 生成 systemd oneshot/timer；Windows GUI 提供 opt-in 单 HTTP(S) source 小时级刷新。默认路径扫描仍未启用。
- **managed 记录**：`managed-status`、`managed-event`（含 `networkcore-linux managed-event list` 有界分页）和 `managed-log` 只读写显式 schema v1 记录，固定 `liveness_verified=false`。
- **Linux 系统集成**：显式 systemd unit 安装/控制（`connect`/`disconnect`/`restart` 映射到该 unit）；`proxy apply/status/rollback` 写显式环境代理文件（绝对路径、独立 snapshot、`--confirm`，Unix `0600`，rollback 检测外部修改）；`mitm certificate trust-apply/trust-rollback` 管理 Ubuntu-style CA trust-file（见 [Linux Trust-File Source Contract](docs/architecture/linux-trust-file-source-contract.md)），其他 trust backend 仍 blocked。
- **Windows**：原生 GUI（Home/Nodes/Subscriptions/Settings/Diagnostics/Advanced）、SCM service、WiX MSI、portable ZIP；连接状态由 SCM、嵌入式引擎的 loopback listener 和交互用户代理共同确认。见 [Windows GUI Daily Usability](docs/architecture/windows-gui-daily-usability.md)。HTTP/2/HTTP/3 MITM 仍未启用。
- **MITM**：`mitm-cli-command-gate-status=partial-active`。Linux `start --enable-https-mitm --mitm-ca-cert <path> --mitm-ca-key <path> --confirm` 提供受控 HTTP/1.1 TLS 终止、web-PKI 上游校验、每 session 最多四次有界 rewrite 和 no-network sandbox 本地脚本；Windows 可显式启用同类 HTTP/1.1 MITM，但拒绝脚本。边界合同：[certificate lifecycle](docs/architecture/linux-mitm-certificate-lifecycle-source-contract.md)、[browser capture](docs/architecture/linux-mitm-browser-capture-source-contract.md)、[HTTP rewrite](docs/architecture/linux-mitm-http-rewrite-source-contract.md)。四个 gate 的当前状态见 [README](README.md#mitm)。
- **iOS**：`apps/ios` 已有 Swift package、XcodeGen spec 和 `NetworkCorePacketTunnel` target；嵌入式 Rust runtime、签名、TestFlight/App Store upload 和 iOS release asset 仍 blocked。

P4 backlog buckets：

- 订阅和客户端兼容：规则/策略组运行时、运行中节点切换、默认路径与更多订阅格式（如 Hysteria v1），继续走 public engine adapter 路线。
- MITM 数据面和证书生命周期：CA 安装/信任检测/撤销/trust-store 回滚、HTTP/2 等协议扩展、跨平台 script runtime；通过 `MITM_CLI_COMMAND_GATE`、`MITM_CERTIFICATE_LIFECYCLE_GATE`、`MITM_HTTP_TLS_DATA_PLANE_GATE`、`MITM_BROWSER_CAPTURE_GATE` 逐项放开。
- 浏览器捕获用户闭环：完整 live browser traffic proof 自动化、显式 browser/system proxy 或系统 PAC、snapshot 与 rollback；完整 managed session 编排。
- SD-WAN 组网：外部组网程序适配已于 2026-10-26 删除，组网能力等 ANX 私有协议重新提供。

## 里程碑（2026-10 起）

| 里程碑 | 内容 |
|---|---|
| M0 | ✅ `v0.2.0` 正式版已发布（2026-10-26，`a636b89`，`v0.2.0-rc.2` 真机验收通过） |
| M1 | iOS 内部 TestFlight：自研 Rust 嵌入式引擎 `engine-embedded`（M1a Shadowsocks-2022，M1b VLESS + REALITY/Vision） |
| M2 | 统一内核 v0.3：FFI C ABI、Process/Embedded 引擎抽象、规则与策略组模型、桌面 TUN、WireGuard |
| M3 | MITM 与插件 v0.4：HTTP/2 MITM、QUIC reject、Loon 插件高频子集、脚本运行时 |
| M4 | iOS MITM 与插件：CA 信任状态、JavaScriptCore |
| M5 | macOS（System Extension、Developer ID）与 App Store |
| M6 | 1.0 |

iOS Network Extension 与桌面端都使用仓库内自研的 Rust 引擎，不托管第三方内核（第三方说明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)）。

## 版本节奏

- `v0.1.0`：Linux-only explicit HTTPS rewrite preview，已发布（alpha.14–alpha.20、rc.1 依次交付 plain HTTP data plane、TLS termination foundation、HTTPS request/response rewrite preview、traffic-proof binding 与 release hardening）。不含 Windows、script dispatch、system trust/proxy mutation、daemon、TUN、DNS 或 firewall mutation。
- `v0.1.1`：引入 Windows CLI artifact，订阅兼容为主线（各 parser gates、节点选择与 cross-platform run plan）。
- `v0.1.2`：managed lifecycle（persistent catalog、managed status/events/logs/reload/rollback、受控 script dispatch、system trust/proxy mutation 与 managed MITM session）；高风险 mutation 必须显式授权、可检测、可回滚。
- `v0.2.0`：Windows managed client（MSI 自 `v0.2.0-alpha.1`），当前候选 `v0.2.0-rc.2`（`v0.2.0-rc.1` 已发布）。

发布门禁与流程见 [Release Strategy](docs/release-strategy.md)。

## 已完成阶段

### P0 Bootstrap Governance (Completed)

建立代理与贡献规范、CI/CD policy、多平台基础 CI、Roadmap/TODO/CHANGELOG 记录入口和 release strategy。

### P1 Domain And Architecture Specification (Completed)

定义统一控制内核领域模型，配置、订阅、策略路由、DNS、MITM 插件和控制 API 边界，插件权限模型与 iOS 审核风险初评，并选定 Rust 首选栈（[ADR 0001](docs/architecture/adr-0001-initial-core-stack.md)）。规格见 [Control Kernel Domain](docs/architecture/control-kernel-domain.md)、[Control Kernel Interfaces](docs/architecture/control-kernel-interfaces.md)、[iOS Platform Risk Assessment](docs/architecture/ios-platform-risk-assessment.md)。

### P2 Core Kernel Skeleton (Completed)

建立最小可编译、可测试的内核骨架：`control-domain`、`control-runtime`、`config-core`、`engine-native`、`platform-linux`、`platform-ios` 和 `networkcore-linux` CLI，以及对应 GitHub Actions 验证。规格见 [Control Runtime Orchestration Design](docs/architecture/control-runtime-orchestration.md)。

### P3 Runtime Capability Baseline (Completed)

确立公有执行内核 adapter 优先（[ADR 0002](docs/architecture/adr-0002-public-engine-adapter-first.md)）：NetworkCore 维护控制层，`engine-*` adapter 负责配置转换与生命周期，`sing-box` 等公有内核承担协议数据面；`engine-native` 保留为实验线，私有协议实现暂缓。完成 `engine-singbox`、`run-url` 前台运行、`mitm_anixops` `v1.4.6` 固定与 `mitm-policy` safe wrapper、内置 `networkcore.adblock`、`ManagedSdwanMitmPolicyGate`、native SOCKS5 CONNECT plugin reject 和 explicit HTTP proxy plain HTTP data plane，以及 subscription catalog runtime gate。第三方 plugin/parser/runtime 须先走 [Third-Party Plugin Onboarding Process](docs/architecture/third-party-plugin-onboarding-process.md)。

## 迭代选择规则

每轮只选择一个最小可验证增量。优先级按以下顺序判断：

1. 修复会阻断 CI/CD、协作或回滚能力的问题。
2. 补齐下一步实现前缺失的规范、设计和接口。
3. 添加最小源码骨架及其 GitHub Actions 验证。
4. 扩展功能前先补齐测试、文档和风险记录。
