# networkcore_AnixOps

`networkcore_AnixOps` 是 AnixOps Net 的网络内核：控制层、自研嵌入式引擎、协议 crate、MITM 插件兼容、平台 adapter 与 Linux/Windows CLI。

AnixOps Net 的客户端（Windows/Linux 桌面客户端、Windows MSI 与 portable ZIP、iOS/macOS App）位于 [AnixOps/anixops-net](https://github.com/AnixOps/anixops-net)。客户端仓库固定引用本仓库的一个内核 commit，并自行构建、测试和发布客户端；本仓库只发布内核与 Linux CLI artifact。

## 目标

- 构建 Linux、macOS、Windows、iOS 可用的统一网络控制内核。
- 维护三层运行架构：NetworkCore 控制层、执行内核 adapter 层、公有执行内核层；桌面与 iOS 都运行自研的嵌入式引擎（`engine-embedded`），协议按 crate 模块化增减，不再托管第三方内核。
- 支持类似 Loon、Quantumult X 的 MITM 插件系统，优先兼容 Loon 插件格式的高频子集。
- 为 [AnixOps/anixops-net](https://github.com/AnixOps/anixops-net) 的全平台客户端提供稳定的内核接口：Rust crate、`platform-*` adapter 和 iOS/macOS 使用的 C ABI 静态库。

## 工作方式

本仓库执行严格的 CI/CD 优先策略：本机只写代码和文档；所有测试、构建、编译、打包、发布验证均由 GitHub Actions 完成；无法自动完成的事项记录在 `docs/manual-intervention.md`。详见 [AGENT.md](AGENT.md)、[CONTRIBUTING.md](CONTRIBUTING.md) 和 [docs/ci-cd-policy.md](docs/ci-cd-policy.md)。

全部文档的分类索引见 [docs/README.md](docs/README.md)。常用入口：

- 进度与计划：[ROADMAP.md](ROADMAP.md)、[TODO.md](TODO.md)、[CHANGELOG.md](CHANGELOG.md)
- 版本能力边界：[Alpha Release Feature Matrix](docs/alpha-release-feature-matrix.md)
- 发布：[docs/release-strategy.md](docs/release-strategy.md)；人工事项：[docs/manual-intervention.md](docs/manual-intervention.md)
- 运维交接：[P0 维护手册](docs/MAINTENANCE_P0.md)、[交付证据](docs/P4_EXECUTION_STATUS.md)、[维护事件 JSON schema](docs/contracts/maintenance-event.schema.json)（只统一诊断事件校验、序列化和适配边界，NetworkCore 运行时尚未接入运维通信）

## 当前状态

P2 Core Kernel Skeleton 和 P3 Runtime Capability Baseline 已完成，当前阶段进入 P4 Client And Platform Integration。阶段判断以本节和 [ROADMAP.md](ROADMAP.md) 为准。

```text
current-main-release-state=released
current-main-source-candidate=v0.2.0
current-main-latest-published-tag=v0.2.0
current-main-latest-stable-tag=v0.2.0
current-main-subscription-foreground=embedded-engine-run-url-and-run-catalog-active
current-main-managed-reload=explicit-foreground-control-socket-active
current-main-linux-node-switch=explicit-loopback-selector-active
current-main-subscription-background=linux-systemd-oneshot-timer-and-windows-opt-in-single-source-active
current-main-cross-platform-run-plan=public-engine-run-plan-active
```

这些机器状态是当前 `main` 的唯一发布判定。

- 当前阶段源：P4 Client And Platform Integration。
- P3 是已完成历史基线；后续章节、TODO 已完成项或 CHANGELOG 中出现的 P3 只表示历史源码合同，不代表当前阶段、发布状态或开发优先级。
- 最新 stable：`v0.2.0`（2026-10-26，tag 在 `a636b89`，与通过真机验收的 `v0.2.0-rc.2` 同一提交）：Linux CLI、Linux 图形客户端 tarball 与 `.deb`、Windows MSI 与 portable ZIP，各四件套。上一个 stable 是 `v0.1.0`（Linux-only）。
- `v0.2.0` 已发布（macOS 不在范围内）。同名 tag 由 GitHub Actions 发布 Linux CLI 四件套、Linux 图形客户端 tarball 与 `.deb` 四件套、Windows managed-client MSI 四件套和 Windows portable ZIP 四件套；`v0.2.0-beta.5` 与 `v0.2.0-rc.1` 已作为 prerelease 发布。历史 `v0.1.1-alpha.2` Windows manual-extract CLI zip 只保留为审计记录。
- 自客户端拆分起，本仓库 tag 只发布 Linux CLI 四件套；Linux 图形客户端、Windows MSI 与 portable ZIP、iOS App 由 [AnixOps/anixops-net](https://github.com/AnixOps/anixops-net) 发布。
- Linux artifact release-state marker：`linux-artifact-release-state=confirmed-release-path`。`docs/manual-intervention.md` 中的 license/NOTICE 状态已是 `confirmed`，但每次 Linux tag release 仍须通过同 commit CI、checksum、manifest、attestation、release notes、rollback 和 publish eligibility gates。

### 能力概览

当前 main 源码状态（含未打 tag 的切片）：

| 领域 | 当前 main |
|---|---|
| 订阅解析 | `CoreSubscriptionService` 归一化到 `SubscriptionDocument`/`NodeCatalog`：`ss://`、Trojan/VLESS/VMess、Hysteria2/TUIC share-link parser gate、Clash YAML parser gate、sing-box JSON parser gate、Surge proxy line parser gate、Loon proxy line parser gate、Quantumult X proxy/server line parser gate、明文/base64 链接列表。`rules`/`policy_groups` 可解析，但 beta.5 客户端运行时忽略。 |
| 前台运行 | Linux `run-url`/`run-catalog` 在进程内用嵌入式引擎前台启动 SOCKS5/HTTP 本地代理，默认 `127.0.0.1:7890`；订阅带规则和策略组且节点都受支持时按订阅分流。 |
| 订阅持久化与刷新 | 显式本地 JSON catalog（v0.1.2-alpha.1 起）：add/list/remove/select/update/rollback，写前 snapshot、失败保留旧 catalog。Linux `subscription refresh schedule` 生成 systemd oneshot service + timer；Windows 客户端可 opt-in 单 HTTP(S) source 小时级刷新。不扫描默认路径。 |
| 节点选择 | AnixOps Net 桌面客户端切换节点或 select 策略组时重写嵌入式引擎配置并重启；url-test/fallback 组由引擎后台测速。Linux CLI `node list/select/rollback` 管理显式选择文件。 |
| managed session 记录 | `managed-status`、`managed-event`（含 `networkcore-linux managed-event list` 有界分页查询）、`managed-log` 只读写显式 schema v1 记录，固定 `liveness_verified=false`。 |
| Linux 系统集成 | 显式确认下安装/卸载命名 systemd unit；`proxy apply/status/rollback` 写显式环境代理文件；`mitm certificate trust-apply/trust-rollback` 管理 Ubuntu-style CA trust-file。安装 tarball 本身不创建 daemon，也不改 TUN/DNS/firewall/trust store。 |
| Windows 平台 | `networkcore-windows` CLI 与 `platform-windows`：SCM service 管理、signed INF driver package lifecycle、WinINet/WinHTTP 系统代理与 LocalMachine ROOT CA 的 apply/rollback、managed lifecycle。Windows GUI、SCM service 程序、WiX MSI 与 portable ZIP 在 [AnixOps/anixops-net](https://github.com/AnixOps/anixops-net)。 |
| iOS/macOS 运行时 | `engine-embedded`（包隧道运行时，`networkcore_ios_runtime.h`）与 `node-import`（订阅导入，`networkcore_import.h`）以 C ABI 静态库供 iOS/macOS App 与包隧道扩展链接；CI 为 `aarch64-apple-ios` 构建这两个静态库。边界见 [iOS Embedded Runtime FFI Boundary Design](docs/architecture/ios-embedded-runtime-ffi-boundary-design.md)；Swift/Xcode 工程、签名与 TestFlight 在 [AnixOps/anixops-net](https://github.com/AnixOps/anixops-net)。 |
| 客户端 | Windows/Linux 桌面客户端、Windows MSI、iOS/macOS App 位于 [AnixOps/anixops-net](https://github.com/AnixOps/anixops-net)，其 CI 与 release 固定引用本仓库的一个内核 commit。 |
| MITM | 见下节。 |

## MITM

`mitm_anixops` Git submodule 固定到 upstream distribution release `v1.4.6` 的 source commit
`6382f0147e02a8653343571791ef61b8cc885cb1`（manifest digest
`sha256:3922e70f15fd0882b0617507a49ab34e223616937027718d862ba7a764c568fa`，linked C core 版本 `0.45.10`）。
`mitm-anixops-sys` 提供低层 FFI，`mitm-policy` 提供 safe wrapper、`AnixOpsMitmPluginService`、内置 `networkcore.adblock`
去广告插件包和 `ManagedSdwanMitmPolicyGate`。第三方 plugin、parser、script runtime 或兼容核心必须先走
[Third-Party Plugin Onboarding Process](docs/architecture/third-party-plugin-onboarding-process.md)。

**受控 HTTPS 数据面。** Linux `networkcore-linux start --enable-https-mitm --mitm-ca-cert <path> --mitm-ca-key <path> --confirm`
在 CONNECT authority 与 ClientHello SNI 一致时签发 authority-bound leaf、终止下游 TLS、以 web-PKI 校验上游 TLS，
并在每个 TLS session 内处理最多四个有界 HTTP/1.1 request/response exchange（reject/redirect/header/body rewrite）。
显式映射的本地脚本在无网络 namespace 和 Node 最小 read permission 下执行，失败 fail-open，不下载远程脚本。
Windows 客户端可通过 `platform-windows` 显式启用受控 HTTP/1.1 MITM 和 CA lifecycle，但在具备等价 sandbox 前拒绝脚本执行。
HTTP/2、HTTP/3/QUIC、pinning bypass、streaming、无界 CONNECT session 和 browser/system proxy mutation 均未启用；CA 私钥不进入日志或诊断。

**四个门禁：**

| Gate | 当前状态 | 下一步 |
|---|---|---|
| `MITM_CLI_COMMAND_GATE` | `mitm-cli-command-gate-status=partial-active`：status/diagnostics/certificate-plan/browser-plan、certificate、http-rewrite、browser-capture 命令可用 | 扩展到完整可操作命令面 |
| `MITM_CERTIFICATE_LIFECYCLE_GATE` | artifact-lifecycle-active/profile-trust-artifact-active/trust-mutation-blocked；另有显式 Ubuntu-style trust-file 写入/回滚 | 其他 CA 安装、信任检测、撤销和 trust-store rollback |
| `MITM_HTTP_TLS_DATA_PLANE_GATE` | `mitm http-rewrite` report 为 plain-http-live-data-plane-active/tls-decryption-blocked 的 preview 边界；不代表上面独立的 `start --enable-https-mitm` 路径 | 扩展协议与捕获范围 |
| `MITM_BROWSER_CAPTURE_GATE` | pac-policy-profile-prefs-active/system-mutation-blocked；browser hijack 为 `deferred` | 显式授权的浏览器/系统代理配置、验证和回滚 |

边界合同：[Linux MITM Certificate Lifecycle](docs/architecture/linux-mitm-certificate-lifecycle-source-contract.md)、
[Linux MITM Browser Capture](docs/architecture/linux-mitm-browser-capture-source-contract.md)、
[Linux MITM HTTP Rewrite](docs/architecture/linux-mitm-http-rewrite-source-contract.md)、
[Linux Trust-File](docs/architecture/linux-trust-file-source-contract.md)。

## Linux CLI 速查

完整说明见 [apps/linux-cli/README.md](apps/linux-cli/README.md)。所有写入系统或文件的命令都要求显式路径、snapshot 和 `--confirm`。

| 命令 | 作用 |
|---|---|
| `help` | 输出命令表 |
| `run-url <share-link>`、`run-catalog` | 嵌入式引擎前台本地代理 |
| `start` / `stop` / `status` | 原生 engine 前台 lifecycle；`SIGINT`/`SIGTERM` 退出码 130；无 daemon/control socket |
| `node list/select/rollback` | 节点列表与显式选择文件 |
| `core list` | 列出已注册的引擎描述 |
| `proxy apply/status/rollback` | 显式环境代理文件（Unix `0600`） |
| `install-service` 等 systemd 命令 | 显式安装/控制/卸载一个命名 NetworkCore systemd unit |
| `subscription add/list/remove/select/update/rollback/refresh` | 持久 catalog 与刷新 |
| `managed-status`、`managed-event`、`managed-log` | 显式 session 记录 |
| `mitm status/diagnostics/certificate-plan/browser-plan` | policy-only 状态，`mitm_status`、`certificate_plan`、`browser_plan` 字段，计划均 `mutation_ready=false` |
| `mitm certificate apply/rollback` | 写入/删除 NetworkCore CA PEM、私钥 PEM、可选 `--profile-trust-file` 副本和 snapshot，输出 `certificate_lifecycle` |
| `mitm certificate trust-apply/trust-rollback` | 显式 `--trust-file` 的 Ubuntu-style 信任文件 |
| `mitm http-rewrite plan/preview` | caller-provided plain HTTP rewrite preview，输出 `http_rewrite` |
| `mitm browser-capture plan/launch-plan/session-plan/launch/apply/rollback/verify/traffic-proof` | 输出 `browser_capture`，见下 |

`mitm browser-capture` 要点：

- `session-plan <ss://url>` 生成脱敏会话计划、dedicated 浏览器命令和带 `networkcore_proof_token` 的 `proof_target_url`；可选 `--target-url <url>`；`--proxy-scheme socks5` 绑定 `socks5://127.0.0.1:7890` 以走 native CONNECT hook。
- `launch --confirm` 启动带显式代理的 dedicated browser profile，输出 `launch_report` 与 `proxy_scheme`。
- `apply --confirm --pac-file <path> [--policy-file <path>] [--profile-prefs-file <path>] --snapshot <path>` 完成 PAC/browser policy artifact apply/rollback 与 Firefox profile prefs 写入，report 含 `profile_prefs_file_path`；不安装系统 PAC 或浏览器 policy。
- `verify --confirm` 检查本地代理端点；带 `--target-url` 时做 target route verify。
- `traffic-proof --confirm` 读取 proof log 输出 `traffic_proof_report`（proof-log-token），要求 token、proxy URL 与 CONNECT authority 绑定一致，否则 `binding_mismatch`。只证明代理会话绑定，不证明 HTTPS 解密或 rewrite 已应用。

## P4 backlog buckets

- 订阅和客户端兼容：在 `PublicEngineRunPlan` 基础上继续推进规则/策略组运行时、默认路径与运行中节点切换。
- MITM 数据面和证书生命周期：CA 安装/信任/撤销/trust-store 回滚、更多协议与 script runtime。
- 浏览器捕获用户闭环：完整 live browser traffic proof 自动化、显式 browser/system proxy 配置、系统 PAC 及回滚边界。

## 版本节奏

- `v0.1.0`：Linux-only explicit HTTPS rewrite preview，已发布正式版（alpha.14–alpha.20、rc.1 逐步交付 plain HTTP data plane、TLS termination foundation、HTTPS request/response rewrite preview、traffic-proof binding 和 release hardening）。
- `v0.1.1`：引入 Windows CLI artifact，订阅兼容为主线（各 parser gates）。
- `v0.1.2`：managed lifecycle（persistent subscription catalog、managed status/events/logs/reload/rollback、受控 script dispatch 与系统 mutation，均须显式授权且可回滚）。
- `v0.2.0`：Windows managed client（MSI 自 `v0.2.0-alpha.1`），当前候选 `v0.2.0-rc.2`（`v0.2.0-rc.1` 已发布）。

各版本精确能力边界见 [docs/alpha-release-feature-matrix.md](docs/alpha-release-feature-matrix.md)，变更历史见 [CHANGELOG.md](CHANGELOG.md)。

## 源码布局

| 路径 | 内容 |
|---|---|
| [apps/linux-cli](apps/linux-cli) | `networkcore-linux` CLI |
| [apps/windows-cli](apps/windows-cli) | `networkcore-windows` CLI |
| [apps/anixcore](apps/anixcore) | `anixcore` 节点内核：由本地管理 API 驱动的协议服务端 inbound |
| [crates/control-domain](crates/control-domain) | 领域类型与端口 trait（含维护事件契约） |
| [crates/control-runtime](crates/control-runtime) | 纯运行层编排（含 subscription catalog runtime gate） |
| [crates/config-core](crates/config-core) | 配置/订阅解析与归一化、规则与策略组模型 |
| [crates/engine-native](crates/engine-native) | 原生 SOCKS5/HTTP 执行内核：回环 listener、CONNECT relay、MITM hook、受控 TLS 数据面 |
| [crates/engine-embedded](crates/engine-embedded)、[crates/node-import](crates/node-import) | 嵌入式引擎（桌面与 iOS/macOS 包隧道共用，协议按 cargo feature 增减）与订阅导入；两者另以 C ABI 静态库供 iOS/macOS 链接 |
| [crates/engine-outbound](crates/engine-outbound) | 嵌入式引擎与协议 crate 共用的出站接口 |
| [crates/mitm-anixops-sys](crates/mitm-anixops-sys)、[crates/mitm-policy](crates/mitm-policy) | `mitm_anixops` FFI 与 safe wrapper / 插件 adapter |
| [crates/platform-linux](crates/platform-linux)、[crates/platform-windows](crates/platform-windows)、[crates/platform-ios](crates/platform-ios) | 各平台能力 adapter |

客户端源码（`apps/windows-gui`、`apps/windows-service`、`apps/linux-gui`、`apps/ios`、`installer/windows`）已连同历史迁到 [AnixOps/anixops-net](https://github.com/AnixOps/anixops-net)。

公有内核客户端参考见 [public-core-client-reference](docs/architecture/public-core-client-reference.md)；持久订阅边界见 [subscription-catalog-persistence-source-contract.md](docs/architecture/subscription-catalog-persistence-source-contract.md)。
