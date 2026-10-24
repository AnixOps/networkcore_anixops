# TODO

本文件记录当前最小增量级待办。长期方向见 [ROADMAP.md](ROADMAP.md)，验证规则见 [docs/ci-cd-policy.md](docs/ci-cd-policy.md)，各版本能力边界见 [docs/alpha-release-feature-matrix.md](docs/alpha-release-feature-matrix.md)。2026-10-22 之前的完整已完成清单已归档到 [docs/archive/todo-completed-2026-10.md](docs/archive/todo-completed-2026-10.md)。

## 当前状态

当前阶段是 P4 Client And Platform Integration。P3 runtime baseline 已完成；本文件只按 P4 backlog buckets 排优先级。

```text
current-main-release-state=pending_manual_acceptance
current-main-source-candidate=v0.2.0-rc.1
current-main-latest-published-tag=v0.2.0-beta.5
current-main-latest-stable-tag=v0.1.0
current-main-subscription-run-url=public-engine-run-plan-mieru-and-sing-box-foreground-active
current-main-subscription-foreground=public-engine-run-plan-mieru-and-sing-box-active
current-main-subscription-background=linux-systemd-oneshot-timer-and-windows-opt-in-single-source-active
current-main-managed-reload=explicit-foreground-control-socket-active
current-main-linux-node-switch=explicit-loopback-selector-active
current-main-subscription-refresh-scheduling=linux-systemd-oneshot-timer-and-windows-opt-in-single-source-active
current-main-cross-platform-run-plan=public-engine-run-plan-active
```

- 发布：当前 source 候选 `v0.2.0-rc.1`（`pending_manual_acceptance`），最新 stable `v0.1.0`。当前最新用户可下载 Linux artifact 以 GitHub Releases 中最新已发布 tag（`v0.2.0-beta.5`）的 Linux 四件套为准，stable 为 `v0.1.0`。Linux artifact marker：`linux-artifact-release-state=confirmed-release-path`（license/NOTICE 已 confirmed）；每次 tag release 仍须通过同 commit CI、checksum、manifest、attestation、release notes、rollback 和 publish eligibility gates。
- Linux `run-url` 在显式前台路径中支持 direct share links（`ss://`、Trojan、VLESS、VMess，以及 Hysteria2/TUIC share-link parser gate 覆盖的链接）、显式绝对 `file://` 订阅、一次前台 HTTP(S) fetch、`--node-id` 单次节点选择，以及 Clash YAML parser gate、sing-box JSON parser gate、Surge proxy line parser gate、Loon proxy line parser gate、Quantumult X proxy/server line parser gate 支持的 catalog payload。`run-catalog <catalog-path> <source-id>` 运行一个保存 source。
- 持久订阅：v0.1.2-alpha.1 完成 `CommandSubscriptionCatalogStore::add_source`、`CommandSubscriptionCatalogStore::list_sources`、`CommandSubscriptionCatalogStore::remove_source`、`CommandSubscriptionCatalogStore::select_source`、`CommandSubscriptionCatalogStore::update_source` 和 `CommandSubscriptionCatalogStore::rollback_catalog`。`subscription refresh start/status/stop` 处理单个已保存 HTTP(S) source（最小 300 秒间隔、先验证后原子替换、失败保留 catalog）；Linux `subscription refresh schedule install/status/stop/uninstall` 生成不含 URL/凭据的 oneshot unit + persistent timer。
- managed 记录（v0.1.2-alpha.2）：`CommandManagedForegroundSessionStore::read_status`、`CommandManagedForegroundSessionStore::write_status`、`CommandManagedForegroundSessionStore::transition_status`、`rollback_status`；`CommandManagedForegroundSessionEventStore::read_event`、`CommandManagedForegroundSessionEventStore::write_event`、`CommandManagedForegroundSessionEventStore::list_events`、`CommandManagedForegroundSessionEventStore::list_event_history`；`CommandManagedForegroundSessionLogStore::read_tail`。CLI：`networkcore-linux managed-status`（含 `networkcore-linux managed-status init`、`networkcore-linux managed-status transition`、`rollback`）、`networkcore-linux managed-event`（含 `networkcore-linux managed-event init`、`networkcore-linux managed-event list`）和 `networkcore-linux managed-log`。全部固定 `liveness_verified=false`。`start --managed-status --managed-snapshot --managed-events` 记录 foreground lifecycle；`--managed-control-socket <absolute-path>` 支持确认式跨进程 foreground stop。
- 外部 core：`core list`、`core install mieru --binary <path> --sha256 <digest>`、`core start/stop/status mieru`。
- Windows：`v0.2.0-beta.5` Tauri/React GUI 覆盖 Home、Nodes、Subscriptions、Settings、Diagnostics、Advanced；服务托管 sing-box/Mieru/EasyTier，维护唯一 runtime proxy snapshot，监督 sing-box 子进程并在异常退出时回滚。native explicit HTTP/1.1 支持有界 chunked 解码。Windows GUI/service 在具备等价 no-network sandbox 前拒绝 MITM 脚本。
- MITM：`mitm-cli-command-gate-status=partial-active`。Linux `start --enable-https-mitm` 提供受控 HTTP/1.1 TLS 数据面和 sandbox 本地脚本；`mitm certificate trust-apply/trust-rollback` 管理显式 Ubuntu-style trust-file（见 `docs/architecture/linux-mitm-certificate-lifecycle-source-contract.md`）。

## 进行中

- [ ] v0.2.0 正式版：维护者同意后打 `v0.2.0-rc.1` tag，在 rc.1 产物上完成 Windows/Linux 必须项真机验收，通过后在同一 commit 打 `v0.2.0`（人工步骤见 [docs/manual-intervention.md](docs/manual-intervention.md)）。
- [ ] 独立验收维护事件的真实运行时接线、部署与跨地域/设备环境；首批契约（[交付证据](docs/P4_EXECUTION_STATUS.md)）不代表这些后续能力完成。

## P4 backlog buckets

- [ ] 订阅和客户端兼容：运行中节点切换、默认路径、规则/策略组运行时（beta.5 解析但忽略 `rules`/`policy_groups`）、更多订阅格式，继续走 Linux/Windows 共用的 `PublicEngineRunPlan`。
- [ ] v0.1.2 managed lifecycle 剩余项：foreground runtime reload/rollback、runtime status、实时 event stream（需单独设计，不能由 history query 或 managed-log 隐式启用）、默认路径和非 Unix control socket。`networkcore-linux reload`/`service reload` 已可在显式确认下控制已安装 systemd unit。
- [ ] MITM 数据面和证书生命周期：
  - `MITM_CLI_COMMAND_GATE`：从 partial-active 扩展到完整可操作命令面。
  - `MITM_CERTIFICATE_LIFECYCLE_GATE`：artifact-lifecycle-active/profile-trust-artifact-active/trust-mutation-blocked；扩展到其他 CA 安装、信任检测、撤销和 trust-store rollback（NSS、p11-kit、浏览器 profile 等仍 blocked）。
  - `MITM_HTTP_TLS_DATA_PLANE_GATE`：`mitm http-rewrite` 仍为 plain-http-live-data-plane-active/tls-decryption-blocked preview 边界（[Linux MITM HTTP Rewrite Source Contract](docs/architecture/linux-mitm-http-rewrite-source-contract.md)）；HTTP/2、HTTP/3/QUIC、streaming 未启用；Windows 需等价 JavaScript sandbox。
- [ ] 浏览器捕获用户闭环：`MITM_BROWSER_CAPTURE_GATE` 为 pac-policy-profile-prefs-active/system-mutation-blocked（[Linux MITM Browser Capture Source Contract](docs/architecture/linux-mitm-browser-capture-source-contract.md)）；待做显式授权的浏览器/系统代理配置、系统 PAC 或其他捕获策略、完整 live browser traffic proof 自动化与回滚。browser hijack 仍 deferred。

## 版本节奏

- `v0.1.0`：Linux-only explicit HTTPS rewrite preview，已发布。
- `v0.1.1`：Windows CLI artifact 与订阅兼容主线。
- `v0.1.2`：managed lifecycle；高风险 mutation 必须显式授权、可检测、可回滚。
- `v0.2.0`：Windows managed client 与 Linux 图形客户端，当前候选 `v0.2.0-rc.1`（`v0.2.0-beta.5` 已发布）。

详细说明见 [ROADMAP.md](ROADMAP.md#版本节奏)。

## 维护规则

- 每轮迭代最多完成一个最小可验证增量。
- 新增源码前必须先有对应规格或设计说明。
- 完成项从本文件移除，并在同一变更中同步更新 [CHANGELOG.md](CHANGELOG.md)。
- 需要人工处理的外部事项必须记录到 [docs/manual-intervention.md](docs/manual-intervention.md)。
