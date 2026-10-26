# Manual Intervention List

本文件记录当前无法由本地自动化完成、需要人工处理的事项。

## v0.2.0 Release Acceptance Gate

This is the historical record of the last joint kernel + client release. The client moved to
[AnixOps/anixops-net](https://github.com/AnixOps/anixops-net) afterwards: future Windows MSI/portable, Linux GUI and iOS
acceptance, and the client sections referenced below (Windows GUI Daily Usability Acceptance, Windows 内置引擎真机验收,
Linux GUI Real-Desktop Acceptance, iOS), live in that repository's `docs/manual-intervention.md`. From now on a release
of this repository ships only the Linux CLI four-file set.

Result (2026-10-26): the maintainer reported Windows and Linux real-host acceptance passed on `v0.2.0-rc.2`
(tag on `a636b89`, release run 40244631348). `v0.2.0` was tagged on the same commit after a green dry-run
(run 40248295002). The record below is kept for the next release.

release-version=v0.2.0
release-final-version=v0.2.0
release-state=passed
release-tag-status=v0.2.0-published-on-a636b89
release-dry-run-status=passed
release-required-artifacts=linux-tarball-four-file-set,linux-gui-tarball-four-file-set,linux-gui-deb-four-file-set,windows-msi-four-file-set,windows-portable-zip-four-file-set
release-ci-source=main-same-commit-ci-summary-success-required
release-out-of-scope=macos,ios-release-assets

`v0.2.0-beta.5` was published as a prerelease on 2026-10-23 (tag on `e5b8632`) and its real-host acceptance was never
recorded; the features added since then make its artifacts unrepresentative, so acceptance moves to `v0.2.0-rc.1`.
The flow is: the maintainer approves and pushes the `v0.2.0-rc.1` tag (from a maintainer machine, since cloud sessions
cannot push tags); the operator runs the must items below on the rc.1 artifacts, plus "Windows 内置引擎真机验收" and the
`.deb` check under "Linux GUI Real-Desktop Acceptance"; when they pass, the maintainer tags `v0.2.0` on the same commit.
A must-item failure is fixed on main and re-tested as `v0.2.0-rc.2`. The tables below keep their beta.5 names; for
v0.2.0 they apply to the current candidate's artifacts, with its `release-version` in the evidence template.

`v0.2.0-rc.1` was published on 2026-10-25 (tag on `54adc04`). During acceptance, Windows imports turned out to go
through sing-box once "安装内核" had been used, so the embedded-engine items could not be tested on rc.1. rc.2 always
imports with the embedded engine and makes the compatibility core optional; acceptance continues on `v0.2.0-rc.2`.
A machine that installed sing-box under rc.1 needs no cleanup: after upgrading, re-import the subscription and check
that the "规则" mode is offered on the rules page.

The beta feature scope is frozen. Do not add new protocols, iOS activation, HTTP/2 or HTTP/3 MITM, JavaScript dispatch, LAN controller, Web UI, urltest automation, background subscription groups, TUN/DNS interception, or other new features for this release. Only real compile, test, package, contract, documentation, or release-gate fixes may be made before the tag.

Maintainer decision (2026-10-12, on branch `claude/ios-app-development-342512`, scope restated 2026-10-22): iOS activation is unfrozen for the contract-gated `apps/ios/Package.swift`, the Swift source gate, the XcodeGen `project.yml` spec and the fail-closed `NetworkCorePacketTunnel` extension target with its minimal entitlements and privacy manifests. This exception adds no `v0.2.0-beta.5` artifact and changes no Linux or Windows acceptance item. The beta freeze still applies to every other feature. iOS release assets, signing, TestFlight upload, App Store upload and App Review submission stay blocked until their own gates pass.

The `v0.2.0-beta.5` tag is maintainer-authorized to generate candidate artifacts. It remains `pending_manual_acceptance` until protected operator evidence records both Windows and Linux acceptance as passed; GitHub Actions validates package names, versions, checksums, manifests, attestations, and bundle contents, but does not replace real host acceptance.

### beta.5 必须项与可推迟项

beta.5 只用真实主机验收“候选工件能安全安装、跑通主路径、出错时不破坏主机、能干净卸载”。下面按编号引用本节下方的 Windows（W1–W14）和 Linux（L1–L14）步骤，以及本文件其他章节。必须项全部 passed 后才能把 `manual-acceptance-overall` 记为 passed；可推迟项不阻塞 beta.5，但必须在受保护证据中写明“未验收”，不得因省略而视为通过，也不得在发布说明中描述为已验收。

划分原则：会改动主机状态（系统代理、信任库、CA 私钥、服务、systemd unit、安装与卸载）的路径，以及主路径（安装、导入订阅、连接）属于必须项，因为出错会伤害主机或泄露凭据；覆盖面矩阵（DPI/主题、睡眠/重启等环境组合）、依赖外部材料的项目（签名驱动包、Authenticode）和可选试用功能属于可推迟项。

必须项（阻塞 beta.5 验收）：

| 编号 | 内容 | 范围说明 |
| --- | --- | --- |
| W1–W3 | 同一 run 的 MSI 与 portable ZIP 四件套下载、checksum、manifest 与文件清单 | 全部 |
| W4 | 干净的提权 Windows 上安装 MSI、WebView2Loader、服务注册与异步启动 | 全部 |
| W5（部分） | GUI 在 100% 和 150% DPI、浅色模式下渲染起始页并能进入六个页面 | 其余 DPI 与深色模式见可推迟项 |
| W6 | 导入本地 profile 与 HTTP(S) 订阅；更新失败保留现有配置、不切换节点、不重启 core | 全部 |
| W7–W8 | 通过 GUI 显式安装外部 sing-box core；只有全部就绪证据通过才显示 Connected | 全部 |
| W9（部分） | invalid config、missing core、occupied listener、非管理员启动四种失败：保留 profile、显示真实错误、恢复代理快照 | 其余失败场景见可推迟项 |
| W10（部分） | Disconnect、Restart service、强制终止服务、强制 core 退出后的 PID/监听清理与代理恢复 | 睡眠、重启等见可推迟项 |
| W11 | HTTPS MITM 启用/停用、CA 私钥严格 ACL、CA 撤销、监听快照恢复；JavaScript dispatch 被阻止；HTTP/2 与 HTTP/3 报告不支持 | 全部（GUI 日常验收第 10、11 条为细化步骤） |
| W13 | MSI 升级与卸载只移除 NetworkCore 自己的服务、文件和 Run 项；portable 解压不注册、不启动服务 | 全部 |
| L1–L5 | Linux 四件套 checksum、manifest、tarball 内容、非 root 只读命令与平台边界诊断 | 全部 |
| L6–L7 | 命名 systemd unit 的安装、快照、幂等重装、拒绝覆盖外部修改、connect/disconnect/restart/reload/强制停止/卸载均需 `--confirm` | 全部 |
| L8 | 安装和移除一个订阅刷新 timer，不隐式重启 core 或切换节点 | 全部 |
| L9 | MITM 证书 apply/rollback 与 trust-file trust-apply/trust-rollback；私钥 `0600`、冲突检测、回滚恢复 | 全部 |
| L10（部分） | 显式确认的 HTTP/1.1 MITM 会话：SNI 匹配与不匹配、上游 web-PKI 校验、停用与回滚清理 | 脚本沙箱细项见可推迟项 |
| L11 | pinning 绕过、HTTP/2、HTTP/3/QUIC 报告不支持并在适用处失败关闭；无 UDP 监听、TUN、DNS、防火墙或默认信任库改动 | 全部 |
| L13 | 卸载命名服务后快照保留，无关 unit、状态目录、信任文件和代理设置不受影响 | 全部 |

可推迟项（不阻塞 beta.5；验收前保持未验收状态）：

| 编号或章节 | 内容 | 推迟到 |
| --- | --- | --- |
| W5（其余） | 125%/200% DPI、深色模式、长节点名、长错误、空状态、数百节点目录 | 下一个 Windows 发布前 |
| W9（其余） | 无网络、selector 切换被拒、缺失 PID | 下一个 Windows 发布前 |
| W10（其余） | 睡眠/唤醒、重启、托盘恢复、Explorer 重启、DPI 变化、登录启动、单实例恢复 | 下一个 Windows 发布前 |
| W12 | 签名 INF 驱动包生命周期：没有维护者批准的驱动包时记录为未验收 | 获得签名驱动包后 |
| L10（其余） | 脚本哈希漂移、无网络沙箱、超时后子进程退出等脚本 dispatch 细项（Linux HTTP/1.1 MITM Acceptance 第 4、6 条） | 下一个 Linux 发布前 |
| L12 | 用第二个归档升级并回滚到旧二进制 | 第一个稳定版前 |
| Windows GUI Daily Usability Acceptance 第 1–9、12、14 条 | 日常可用性覆盖矩阵、选择器组编辑、待处理操作期间的重绘 | 下一个 Windows 发布前 |
| Windows GUI Daily Usability Acceptance 第 13 条 | Bilibili 推广请求拦截试用（默认关闭的可选功能） | 不设期限 |
| Windows managed client | Authenticode 签名（未签名警告是 beta 已知限制） | 维护者提供签名材料后 |
| Mieru Native Outbound Acceptance | 内置 Mieru 出站对远端 mita 的真机互通 | Mieru 宣称可用前 |
| 当前待处理中的运维上线环境与诊断运行时接线 | 告警渠道、独立监控、跨地域设备 | 运维上线前 |
| iOS 各章节 | iOS 不产生 beta.5 工件，按自己的门禁推进 | 不属于 beta.5 |

真实主机验收中发现必须项失败时，只修复该问题（编译、测试、打包、合同、文档或发布门禁修复），tag 之前在同一版本上重新生成候选工件，tag 之后改用下一个 beta 序号，并重做受影响的必须项；不得借机加入新功能。

### Windows Beta Acceptance

Record all detailed screenshots, raw logs, route tables, process IDs, local paths, subscription URLs, CA material, driver package evidence, and service diagnostics outside Git. Commit only the redacted status markers if a maintainer later decides to update this file.

1. Download the dry-run or tag-candidate Windows MSI, MSI sha256, MSI manifest, MSI manifest sha256, portable ZIP, portable ZIP sha256, portable manifest, and portable manifest sha256 from the same GitHub Actions run.
2. Verify both checksum files and both manifest checksum files on Windows. Confirm the manifest version is `v0.2.0-beta.5`, schema version is `2`, target is `x86_64-pc-windows-gnu`, installer format is `msi`, and the portable ZIP declares manual-extract with no extraction-time service registration.
3. Inspect the MSI and portable ZIP file lists. Confirm GUI, app-local x64 `WebView2Loader.dll`, service, CLI, installer metadata, license material, default managed config, and expected WiX product version are present; confirm no bundled or silently downloaded third-party core, signing private key, CA private key, production subscription, or secret is present.
4. On a clean elevated Windows desktop, install the MSI. Confirm `WebView2Loader.dll` is installed beside the GUI executable, the Microsoft Edge WebView2 Evergreen Runtime is available, service registration, install-time asynchronous service start behavior, uninstall metadata, and expected unsigned-installer warning if Authenticode signing is still unavailable.
5. Launch the GUI at 100%, 125%, 150%, and 200% DPI in the light, dark, and pure-black (OLED) appearances and with the system appearance switched while the window is open. Confirm the Tauri start page renders rather than remaining blank or loading indefinitely, then exercise 概览, 代理, 规则, 扩展, 活动, and 设置 with long node names, long errors, empty state, and a large catalog.
6. Import a local profile and an operator-entered HTTP(S) subscription URL. Confirm load, update, failure retention, redacted status, node diff counts, and that failed refresh does not overwrite current config, switch node, restart core, or retry the same failure.
7. Install or stage the approved external sing-box core through the explicit GUI/operator path. Confirm `sing-box check -c`, service-owned run, PID, exit, bounded log tail, and diagnostics use only service-owned paths.
8. Connect a generated NodeCatalog profile. Confirm Connected is shown only after SCM running, service-owned `check -c`, loopback listener, service-owned sing-box PID, generated selector active-outbound/default readback, and exact current-user proxy evidence all pass.
9. Force failures for invalid config, missing core, occupied listener, no network, rejected selector switch, missing PID, and non-admin launch. Confirm the GUI preserves usable profile state, shows truthful unavailable/error states, restores proxy snapshots, and does not submit duplicate mutations.
10. Test Disconnect, Restart service, forced service termination, forced core exit, sleep/resume, reboot, tray restore, Explorer restart, display DPI change, login startup, and single-instance restore. Confirm owned PID/listener cleanup and exact GUI-owned proxy recovery.
11. Exercise HTTPS MITM enable/disable for native JSON and generated profiles. Confirm service-owned CA lifecycle, strict private-key ACL, snapshot restore, CA revoke/remove, native mixed-in listener snapshot/restore, and blocked JavaScript dispatch. Confirm HTTP/2 and HTTP/3/QUIC MITM remain unsupported.
12. Exercise driver lifecycle only with an operator-provided signed INF package. Confirm NewDev install/remove boundaries and license/NOTICE evidence. If no approved driver package exists, record that driver lifecycle remains unaccepted rather than passing it by omission.
13. Verify MSI upgrade/uninstall removes only NetworkCore-owned service, files, and matching Run entry. Verify portable extraction does not register or start a service and that portable login startup is explicitly disabled before moving the directory.
14. Record Windows acceptance as passed only if install, GUI, service, proxy, CA, driver-package boundary, portable, failure, rollback, and cleanup evidence all pass on a real Windows host.

### Linux Beta Acceptance

1. Download the Linux tarball, tarball sha256, manifest, and manifest sha256 from the same GitHub Actions run as the Windows artifacts.
2. Verify both checksum files on Linux. Confirm the manifest version is `v0.2.0-beta.5`, target is `x86_64-unknown-linux-gnu`, package is `networkcore-linux`, install model is manual-extract, and rollback policy is manual version switch.
3. Inspect the tarball before extraction. Confirm one top-level directory, `bin/networkcore-linux`, license material, pinned `libexec/anixops-runner.js`, and no installer, systemd unit, private key, CA material, bundled third-party proxy core, production subscription, or secret.
4. Extract into a versioned user-selected directory on a supported Ubuntu LTS/systemd host. Run only read-only/version/help commands from the extracted `bin` path without root and record stable output.
5. Confirm plain platform status remains read-only and unsupported or non-systemd environments return documented stable boundary diagnostics without daemon discovery or host mutation.
6. Install one named NetworkCore systemd unit using explicit executable, state directory, snapshot path, and `--confirm`. Record unit pre-write snapshot, exact readback, daemon reload, bounded restart policy, and idempotent reinstall.
7. Introduce an external unit-file change and verify reinstall refuses to overwrite it. Exercise connect, disconnect, restart, status with service unit, reload, forced stop, and uninstall. Confirm each mutation requires explicit confirmation and affects no unrelated unit.
8. Install and remove one explicit subscription refresh timer with redacted test source. Confirm timer/service names, daemon reload, one bounded refresh result, retained refresh status, and no implicit core restart or node switch.
9. Exercise MITM certificate artifact apply/rollback and Ubuntu-style trust-file trust-apply/trust-rollback with explicit cert, key, trust-file, snapshot, and `--confirm`. Confirm private key mode `0600`, precise trust-file readback, refresh result, conflict detection, and rollback restoration.
10. Start an explicitly confirmed HTTP/1.1 MITM session with generated CA material. Record authority/SNI match, SNI mismatch failure, web-PKI upstream verification, bounded request/response rewrite, fail-open script behavior, script hash drift, no-network sandbox, and disable/rollback cleanup.
11. Confirm certificate/public-key pinning bypass, HTTP/2 MITM, and HTTP/3/QUIC MITM are reported unsupported and fail closed where applicable. Confirm no UDP/QUIC listener, browser hijack, system PAC, TUN, DNS, firewall, or default trust backend mutation is introduced.
12. Upgrade by extracting a second verified archive to a separate directory, repointing the named unit through the documented snapshot-protected path, then restoring the previous binary. Confirm service and selected explicit configuration recover.
13. Uninstall the named service and remove only the extracted version directory manually after rollback. Confirm snapshots remain and unrelated units, state directories, trust files, and proxy settings are untouched.
14. Record Linux acceptance as passed only if archive, systemd, subscription refresh, trust-file, MITM HTTP/1.1, upgrade, rollback, and cleanup evidence all pass on a real supported Linux host.

### Protected Evidence Template

```text
release-version=v0.2.0-beta.5
release-state=pending_manual_acceptance|passed|failed
candidate-commit=[commit-sha]
ci-run=[github-actions-ci-url]
release-dry-run=[github-actions-release-url]
linux-artifacts=[redacted-file-list-and-sha256-pass|fail]
windows-artifacts=[redacted-file-list-and-sha256-pass|fail]
windows-msi-acceptance=[pending|passed|failed]
windows-portable-acceptance=[pending|passed|failed]
windows-gui-service-proxy-ca-driver-acceptance=[pending|passed|failed]
linux-archive-systemd-acceptance=[pending|passed|failed]
linux-trust-mitm-acceptance=[pending|passed|failed]
manual-acceptance-overall=[pending|passed|failed]
deferred-items-unaccepted=[comma-separated-item-ids-from-the-deferred-table]
operator=[operator-id]
recorded-at=[utc-timestamp]
```

Keep `release-state=pending_manual_acceptance` until every required Windows and Linux row is passed. A failed or missing row blocks production-ready acceptance and must be fixed or explicitly documented before promotion beyond the maintainer-authorized beta tag. For beta.5, each row covers only the must items in "beta.5 必须项与可推迟项"; for example `windows-gui-service-proxy-ca-driver-acceptance` may pass while W12 is listed in `deferred-items-unaccepted`.

## 客户端人工事项（已迁移）

客户端已连同历史迁到 [AnixOps/anixops-net](https://github.com/AnixOps/anixops-net)。以下人工事项及其状态 marker 现在记录在该仓库的
`docs/manual-intervention.md`，本仓库不再维护：

- Windows managed client（MSI Authenticode 签名、签名 INF 驱动包）、Windows GUI Daily Usability Acceptance、
  Windows 内置引擎与去除第三方内核/SD-WAN 隧道后的真机验收、Windows Tauri/pnpm lockfile 刷新、Alpha Windows Manual Smoke Test；
- Linux GUI Real-Desktop Acceptance（`anixops-net` tarball 与 `.deb`）；
- iOS Activation Status、iOS 真机验收（M1a、WireGuard、全协议导入、订阅规则与策略组、订阅链接与节点切换）、
  iOS Widget And Control Center Setup、iOS App Review Manual Confirmation、iOS TestFlight/App Store Connect Upload Workflow；
- macOS App Signing And TestFlight。

本仓库只保留内核相关的人工事项：Linux artifact 与 managed-service、Linux HTTP/1.1 MITM、HTTP/2/HTTP/3 依赖刷新、
协议出站真机互通，以及 Linux artifact license/NOTICE 确认。

## Linux HTTP/1.1 MITM Acceptance

GitHub Actions covers source contracts, disposable loopback TLS exchanges, and
the Ubuntu-style trust-file command boundary. It cannot certify a supported
Ubuntu LTS host's trust database, browser behavior, certificate pinning, or
real HTTP/2/HTTP/3 application behavior. Before describing Linux HTTPS MITM as
operational, retain the following protected operator evidence without CA keys,
subscription URLs, or full traffic contents:

1. On a supported Ubuntu/systemd baseline, use `networkcore-linux mitm
   certificate apply --confirm` with explicit artifact and snapshot paths.
   Record that the generated CA private key is a regular `0600` file and that
   certificate artifact rollback removes only the matching NetworkCore-created
   files. Do not record the private key or its PEM content.
2. Use explicit `mitm certificate trust-apply --cert-file`, `--trust-file`,
   `--snapshot`, and `--confirm`; capture the before/after trust-file and
   refresh evidence. Use `trust-rollback` and confirm snapshot-verified removal
   restores the prior trust-file state without touching unrelated certificates.
3. Start only an explicitly confirmed HTTP/1.1 MITM session with the generated
   CA material. Record authority/SNI match success, a controlled SNI mismatch
   failure, web-PKI upstream verification, bounded request/response exchange,
   and disable/rollback evidence. A failed start must not leave a new trust-file
   or proxy mutation behind.
4. Send bounded HTTP/1.1 request and response rewrite fixtures through the
   explicit proxy. Capture reject, redirect, header, and allowed content-type/
   body-size rewrite evidence, plus one oversized or disallowed-content failure
   that leaves the original response unmodified.
5. Preserve the JSON report values
   `certificate_pinning_bypass_supported=false`, `http2_mitm_supported=false`,
   and `http3_quic_mitm_supported=false`. Test an application with certificate
   or public-key pinning and confirm its handshake fails closed: NetworkCore
   must not claim a bypass. Confirm HTTP/2 and HTTP/3/QUIC traffic remains out
   of scope and that no UDP/QUIC listener or HTTP/2 interception behavior is
   introduced.
6. For an explicitly configured local script asset, retain its authorized
   SHA-256 and one successful bounded dispatch. Confirm the runner can read only
   its mapped local asset and staged body, is capped at 64 MiB V8 old-space,
   cannot write a file, spawn a child process, load an addon, or reach a network
   endpoint. Trigger a timeout and preserve evidence that its sandboxed Node
   child also exits and the fail-open result is reported as `script_dispatch_failed`,
   not deferred. Replace the asset while the runtime remains active,
   repeat the matching request, and record the deferred fail-open result with no
   Node execution.

## Linux Artifact And Managed-Service Acceptance

GitHub Actions verifies the Linux archive layout, checksum/manifest pair,
attestation request, and injected systemd contracts. It cannot prove a real
Ubuntu LTS/systemd host's privilege boundary, service manager behavior, desktop
proxy restoration, or operator-controlled upgrade and removal. Before treating
the Linux artifact or managed-service path as operational, retain the following
protected operator evidence without subscription URLs, credentials, CA private
keys, or complete log content:

1. Download one tagged Linux archive and its four release files (archive,
   archive checksum, manifest, and manifest checksum). Verify both checksums,
   inspect the manifest file list, and extract into a versioned user-selected
   directory. Confirm the archive has no installer, systemd unit, private key,
   or third-party core binary and that `networkcore-linux version` runs from the
   extracted `bin` path without root.
2. On a supported Ubuntu LTS host with systemd, confirm plain `status` remains
   platform-only and that unsupported or non-systemd environments return the
   documented stable boundary instead of discovering a daemon or modifying host
   state. Preserve only command exit codes and stable diagnostic codes.
3. With a disposable non-root service account, install one named NetworkCore
   unit using explicit executable, state directory, and `--confirm`. Record the
   pre-write unit snapshot, exact readback verification, `systemctl` action
   result, and the unit's bounded restart policy. Reinstall unchanged content
   to prove idempotence, then introduce an external unit-file change and prove
   the operation refuses to overwrite it.
4. Exercise `connect`, `disconnect`, `restart`, `status --service-unit`, and
   `service reload` against that same named unit. Record that each mutation
   requires explicit confirmation, affects no other unit, and that failure does
   not claim a running runtime. Force-stop the service and record the cleanup
   of its owned listener/process and any explicit environment-proxy rollback.
5. Install one explicit subscription refresh timer with a redacted test source.
   Record daemon reload, timer activation, one bounded refresh result, stop,
   and uninstall. Confirm the timer/service pair removal retains the refresh
   status record and does not restart a core or switch a node.
6. Upgrade by extracting a second verified archive to a separate versioned
   directory, preserving the prior directory and its checksum evidence. Point
   the explicitly managed unit at the new binary only through the documented
   snapshot-protected update path, then restore the previous binary and verify
   the service and selected explicit configuration recover. Do not replace an
   archive in place.
7. Uninstall using the original unit name and state directory with
   `uninstall-service --confirm`. Verify only the NetworkCore-owned unit is
   removed, its non-overwriting snapshot remains, no unrelated unit or state
   directory is deleted, and the extracted version directory can then be
   removed manually. If trust-file mutation was exercised, run the matching
   `mitm certificate trust-rollback --confirm` first and retain its readback
   evidence.

These proofs complement the GitHub Actions contracts; their absence means the
Linux artifact and managed-service paths remain source/CI validated rather than
manually accepted on the target host.

## HTTP/2 and HTTP/3 MITM Dependency Lock Refresh

The native MITM path now contains an HTTP/2 data plane
(`crates/engine-native/src/h2_mitm.rs`, design in
`docs/architecture/http2-mitm-design.md`) built on the maintained `h2`, `http`,
`bytes`, `tokio`, and `tokio-rustls` crates. HTTP/3/QUIC is not intercepted;
UDP/443 to MITM hostnames is refused through `plan_native_udp_mitm_decision`
so clients fall back to TCP TLS. Until the steps below are recorded, the
`http2_mitm_supported` and `http3_quic_mitm_supported` markers stay `false`.

Lock refresh for this slice: dispatch `.github/workflows/refresh-cargo-lock.yml`
on the feature branch with `strategy=add-missing`, which resolves only the new
dependencies and keeps existing pins, then commit the downloaded artifact.

Real-host acceptance still required: on Linux and Windows, point Chrome and
Firefox at the explicit HTTP proxy with the MITM CA trusted, open an HTTPS site
in the plugin hostname list that serves HTTP/2, and confirm the browser reports
`h2`, a reject rule blocks its URL, a header rewrite is visible, and a large
download completes unmodified (passthrough). Repeat against an HTTP/1.1-only
origin to confirm the fallback. Record the result and any pinned-certificate
failures here.

The original constraints below still apply. A live HTTP/2/HTTP/3
implementation must use maintained protocol crates for HTTP/2
framing/HPACK and HTTP/3/QUIC/QPACK; it must not add hand-written protocol
parsers to the blocking listener. The maintainer must resolve and commit the
Cargo.lock changes from an authorized GitHub Actions dependency-refresh run,
then run the locked Linux, macOS, and Windows Rust matrix before source or
release markers can claim H2/H3 support. The refresh must also record the
selected crate versions, license/NOTICE review, ALPN behavior, QUIC UDP
listener boundary, bounded stream/body limits, and rollback behavior. No local
dependency resolution, build, or protocol runtime smoke test is allowed.

## Mieru Native Outbound Acceptance

`outbound-mieru` is the built-in Mieru client, written clean-room from
`docs/protocols/mieru.md`. The external Mieru core and its binary allowlist are
gone. CI checks it two ways:

- Loopback contract tests.
- The `REALITY interop (Linux)` job, which runs it against the official `mita`
  package. The package is installed on the runner from the enfein/mieru GitHub
  release and is never redistributed.

CI cannot prove behaviour against a real remote server. Before calling Mieru
production-ready on a platform:

1. Import a test `mierus://` simple share link (or a Clash `type: mieru`
   entry) for a TCP port binding on a remote `mita` server.
2. Browse and download through it on iOS, Windows and Linux.
3. Record the platform, the `mita` version and the result here. Leave out
   addresses and credentials.
4. Confirm that UDP-only links and nodes are reported as unsupported rather
   than failing silently. The UDP transport, multiplexing and low-entropy
   segments are not implemented yet.

## VLESS + REALITY Outbound Acceptance (M1b)

`tls-mimic` and `outbound-vless` are validated in CI only: contract tests, a
direct TLS 1.3 handshake against OpenSSL, and the `REALITY interop (Linux)` job
against Xray-core and sing-box REALITY servers on loopback. CI cannot prove
that a real server survives active probing or that the ClientHello passes a
real censor.

Before describing VLESS + REALITY as usable on iOS, the maintainer records here
(no keys, UUIDs, short ids or server addresses):

- the server software and version, the camouflage target domain class, and
  whether Vision was enabled;
- a capture or JA3/JA4 comparison showing the outbound ClientHello matches the
  current desktop Chrome release it claims to imitate;
- a multi-hour transfer on the target network with no resets or blocks, once
  through `engine-embedded` on an iPhone after M1a wires the outbound in.

## 当前待处理

- 首批运维上线环境尚未提供：真实邮件/Telegram 接收渠道、第三方独立 Control 监控、跨地域节点和设备以及维护负责人。当前自动化只能运行测试适配器与代码 CI，不能证明这些真实环境门槛。维护负责人补齐渠道与部署范围后，记录投递/监控/网络/设备及回滚演练证据，再由 CI/CD 推进获准的灰度发布；真实地址与密钥仅放部署系统或密码库。
- NetworkCore 的首批诊断库不含宿主运行时事件接线。后续实现真实观察源、宿主认证身份和持久化发送适配后，需在 CI 中补 Agent/Control 的端到端验收，再安排环境演练。

- `third_party/mitm_anixops` 只能固定在已发布的 release commit（当前 v1.4.6 / `6382f01`，CI policy 同时校验 tag object 与 manifest digest）。mitm_anixops main 上的 `6c71236`（脚本 runner 在 Windows 上替换 store 文件时对 EPERM/EACCES/EBUSY 重试，修复 Windows engine-native 偶发失败）需要维护者批准并发布 mitm_anixops 新版本后，再在独立 PR 中同步更新 submodule、`ci.yml` 与 `managed-sdwan-mitm-policy-gate-source-contract.md` 中的 release tag/commit/manifest 字段。

## 已完成的人工/外部事项

1. 已确认 GitHub 远端地址：`https://github.com/AnixOps/networkcore_anixops.git`。
2. 已初始化本地仓库并绑定远端。
3. 已为 GitHub CLI 授权 `workflow` scope，使其可以推送 GitHub Actions workflow。
4. 已推送 bootstrap 文件并打通 CI。
5. 已确认 `v0.1.0-alpha.1` alpha Windows 手工 smoke 测试通过；候选 commit 为
   `67e86a84388023df77e53537f3f209b5a05c1682`，CI run 为 `28901464670`，release run 为
   `28901692913`，确认环境为 Windows 11 24H2 x64，且未运行本地构建或测试。
6. 已确认 Linux CLI artifact 使用仓库 `LICENSE` 的 `Apache-2.0`，`NOTICE=not-required`，
   artifact files 为 `LICENSE`；该确认只解除 license/NOTICE 人工门禁，真实二进制仍必须由
   GitHub Actions 的 CI、checksum、manifest、attestation、release notes、rollback 和 publish
   eligibility gates 生成、校验和发布。

## 后续 CI 观察命令

需要观察 CI 时运行：

```bash
gh workflow run ci.yml
gh run list --workflow ci.yml --commit <commit-sha> --limit 2
```

编码 Agent 对当前 commit 只允许进行一次、最多两次上述非阻塞查询。不得使用 `gh run watch`、
无限循环或长时间 sleep。若 run 仍为 `queued`/`in_progress`，记录 commit SHA、workflow、run ID、
run URL 和状态，以 `task_state: pending_ci`、`next_action: resume_after_ci_completion` 交接；失败时
只读取失败 job/step 日志，成功 job 日志不重复下载。

如果 GitHub CLI 不可用，可在 GitHub 网页端进入 `Actions`，选择 `CI`，手动触发 `workflow_dispatch`。

## 后续预计人工事项

iOS/macOS（Apple Developer、App Store Connect、TestFlight、App Review）与 Windows 代码签名相关的人工事项随客户端在 AnixOps/anixops-net 跟踪。

后续涉及新的平台 release artifact、artifact 范围扩大或 license/NOTICE 来源变化时，还需要人工处理：

- 对应平台或新增 artifact 文件集合的 license/NOTICE 文本确认；Linux `networkcore-linux` 当前范围已确认，
  但范围变化前不得复用旧确认绕过 release gates
- GitHub Environments、protected tags、branch protection 和 release approval policy 配置
- 第三方发布渠道账号、API token、税务或合规材料确认

## Linux Artifact License/NOTICE Confirmation

以下字段是 release readiness 读取的机器状态。license/NOTICE 人工确认已完成；
该确认只允许进入后续 GitHub Actions gates，不表示可跳过 CI、checksum、manifest、
attestation、release notes、rollback 或 publish eligibility。

```text
linux-artifact-release-state=confirmed-release-path
linux-artifact-license-notice-status=confirmed
linux-artifact-license-notice-source-contract=docs/architecture/linux-artifact-license-notice-confirmation.md
linux-artifact-license-notice-transition-contract=docs/architecture/linux-package-license-notice-transition-validation-contract.md
linux-artifact-license-notice-transition-commit=independent-manual-confirmation-commit
linux-artifact-license-notice-confirmed-at=2026-07-08
linux-artifact-license-notice-confirmed-by=operator
linux-artifact-license-notice-scope=networkcore-linux
linux-artifact-license-notice-license-source=LICENSE
linux-artifact-license-notice-notice-source=not-required
linux-artifact-license-notice-artifact-files=LICENSE
linux-artifact-license-notice-package-linux=eligible-after-ci-and-release-gates
linux-artifact-license-notice-release-assets=eligible-after-package-signing-checksum-and-rollback-gates
```

`package-linux` 和 release assets 仍必须遵守
`docs/architecture/linux-package-license-notice-transition-validation-contract.md`、同 commit CI、
checksum/manifest、attestation、release notes、rollback 和 publish eligibility gates。
