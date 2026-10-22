# Manual Intervention List

本文件记录当前无法由本地自动化完成、需要人工处理的事项。

## v0.2.0-beta.5 Release Acceptance Gate

release-version=v0.2.0-beta.5
release-state=pending_manual_acceptance
release-tag-status=blocked-pending-manual-acceptance
release-dry-run-status=pending_github_actions_validation
release-required-artifacts=linux-tarball-four-file-set,windows-msi-four-file-set,windows-portable-zip-four-file-set
release-ci-source=main-same-commit-ci-summary-success-required

The beta feature scope is frozen. Do not add new protocols, iOS activation, HTTP/2 or HTTP/3 MITM, JavaScript dispatch, LAN controller, Web UI, urltest automation, background subscription groups, TUN/DNS interception, or other new features for this release. Only real compile, test, package, contract, documentation, or release-gate fixes may be made before the tag.

Maintainer decision (2026-10-12, on branch `claude/ios-app-development-342512`, scope restated 2026-10-22): iOS activation is unfrozen for the contract-gated `apps/ios/Package.swift`, the Swift source gate, the XcodeGen `project.yml` spec and the fail-closed `NetworkCorePacketTunnel` extension target with its minimal entitlements and privacy manifests. This exception adds no `v0.2.0-beta.5` artifact and changes no Linux or Windows acceptance item. The beta freeze still applies to every other feature. iOS release assets, signing, TestFlight upload, App Store upload and App Review submission stay blocked until their own gates pass.

The `v0.2.0-beta.5` tag is maintainer-authorized to generate candidate artifacts. It remains `pending_manual_acceptance` until protected operator evidence records both Windows and Linux acceptance as passed; GitHub Actions validates package names, versions, checksums, manifests, attestations, and bundle contents, but does not replace real host acceptance.

### beta.5 必须项与可推迟项

beta.5 只用真实主机验收“候选工件能安全安装、跑通主路径、出错时不破坏主机、能干净卸载”。下面按编号引用本节下方的 Windows（W1–W14）和 Linux（L1–L14）步骤，以及本文件其他章节。必须项全部 passed 后才能把 `manual-acceptance-overall` 记为 passed；可推迟项不阻塞 beta.5，但必须在受保护证据中写明“未验收”，不得因省略而视为通过，也不得在发布说明中描述为已验收。

划分原则：会改动主机状态（系统代理、信任库、CA 私钥、服务、systemd unit、安装与卸载）的路径，以及主路径（安装、导入订阅、连接）属于必须项，因为出错会伤害主机或泄露凭据；覆盖面矩阵（DPI/主题、睡眠/重启等环境组合）、依赖外部材料的项目（签名驱动包、Authenticode、Mieru、EasyTier POP）和可选试用功能属于可推迟项。

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
| Mieru External Core Acceptance | Mieru 外部 core 互通 | Mieru 宣称可用前 |
| Windows Foreground Tunnel Manual Acceptance 与 Stage 4 POP | EasyTier 前台隧道与 POP 对端 | 隧道宣称可用前 |
| 当前待处理中的运维上线环境与诊断运行时接线 | 告警渠道、独立监控、跨地域设备 | 运维上线前 |
| iOS 各章节 | iOS 不产生 beta.5 工件，按自己的门禁推进 | 不属于 beta.5 |

真实主机验收中发现必须项失败时，只修复该问题（编译、测试、打包、合同、文档或发布门禁修复），tag 之前在同一版本上重新生成候选工件，tag 之后改用下一个 beta 序号，并重做受影响的必须项；不得借机加入新功能。

### Windows Beta Acceptance

Record all detailed screenshots, raw logs, route tables, process IDs, local paths, subscription URLs, CA material, driver package evidence, and service diagnostics outside Git. Commit only the redacted status markers if a maintainer later decides to update this file.

1. Download the dry-run or tag-candidate Windows MSI, MSI sha256, MSI manifest, MSI manifest sha256, portable ZIP, portable ZIP sha256, portable manifest, and portable manifest sha256 from the same GitHub Actions run.
2. Verify both checksum files and both manifest checksum files on Windows. Confirm the manifest version is `v0.2.0-beta.5`, schema version is `2`, target is `x86_64-pc-windows-gnu`, installer format is `msi`, and the portable ZIP declares manual-extract with no extraction-time service registration.
3. Inspect the MSI and portable ZIP file lists. Confirm GUI, app-local x64 `WebView2Loader.dll`, service, CLI, installer metadata, license material, default managed config, and expected WiX product version are present; confirm no bundled or silently downloaded third-party core, signing private key, CA private key, production subscription, or secret is present.
4. On a clean elevated Windows desktop, install the MSI. Confirm `WebView2Loader.dll` is installed beside the GUI executable, the Microsoft Edge WebView2 Evergreen Runtime is available, service registration, install-time asynchronous service start behavior, uninstall metadata, and expected unsigned-installer warning if Authenticode signing is still unavailable.
5. Launch the GUI at 100%, 125%, 150%, and 200% DPI in light and dark modes. Confirm the Tauri start page renders rather than remaining blank or loading indefinitely, then exercise Home, Nodes, Subscriptions, Settings, Diagnostics, and Advanced with long node names, long errors, empty state, and a large catalog.
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

## Windows managed client

The managed Windows client is implemented and its MSI is built and validated in
GitHub Actions. The current beta MSI is intentionally unsigned because an
Authenticode certificate/private key must be supplied by the maintainer through
a protected GitHub Actions secret or an external signing service; signing
material must never be committed. Until that secret is configured, Windows may
show the normal unsigned-installer warning, but the MSI, service, GUI, proxy,
certificate, and driver lifecycle remain functional.

The driver lifecycle accepts an operator-provided signed INF package. A driver
vendor or maintainer must provide the package and its license/NOTICE evidence;
the Windows service installs and removes it through NewDev only after Windows
validates the package signature. After the package and optional Authenticode
secret are configured, rerun the Windows MSI CI/release workflow; no local
installer or signing validation is allowed.

## Windows GUI Daily Usability Acceptance

The headless GitHub Actions Windows runner verifies source, Rust tests, MSI
install/uninstall, and portable ZIP contents. It cannot verify visual layout,
DPI, shell ownership, interactive-user proxy state, or suspend/resume. Record
the following from an elevated Windows desktop before calling the daily GUI
experience production-ready:

1. At 100%, 125%, 150%, and 200% DPI, resize the window to its normal and
   minimum useful size. Check light and dark modes, long node names, long
   errors, empty subscription state, and a catalog with several hundred nodes.
2. Import a local NodeCatalog profile and an HTTP(S) URL. Confirm the Nodes
   page search/filter/selection, a successful explicit update, and a failed
   update retaining the prior managed config and displaying its error. Restart
   with networking disabled and confirm unchanged generated config restores the
   saved node names/protocols without fetching; after externally changing that
   config, confirm the stale catalog is not restored.
3. With a running generated profile, confirm `Check core`, one delay test, and
   a successful selector switch. Disconnect and reconnect, then use `Restart
   service`; verify the newly selected node remains active and the interactive
   proxy is restored while the core restarts, then reapplied only after the
   listener and selector are ready. Make `sing-box check -c` fail and confirm
   Restart does not stop the existing service or change the interactive proxy.
   Force a rejected switch and verify the former selected node remains displayed.
4. Confirm Home reports `Connected` only after SCM is running, `sing-box check -c`
   succeeded, the service-owned sing-box child exists, the selected loopback
   listener accepts connections, and the interactive user's proxy exactly
   matches the managed setting. For a NodeCatalog profile, verify the loopback
   selector API's active outbound equals its generated default before the proxy
   changes, then force an API failure or mismatched selection and verify the
   service records failure, restores the proxy, and stops. Test missing
   service/core, invalid config, occupied port, no network, and a
   non-administrator launch/elevation rejection.
5. Stop and forcibly terminate the service separately, force a core exit,
   close/reopen the GUI, sleep/resume, and reboot Windows. After the forced
   Service exit, verify its owned sing-box PID and listener are gone before the
   next start. For each case verify the interactive-user proxy is restored or
   an explicit recovery failure is shown; capture the GUI, service, and core
   diagnostic report paths.
6. Verify MSI upgrade/uninstall and portable extraction separately. Enable
   login startup first, then confirm MSI uninstall removes only NetworkCore's
   matching Run value. The portable ZIP must not register or start a service on
   extraction; its GUI still exposes the explicit service-install path and its
   optional login startup must be disabled before moving the extracted folder.
7. Capture before/after screenshots on the same Windows/DPI/theme setup for
   the release evidence. Source-only and headless CI runs cannot produce an
   authoritative desktop screenshot.
8. Enable login startup and sign in again. Confirm NetworkCore creates its
   tray icon before hiding the main window; launch it again from the installed
   shortcut and from its login-startup entry. Confirm the existing hidden
   window is restored and no second GUI process can submit a competing
   connect, disconnect, or proxy operation.
9. While the main window is hidden, restart Explorer or change the primary
   display DPI. Confirm the NetworkCore notification-area icon returns with
   its current shared status tooltip and can restore the window. If an
   interrupted GUI-owned proxy recovery fails, confirm it stops after that
   attempt, shows the in-page recovery error, and `Restore network settings`
   performs the explicit retry.
10. With an elevated Windows desktop, enable and disable HTTPS MITM for both a
    native sing-box JSON profile and a generated NodeCatalog profile. Confirm
    the service proxy points at the native local listener while enabled, the
    native JSON listener snapshot is restored on disable, and the
    service-recorded CA is removed. Before disable, inspect
    `%ProgramData%\\AnixOps\\NetworkCore\\mitm\\root-ca-key.pem`: inheritance
    must be disabled and only the generating account and `SYSTEM` may have
    access. Stop the service, deliberately add a third ACL entry, and start it
    again: verify MITM fails before installing its CA or applying its proxy and
    any previously recorded managed CA is revoked while the existing rollback
    restores the previous proxy state. Restore the strict ACL,
    then confirm the private key is deleted after disable.
11. With native HTTPS MITM disabled and the service stopped, retain or manually
    stage a legacy managed Script dispatch configuration containing a local
    policy source, Node runner, Node executable, and HTTP(S)-URL-to-script
    mapping. Confirm the GUI refuses new configuration and HTTPS MITM enable
    before it stops the service or creates CA material. Confirm a direct service
    start rejects the legacy configuration before installing a CA certificate,
    changing the system proxy, or reading the policy/runner. Clear the legacy
    runtime, then verify normal HTTPS MITM enable/disable remains available.
12. Import a native sing-box profile containing both a selector and a
    non-selector outbound group. With the service stopped, record the listed
    groups, switch the selector default to a listed member, and replace one
    group's same-tag JSON using its Advanced editor. Verify the saved managed
    JSON changes only that group, start the service, and retain the relevant
    sing-box check/runtime evidence. Restore the original group JSON after
    the proof.
13. With HTTPS MITM disabled, choose the first-party Bilibili web promotional
    request-blocking trial in Advanced, enable HTTPS MITM, and use a Bilibili
    web search page through the trusted local proxy. Record only redacted
    evidence that recommendation-word requests are rejected and normal home
    feed/video/comment requests still work. Then disable the selection,
    re-enable HTTPS MITM, and confirm the general policy is restored. Do not
    add CA keys, cookies, URLs containing tokens, or raw traffic captures to
    Git.
14. While each of Connect, Disconnect, Restart service, selector check/switch,
    service install/start/stop, proxy recovery, TUN/DNS/script configuration,
    HTTPS MITM enable/disable, and certificate/driver lifecycle is pending,
    keep the GUI visible and interact with a non-mutating view. Confirm its
    window continues to repaint and shows a single pending operation instead
    of freezing or submitting a duplicate mutation. Record any SCM, UAC, or
    system-API delay that cannot be reproduced in headless CI.

GitHub-hosted Windows runners cannot provide WebView interaction, an operator's
trusted MITM CA, locally approved Node runner and script assets, or authoritative
live traffic through the interactive desktop proxy. The above evidence complements,
rather than replaces, the GitHub Actions Rust, TypeScript, MSI, and portable-package
verification.

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

## Windows Tauri Dependency Lock Refresh

The Windows GUI now declares Tauri and a pnpm-managed React frontend. Repository
policy prohibits generating Cargo or pnpm lockfiles locally. Use
`.github/workflows/refresh-cargo-lock.yml` for `Cargo.lock` and
`.github/workflows/refresh-pnpm-lock.yml` for
`apps/windows-gui/ui/pnpm-lock.yaml`. The initial pnpm lockfile was generated
by GitHub Actions run `30288969826`; future updates must likewise download only
the generated workflow artifact, review it, and commit it before the `--locked`
Rust and frozen pnpm
checks can pass. After that commit, rerun CI and the Windows MSI workflow; do not
generate either lockfile on a developer workstation.

## HTTP/2 and HTTP/3 MITM Dependency Lock Refresh

The current native MITM path deliberately remains HTTP/1.1. A future live
HTTP/2/HTTP/3 implementation must use maintained protocol crates for HTTP/2
framing/HPACK and HTTP/3/QUIC/QPACK; it must not add hand-written protocol
parsers to the blocking listener. The maintainer must resolve and commit the
Cargo.lock changes from an authorized GitHub Actions dependency-refresh run,
then run the locked Linux, macOS, and Windows Rust matrix before source or
release markers can claim H2/H3 support. The refresh must also record the
selected crate versions, license/NOTICE review, ALPN behavior, QUIC UDP
listener boundary, bounded stream/body limits, and rollback behavior. No local
dependency resolution, build, or protocol runtime smoke test is allowed.

## Mieru External Core Acceptance

The source and contract layers now require an operator-supplied Mieru binary or
an explicitly confirmed `enfein/mieru` GitHub release asset with a pinned
SHA-256 digest. Before calling Mieru production-ready, record the selected
release URL, digest, license/NOTICE evidence, and binary provenance in the
protected release record. Do not place the binary, credentials, or client JSON
in the repository or diagnostic artifact.

On a supported Windows host and an Ubuntu/systemd Linux host, import a test
`mierus://` node, render the client config, run the official Mieru `apply
config`, `start`, and `status` flow, and verify that the loopback SOCKS5 port
accepts connections through the intended remote node. Stop the client and
confirm the loopback listener, system proxy, and service-owned temporary state
are cleaned up. Terminate the official client unexpectedly and preserve the
failed-state, status-check, listener-check, and proxy-rollback evidence.

The automated contracts verify source allowlisting, digest checks, command
ordering, redaction, and bounded loopback probing; they do not prove external
Mieru server interoperability, real traffic forwarding, or Windows GUI/DPI
behavior. Those results must be recorded here before M3/M4/M5 are described as
fully accepted.

## 当前待处理

- 首批运维上线环境尚未提供：真实邮件/Telegram 接收渠道、第三方独立 Control 监控、跨地域节点和设备以及维护负责人。当前自动化只能运行测试适配器与代码 CI，不能证明这些真实环境门槛。维护负责人补齐渠道与部署范围后，记录投递/监控/网络/设备及回滚演练证据，再由 CI/CD 推进获准的灰度发布；真实地址与密钥仅放部署系统或密码库。
- NetworkCore 的首批诊断库不含宿主运行时事件接线。后续实现真实观察源、宿主认证身份和持久化发送适配后，需在 CI 中补 Agent/Control 的端到端验收，再安排环境演练。

- iOS App Review manual confirmation 仍为 pending；完成前不得启用 TestFlight upload、App Store upload、
  App Review submission 或 iOS release asset。
- iOS TestFlight/App Store Connect upload workflow 仍为 pending；完成前不得执行 archive/export、
  TestFlight upload、App Store upload、App Review submission 或 iOS release asset。当前 release workflow 仅允许
  `ios-upload-readiness` blocked placeholder 读取这些 marker，输出 source tree preflight 和 safe summary。
- Windows Stage 4 signed POP peer identity and structured readiness remains pending. The required
  Linux POP, POP-routed Linux target, Windows endpoint, and protected evidence boundary are defined
  in [Windows Stage 4 POP Peer Manual Acceptance](architecture/windows-stage-4-pop-peer-manual-acceptance.md).
  Do not mark the foreground tunnel production-ready until its positive, negative, and cleanup
  proofs are all recorded.

## Windows Foreground Tunnel Manual Acceptance

The following elevated-Windows record is required before the foreground EasyTier tunnel can be
considered operational. GitHub-hosted CI cannot supply this host, adapter, ACL, TUN, or data-plane
evidence; it verifies source and injected contracts only.

1. Secure ProgramData root evidence: owner and exact SYSTEM/Administrators-only ACL for
   `AnixOps\WindowsTunnel`, `state`, `secrets`, and `easytier`, with no reparse point. Stage the
   approved EasyTier core, CLI, and every loader sidecar (including DLL/Wintun) as existing
   non-reparse direct regular children of `easytier`, with no nested directories. Record the
   exact SYSTEM/Administrators-only, non-inheriting ACL for every direct file and the independently
   verified lower-case core/CLI SHA-256 values. The elevated start path must normalize and recheck
   that complete direct-file inventory before it launches the core; record the resulting ACL
   evidence. NetworkCore never copies or downloads executable content.
2. Delivery-ledger floor values for the verified client and POP identities before and after the
   accepted start reservation.
3. `Find-NetRoute` and `Get-NetAdapter -Physical` evidence that the selected endpoint underlay is
   the same up physical interface, not a virtual or VPN adapter.
4. Before/after `ActiveStore` tuples for every endpoint bypass and planned destination route,
   including destination prefix, next hop, interface index, and route metric. Record only in the
   protected operator evidence, not a CLI report or repository fixture. For a controlled
   endpoint-bypass proof failure, or reconciliation of earlier successful adds after an add
   failure, record bounded per-tuple reconciliation: either a proven absence, or exact removal
   followed by a proven absence. An ambiguous inspection, inspection or removal failure, or a
   still-present tuple must remain a `rollback_failed` manual-recovery outcome. Before every add,
   record a bounded exact absence proof; a pre-existing or ambiguous exact tuple is not
   session-owned, must not be deleted, and may only cause reconciliation of earlier tuples that
   already had that pre-add absence proof. An add error does not establish ownership despite that
   preflight: reconcile only earlier successful adds, then inspect the current exact tuple without
   deleting it. Only a proven absent current tuple retains the normal endpoint error; a present or
   ambiguous tuple remains in place and returns `rollback_failed`. Record that a failed add did
   not trigger an outer restore; later start failures may restore only a bypass whose add
   succeeded for that start.
5. Successful EasyTier peer and route readiness plus `ping` to the overlay address and `ping` and
   `curl` to the POP test subnet.
6. Stop evidence that both exact virtual destination routes and endpoint-bypass routes were removed
   before the owned EasyTier process ended.
7. A controlled missing and ambiguous tuple proof that leaves the owned process, state/config, and
   unrelated routes unchanged while `tunnel stop` fails closed; restore the fixture before normal
   cleanup.
8. State-write denial, disk-full, and native state move failure evidence for each durable cleanup
   transition. A failed `Stopping` write leaves routes, process, and config untouched; a failure
   after mutation retains retryable cleanup intent. After storage is restored, record fresh cleanup
   convergence: it removes only exact still-present tuples and accepts proven-absent resources only
   for persisted `Stopping` or `Failed` cleanup. Confirm that this cleanup can reprove and stop the
   protected running core without requiring the CLI artifact; `Running` requires all ownership
   proofs and the full direct-file artifact set. Leave unrelated resources unchanged and keep this
   evidence in protected operator records, without raw tuple, PID, or config details in CLI or
   repository output.

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

后续涉及 iOS 时，还需要人工处理：

- Apple Developer Program 组织账号和账号角色确认
- App ID、Bundle ID、Network Extension capability、entitlement 与 Provisioning Profile 配置
- 证书、signing asset redaction 和 Provisioning Profile 轮换策略确认
- App Store Connect 或 TestFlight 初次配置、App Privacy 问卷、Privacy Manifest/Required Reason API review、privacy policy URL、TestFlight group 和 export compliance 确认
- GitHub Secrets 写入 Apple 相关凭据
- App Review Notes、demo account、review attachment、隐私政策和目标地区 VPN compliance/VPN 牌照材料确认

后续涉及新的平台 release artifact、artifact 范围扩大或 license/NOTICE 来源变化时，还需要人工处理：

- 对应平台或新增 artifact 文件集合的 license/NOTICE 文本确认；Linux `networkcore-linux` 当前范围已确认，
  但范围变化前不得复用旧确认绕过 release gates
- GitHub Environments、protected tags、branch protection 和 release approval policy 配置
- Windows 代码签名证书、时间戳服务和商店账号确认
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

## Alpha Windows Manual Smoke Test

以下字段记录 alpha 启动期间由用户在外部 Windows 环境执行的手工 smoke 测试状态。该测试不能在本机自动完成，
也不能替代 GitHub Actions 的 `windows-latest` CI 矩阵。

```text
alpha-release-windows-manual-test-status=confirmed
alpha-release-windows-manual-test-source-contract=docs/alpha-windows-smoke-test.md
alpha-release-windows-manual-test-source=manual-user-windows-environment
alpha-release-windows-manual-test-version=v0.1.0-alpha.1
alpha-release-windows-manual-test-commit=67e86a84388023df77e53537f3f209b5a05c1682
alpha-release-windows-manual-test-ci-run=28901464670
alpha-release-windows-manual-test-release-run=28901692913
alpha-release-windows-manual-test-scope=windows-local-smoke-user-run
alpha-release-windows-manual-test-windows=Windows 11 24H2
alpha-release-windows-manual-test-arch=x64
alpha-release-windows-manual-test-ci=github-actions-windows-latest-confirmed-success
alpha-release-windows-manual-test-artifacts=not-produced-placeholder
alpha-release-windows-manual-test-local-build-test=not-run
alpha-release-windows-manual-test-result=passed
alpha-release-windows-manual-test-confirmed-at=2026-07-07T22:10:50Z
alpha-release-windows-manual-test-confirmed-by=operator
alpha-release-windows-manual-test-next-action=rerun-ci-release-workflows-after-marker-update
```

该确认仅覆盖上述 alpha placeholder 候选版本和 GitHub Actions Windows 证据；当前仍不生成 Windows artifact、
installer、service、code signing、store upload 或 release asset。

## iOS Activation Status

以下字段记录 iOS 激活的维护者决定和账号类型，不记录 Team ID、Bundle ID、证书或描述文件标识。

```text
ios-activation-status=swift-source-gate-active
ios-xcode-project-gate=xcodegen-spec-active
ios-xcode-project-committed=no-generated-in-github-actions
ios-testflight-distribution=user-confirmed-2026-10-12
ios-network-extension-target=active-fail-closed-until-runtime
ios-entitlements=minimal-network-extension-only
ios-privacy-manifest=active-no-collected-data
ios-activation-maintainer-decision=unfrozen-2026-10-12
ios-activation-branch=claude/ios-app-development-342512
ios-apple-developer-account-type=individual
ios-apple-developer-account-type-source=user-reported-2026-10-12
ios-organization-account-for-vpn-release=blocked
ios-individual-account-release-review=blocked-pending-account-review
```

人工确认 marker 仍由维护者在独立提交中更新；CI 不得自动设为 confirmed 或 enabled。

## iOS App Review Manual Confirmation

以下字段是后续 iOS upload/release readiness 读取的机器状态。当前仍未完成 App Privacy answers、
privacy policy URL、App Review Notes、demo account、review attachment、VPN compliance、TestFlight group、
App Store Connect app record、export compliance、beta app review 和 App Review submission 人工确认，
因此 iOS upload 和 release asset 发布保持阻断。

```text
ios-app-review-manual-confirmation-status=pending
ios-app-review-manual-confirmation-source-contract=docs/architecture/ios-app-review-manual-confirmation-source-contract.md
ios-app-review-app-privacy-answers=blocked
ios-app-review-privacy-policy-url=blocked
ios-app-review-notes=blocked
ios-app-review-demo-account=blocked
ios-app-review-demo-mode=blocked
ios-app-review-review-attachment=blocked
ios-app-review-vpn-compliance=blocked
ios-app-review-testflight-group=blocked
ios-app-review-app-store-connect-app-record=blocked
ios-app-review-export-compliance=blocked
ios-app-review-beta-app-review=blocked
ios-app-review-app-review-submission=blocked
ios-app-review-testflight-upload=blocked
ios-app-review-release-assets=blocked
ios-app-review-confirmed-at=pending
ios-app-review-confirmed-by=pending
```

人工确认完成前，不得定义 TestFlight upload、App Store upload、App Review submission 或 iOS release asset。
未来从 pending 切换到 confirmed 时，必须遵守
`docs/architecture/ios-app-review-manual-confirmation-source-contract.md` 中的独立人工确认提交、
字段、脱敏和 upload/release 阻断规则。

## iOS TestFlight/App Store Connect Upload Workflow

以下字段是后续 iOS release readiness 读取的机器状态。当前没有真实 Swift/Xcode source、signing、
archive/export、App Store Connect API、protected environment 或 manual approval，因此 upload/release 保持阻断。

```text
ios-upload-workflow-status=pending
ios-upload-workflow-source-contract=docs/architecture/ios-testflight-app-store-connect-upload-workflow-source-contract.md
ios-upload-workflow-archive-export=blocked
ios-upload-workflow-app-store-connect-api=blocked
ios-upload-workflow-protected-environment=blocked
ios-upload-workflow-manual-approval=blocked
ios-upload-workflow-testflight-upload=blocked
ios-upload-workflow-app-store-upload=blocked
ios-upload-workflow-app-review-submission=blocked
ios-upload-workflow-release-assets=blocked
ios-upload-workflow-macos-runner=blocked
ios-upload-workflow-build-processing-check=blocked
ios-upload-workflow-confirmed-at=pending
ios-upload-workflow-confirmed-by=pending
ios-upload-scope=internal-testflight-only
ios-upload-scope-decision=maintainer-2026-10-13
ios-upload-external-testflight=blocked
ios-upload-beta-app-review=blocked-not-required-for-internal
ios-upload-bundle-id-storage=github-variables-only
ios-upload-api-key-status=team-key-added-to-environment
ios-export-compliance-answer=standard-https-only-exempt-2026-10-13
ios-upload-internal-confirmation-status=pending
ios-upload-internal-confirmation-items=app-record,export-compliance,internal-testing-group,app-privacy-determination,privacy-policy-determination,environment-secrets-and-variables
```

当前 workflow activation validation 仍是 blocked placeholder：`ios-upload-readiness` 只读取本节 marker、
检查 source contract、输出 source tree preflight、protected environment/manual approval/App Store Connect API secret status/
archive/export/upload/submission/release asset 的 blocked 状态，不读取 secret、不定义真实 upload job。

iOS Swift/Xcode source tree activation preflight 也保持 blocked：仓库只允许 `apps/ios/README.md` 作为 source tree
governance placeholder，仍没有真实 `apps/ios` Swift source tree、`Package.swift`、Swift source、Xcode project、
Network Extension target、`PrivacyInfo.xcprivacy`、entitlement/provisioning source 或 iOS release asset。
`ios-upload-workflow-status` 不得切换为 `enabled`，直到 source tree、manual confirmation、protected environment
和 secret setup 都按合同完成并通过 GitHub Actions。`Package.swift` source ownership preflight contract 和
`docs/architecture/ios-package-swift-manifest-only-activation-validation-contract.md` 已补充，当前 Package.swift ownership gate
与 manifest-only activation validation gate 仍是 blocked-placeholder；仍不得新增真实 `Package.swift` 或 Swift source。

人工确认和 workflow activation enabled marker 完成前，不得定义 archive/export、TestFlight upload、App Store upload、
App Review submission 或 iOS release asset。未来从 pending 切换到 enabled 时，必须遵守
`docs/architecture/ios-testflight-app-store-connect-upload-workflow-source-contract.md` 和
`docs/architecture/ios-upload-workflow-activation-validation-contract.md`、
`docs/architecture/ios-swift-xcode-source-tree-activation-preflight-contract.md` 中的独立启用提交、protected environment、
manual approval、secret redaction、source tree gate 和 upload/release 阻断规则。
