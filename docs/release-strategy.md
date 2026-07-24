# Release Strategy

本文件定义真实平台产物进入 `.github/workflows/release.yml` 前必须满足的发布策略。它是发布 workflow 的设计约束；当前 Linux CLI
已有受 CI、checksum、manifest、attestation、release notes、rollback 和 publish eligibility gates 约束的 Linux artifact 产物路径，其他平台仍保持 blocked 或未定义状态。

评估时间：2026-07-23。

## 当前发布状态

`v0.2.0-alpha.21` 是当前已发布 Windows managed-client prerelease；`v0.2.0-alpha.22` 是当前待发布的 Windows source candidate。Linux `v0.1.2-alpha.3` 仍是当前 Linux source slice。Windows MSI 与 portable ZIP 只在同名 tag 的 GitHub Actions 中生成。

服务先完成 SCM `Running` handoff，再应用 managed runtime configuration；GUI/CLI `start` 立即返回观察到的 SCM state，因此坏配置只记录到 service log 并使服务停止，不能阻塞 MSI 或 Start。GUI 的 `Profile / URL` 允许手动导入本地 profile 或 HTTP(S) 地址，`Load nodes` 展示 NodeCatalog 节点。NodeCatalog 导入会生成包含全部可翻译节点的 sing-box `selector`，导入时选择默认 outbound；运行中的服务可由 `Switch active` 通过 `127.0.0.1:9091` 回环 Clash API 显式切换并读回确认。原生 sing-box JSON 保持 pass-through。当前 main 额外提供 tray、current-user startup 和 preflight-gated one-shot recovery；它仍不启用 LAN controller、Clash Web UI、`urltest`、自动延迟选择、后台更新或无限自动服务重启。GUI 仍提供不变更系统状态的 `sing-box check -c` 预检和本地 diagnostics。GUI HTTPS MITM、Hysteria2/TUIC、V2Ray compatibility subset 与 native `mixed-in` snapshot/restore 的既有边界保持不变。没有本机打包或本机发布路径，用户可下载状态以 tag workflow 成功结果为准。

当前 release workflow 已从 placeholder 过渡为 Linux CLI artifact 发布路径：`release-policy`、
`release-ci-gate`、release contract jobs、`linux-artifact-readiness`、`package-linux`、`attest-linux`、
`post-release-summary`、`publish-eligibility-gate`、`publish-github-release`、`ios-upload-readiness`、`windows-cli-artifact-readiness` 和
`release-summary`。所有构建、打包、checksum、manifest、attestation 和 GitHub Release asset 上传仍只能在
GitHub Actions 中执行。

Linux artifact release state consistency:

```text
linux-artifact-release-state=confirmed-release-path
linux-artifact-license-notice-status=confirmed
linux-artifact-publish-scope=tag-release-after-all-gates
```

当前最新已发布 Linux artifact 是 `v0.1.0` 正式版 stable CLI 四件套；当前最新 Windows prerelease tag release 是
`v0.2.0-alpha.21`；当前 Windows source candidate 是 `v0.2.0-alpha.22`，只有同名 tag workflow 全部成功后才成为可下载 release。该发布路径始终同时产出 Linux CLI 四件套、Windows managed-client MSI 四件套和 Windows portable ZIP 四件套。MSI 在安装期请求异步 service start，不等待 runtime ready；服务在配置 runtime 前完成 SCM handoff，CLI 继续只返回即时状态。GUI 日常 `Connect` 在后台验证 SCM、service-owned core PID、回环监听和生成 selector 后才应用当前 interactive-user proxy；GUI 仍保留明确的 official sing-box core install、`check -c` 预检、本地 diagnostics、HTTP(S) profile import/update、NodeCatalog selector、`Check core`、手动 delay test 和明确 runtime switch；native JSON 保持 service-owned pass-through。MSI/portable ZIP 不捆绑或静默下载第三方 core，且不启用后台 refresh、自动 service restart、LAN controller/Web UI、`urltest`、XHTTP/ECH/multiplex 推断、HTTP/2/HTTP/3/QUIC MITM、streaming、多 request CONNECT 或 JavaScript dispatch。历史 `v0.1.1-alpha.2` Windows manual-extract CLI zip 仅保留为审计记录。Linux CLI
`mitm http-rewrite preview --confirm --url https://... --phase request` 的合同测试固定 caller-provided
HTTPS request preview 只能输出 preview/reject 边界，继续保持 `tls_decryption_ready=false`、
`https_response_rewrite_ready=false` 和 `script_dispatch_ready=false`；Windows path 已新增 `apps/windows-cli`、
`platform-windows`、`package-windows`、`attest-windows`、Windows release notes/rollback gate 和 Windows publish
eligibility gate，后续 P4 源码增量只有在新 tag release 完整通过 GitHub Actions 的 CI、package、
attestation、publish eligibility 和 publish jobs 后，才会进入用户可下载的 GitHub Release asset。
逐版本 alpha/rc 功能、边界和规划切片记录在 [Alpha Release Feature Matrix](alpha-release-feature-matrix.md)。

已拍板版本节奏：

- `v0.1.0`：Linux-only explicit HTTPS rewrite preview。alpha.15 已完成 TLS MITM
  readiness，alpha.16 已完成 controlled TLS termination plan/report release，alpha.17 已完成 HTTPS request rewrite preview release，alpha.18 已完成 HTTPS response rewrite preview release，alpha.19 已完成 traffic-proof token/proxy/CONNECT authority binding hardening release，alpha.20 已完成 release hardening，rc.1 已完成回归冻结候选，正式版已发布 Linux-only artifact；不发布 Windows artifact，不启用 JavaScript script dispatch，不执行
  system trust store mutation、system proxy mutation、daemon/service、TUN、DNS 或 firewall mutation。
- `v0.1.1`：正式引入 Windows 版本，并把订阅兼容作为主线。Windows 首期发布目标是 CLI artifact
  和 release path；Windows service、driver、installer、代码签名和系统代理 mutation 必须各自具备
  source contract、manual marker 或 release gate 后才能进入对应切片。
- `v0.1.2`：managed lifecycle 版本。新增 persistent subscription catalog、managed foreground
  status/events/logs/reload/rollback，并在 alpha 切片中相继推出 JavaScript script dispatch、
  system trust store mutation、system proxy mutation 和 managed MITM session orchestration；所有高风险
  mutation 必须显式授权、可检测、可回滚。

`docs/manual-intervention.md` 中的 Linux artifact license/NOTICE marker 已为
`linux-artifact-license-notice-status=confirmed`。该状态只解除 license/NOTICE 人工门禁；
`package-linux` 和 GitHub Release asset 仍必须继续通过同 commit CI、checksum、manifest、
GitHub artifact attestation、release notes、rollback 和 publish eligibility gates。若未来 marker
缺失、非法或回退到 pending，`linux-artifact-readiness` 必须失败，且不得继续构建、上传或发布。

- 允许 tag `v*` 和 `workflow_dispatch` 触发。
- release policy job 检查版本格式和触发来源一致性；手动 `workflow_dispatch` 验证必须从 `main` 分支发起，tag release 必须使用同名 tag 版本，版本可为稳定版、`alpha.N` 或 `rc.N` 预发布版。
- `release-ci-gate` job 已在 job 级启用 `actions: read`，自动读取 `main` 上同 commit 的成功 CI 结果，校验 `CI summary` job，并输出 [Release CI success source contract](architecture/release-ci-success-source-contract.md) 中定义的 CI run/source 字段，以及 [Linux package release CI gate activation validation contract](architecture/linux-package-release-ci-gate-activation-validation-contract.md)、[Release CI gate execution validation contract](architecture/release-ci-gate-execution-validation-contract.md) 和 [Release CI gate API implementation plan](architecture/release-ci-gate-api-implementation-plan.md) 中定义的 active API read 状态。
- `release-artifact-contract` job 记录首个真实 artifact job 必须输出 `artifact_name`、`artifact_path`、`checksum_algorithm`、`checksum_file` 和 `checksum_value`，且 checksum 算法默认为 `sha256`。
- `release-signing-contract` job 记录真实平台 artifact 发布前必须声明签名或 attestation 策略，并要求后续 job 输出 `signing_policy`、`signing_status`、`attestation_policy`、`attestation_status`、`provenance_policy` 和 `provenance_file`。
- `release-rollback-contract` job 记录真实 artifact 发布说明必须输出 `rollback_scope`、`rollback_trigger`、`rollback_steps`、`replacement_version` 和 `rollback_owner`。
- `linux-artifact-readiness` job 检查 Linux CLI 源码、platform adapter、native listener/node 配置设计、foreground stop/release 源码与合同测试、artifact manifest 合同设计、license/NOTICE confirmation source contract、Linux package license/NOTICE transition validation contract、release CI success source contract、Linux package release CI gate activation validation contract、release CI gate execution validation contract、release CI gate API implementation plan、Linux package artifact job preflight validation contract、Linux package artifact build command validation contract、Linux package artifact staging file validation contract、Linux package artifact archive creation validation contract、Linux package artifact checksum execution validation contract、Linux package artifact manifest generation validation contract、Linux package artifact manifest checksum validation contract、Linux package workflow artifact bundle upload validation contract、Linux package artifact attestation execution validation contract、Linux package release notes/rollback execution validation contract、Linux package publish eligibility execution validation contract、Linux package runner/toolchain/target contract、Linux package archive staging contract、Linux package checksum/manifest checksum contract、Linux package publish/upload boundary contract、Linux package signing/attestation policy binding contract、Linux package release notes/rollback policy binding contract、Linux package publish eligibility aggregate contract、安装/回滚设计和 license/NOTICE marker；marker 为 pending 时失败，marker confirmed 后才允许进入 `package-linux`。
- `package-linux` 在 `ubuntu-latest` 使用受版本控制的 `Cargo.lock` 执行 `cargo build --locked --release --package networkcore-linux --bin networkcore-linux --target x86_64-unknown-linux-gnu`，组装 `networkcore-linux-${version}-${target}.tar.gz`、`.sha256`、manifest JSON 和 manifest `.sha256`，并以同 run workflow artifact bundle 上传。
- `attest-linux` 下载同 run bundle，重新校验 checksum，并用 GitHub artifact attestation 覆盖 archive、archive checksum、manifest 和 manifest checksum。
- `post-release-summary` 与 `publish-eligibility-gate` 校验 release notes、rollback、withdrawal/replacement policy 和 `package_publish_eligibility_status=eligible`。
- `publish-github-release` 只在 tag push release 中运行，使用 GitHub CLI 创建同名 GitHub Release，并上传符合 eligibility 的 Linux archive、archive checksum、manifest、manifest checksum，以及当前 Windows managed client MSI 与 portable ZIP 的 archive、checksum、manifest、manifest checksum；workflow_dispatch 只做验证，不发布 GitHub Release asset。历史 `v0.1.1-alpha.2` Windows zip 仅保留为审计记录。
- `ios-upload-readiness` job 检查 [iOS upload workflow activation validation contract](architecture/ios-upload-workflow-activation-validation-contract.md)、[iOS Swift/Xcode source tree activation preflight contract](architecture/ios-swift-xcode-source-tree-activation-preflight-contract.md)、[iOS Package.swift source ownership activation preflight contract](architecture/ios-package-swift-source-ownership-activation-preflight-contract.md)、[iOS Package.swift manifest-only activation validation contract](architecture/ios-package-swift-manifest-only-activation-validation-contract.md)、iOS upload source contract、`apps/ios/README.md` governance placeholder、`docs/manual-intervention.md` 中的 `ios-upload-workflow` pending/blocked marker、source tree preflight `readme-placeholder`/no Swift source 状态、Package.swift ownership blocked 状态、Package.swift manifest-only activation blocked 状态、protected environment/manual approval blocked 状态、App Store Connect API secret status not-read-blocked、archive/export/upload/submission blocked 输出，并继续不读取 secret、不定义真实 iOS upload job、不生成 iOS release asset。
- `windows-cli-artifact-readiness` job 检查 [Windows CLI artifact source release contract](architecture/windows-cli-artifact-source-release-contract.md)、`v0.1.1-alpha.2` 合同范围、`apps/windows-cli` source identity、`windows-latest` runner、`x86_64-pc-windows-gnu` target、zip/checksum/manifest/attestation/release notes/rollback/signing policy 和 blocked mutation marker；该 job 不读取 signing secret，不放开 service、driver、installer、system proxy mutation、system trust store mutation、JavaScript script dispatch 或 managed lifecycle。
- alpha.1 placeholder 阶段的 `release-placeholder` 语境已由当前 Linux CLI release path 取代；当前 source of truth 是
  `linux-artifact-release-state=confirmed-release-path`、`package-linux`、`attest-linux`、
  `post-release-summary`、`publish-eligibility-gate`、tag-only `publish-github-release` 和 release summary。
- `package-linux` 当前必须生成 archive、archive checksum、manifest 和 manifest checksum；`attest-linux`
  必须对四个 subject 生成 GitHub artifact attestation；`publish-eligibility-gate` 必须输出
  `package_publish_eligibility_status=eligible` 后，tag release 才能上传 GitHub Release assets。
- iOS 仍保持 `ios-upload-readiness` blocked placeholder：不读取 secret，不定义真实 upload job，不生成
  Swift/Xcode source、archive/export、TestFlight/App Store upload、App Review submission 或 iOS release asset。
- 历史 Windows CLI package/publish path 在 `v0.1.1-alpha.2` 激活：`package-windows` 生成 `networkcore-windows` manual-extract zip，`attest-windows` 对 Windows 四件套生成 GitHub artifact attestation；该记录不代表当前 main 的能力边界。
- Windows managed client MSI 已在 `v0.2.0-alpha.1` 发布：`package-windows` 在 `windows-latest` 以 Rust GNU target 构建 `networkcore-windows`, `networkcore-windows-gui` 和 `networkcore-windows-service`，用 WiX 4.0.6 生成 per-machine MSI 和 portable ZIP，`attest-windows` 对两者的 archive、sha256、schema-version-2 manifest 和 manifest sha256 生成 GitHub artifact attestation。安装器注册 automatic SCM service，完整卸载前运行 service `purge`，GUI/service/platform 共同激活 signed INF driver package lifecycle、WinINet/WinHTTP system proxy、LocalMachine ROOT CA 和 managed lifecycle 的 apply/rollback；JavaScript dispatch 仍 blocked。当前合同见 [Windows Managed Client Source Release Contract](architecture/windows-managed-client-source-release-contract.md)。
- `v0.2.0-alpha.2` 在同一 MSI/attestation/publish path 上增加 operator-staged
  sing-box managed process lifecycle、Windows official ZIP extraction、GUI PID/exit
  diagnostics 和原生 sing-box JSON 示例；automatic core install、Windows live
  HTTPS MITM data plane 和 JavaScript dispatch 仍 blocked。
- `v0.2.0-alpha.3` 保持同一 MSI/attestation/publish path，但将 install-time
  service start 改为 asynchronous，并在每个 Windows tag release 增加 portable
  ZIP、checksum、manifest、attestation 与 bounded MSI install/uninstall smoke。
- `v0.2.0-alpha.4` 保持同一 MSI/portable/attestation/publish path，并增加 GUI
  显式官方 sing-box core install 与 local profile import。它只生成基础
  Shadowsocks/Trojan/VLESS/VMess 配置；remote subscription、advanced transport
  rendering、Windows live HTTPS MITM 和 JavaScript dispatch 仍 blocked。
- `v0.2.0-alpha.5` 保持同一 MSI/portable/attestation/publish path，并增加 GUI
  触发的 service-owned CA lifecycle 和 controlled HTTP/1.1 HTTPS MITM data plane。
  native listener 使用 sing-box 本地 SOCKS upstream；HTTP/2、HTTP/3/QUIC、streaming、
  multi-request CONNECT、remote scripts 和 JavaScript dispatch 仍 blocked。
- `v0.2.0-alpha.6` 保持同一 MSI/portable/attestation/publish path，并增加原生
  sing-box JSON 直通导入、local mixed/http inbound 的系统代理端口识别，以及 GUI 直接打开
  `sing-box.log` 的诊断入口。
- `v0.2.0-alpha.7` 保持同一发布路径，并将带 `type: mixed`、`tag: mixed-in` 的
  原生 sing-box JSON 接入 GUI MITM snapshot/restore 生命周期；其他 native 字段和入站不改写。
- `v0.2.0-alpha.8` 保持同一发布路径，并增加 Hysteria2/TUIC local-file share-link 与
  sing-box JSON outbound catalog import，以及到 direct sing-box QUIC outbound 的受控渲染；
  它们不进入 GUI HTTP/1.1 HTTPS MITM 生命周期。
- `v0.2.0-alpha.9` 保持同一发布路径，并增加 Trojan/VLESS/VMess local-file
  share-link 与 sing-box outbound catalog import 的 TLS/REALITY/uTLS/Vision/VMess
  security/alter-id/WebSocket/gRPC/HTTP/HTTPUpgrade/V2Ray QUIC compatibility subset；
  不推断 XHTTP、ECH、multiplex 或任意 native transport 字段，也不进入 HTTP/3 MITM。
- `v0.2.0-alpha.10` 保持同一发布路径，固定服务先完成 SCM handoff、GUI/CLI `start` 只返回即时 SCM state，坏配置不得阻塞启动调用；CI 用真实 MSI 的无效配置路径验证 service 日志和 `Stopped` 结果。每个 Windows tag 仍必须同时上传 MSI 与 portable ZIP 的 archive、sha256、manifest 和 manifest sha256。
- `v0.2.0-alpha.11` 保持同一发布路径，并让 GUI 复用 service 的 managed JSON/schema 和 `sing-box check -c` 预检；`Diagnostics` 输出仅本地的 SCM/runtime 状态及有界日志尾部，失败 action 自动生成同一报告。GUI debug activity 不代替 core debug，后者仍由 operator-owned sing-box JSON 显式设置。
- `v0.2.0-alpha.12` 保持同一发布路径，并允许 GUI 的 `Profile / URL` 手动下载 HTTP(S) 订阅 payload 后复用本地 profile 的 native JSON/NodeCatalog 导入路径；不启动后台刷新、订阅目录/组、route/rule 拉取或自动重启服务。
- `v0.2.0-alpha.13` 保持同一发布路径，并新增 `Update URL`：仅显式更新最后一次成功导入的单个 HTTP(S) URL，失败不覆盖当前 managed config；不启动后台刷新、订阅目录/组、route/rule 拉取或自动重启服务。
- `v0.2.0-alpha.14` 保持同一发布路径，并新增 `Load nodes`：显式解析 local profile 或 HTTP(S) URL，展示并选择 NodeCatalog 节点，再生成确定性单节点 service config；原生 sing-box JSON 继续 pass-through，不提供运行期 selector/latency controller。
- `v0.2.0-alpha.15` 保持同一发布路径，并让 NodeCatalog 导入生成包含所有可翻译节点的 sing-box `selector`。GUI 的 `Switch active` 仅经 `127.0.0.1:9091` 回环 Clash API 显式切换并读回确认；不启用 LAN controller、Web UI、`urltest`、自动延迟选择、后台刷新或自动服务重启。原生 sing-box JSON 继续 pass-through。
- `v0.2.0-alpha.16` 保持同一发布路径，并新增 GUI `Test delay`：它只通过
  `127.0.0.1:9091` 回环 Clash API 对当前选择的 generated outbound 进行一次 HTTPS
  delay test，用户可编辑 target，结果回显为毫秒；不切换 selector、不创建 `urltest`、不
  启动后台测速、后台刷新或自动服务重启。原生 sing-box JSON 继续 pass-through。
- `v0.2.0-alpha.17` 保持同一发布路径，并新增 GUI `Check core`：它只通过
  `127.0.0.1:9091` 回环 Clash API 读取 generated selector 的 active outbound 和 node
  count，把 SCM service 状态和核心控制器可达性分开显示；不保存节点、不切换 selector、
  不改写 managed config，也不启动、停止或重启服务。原生 sing-box JSON 继续 pass-through。
- `v0.2.0-alpha.18` 保持同一发布路径，并移除 GUI `Start`/`Restart` 对 managed
  system proxy 的启动前写入。service runtime state 是 managed proxy snapshot 的唯一
  owner，core 异步启动失败时 rollback 会恢复真实启动前设置；GUI `Enable proxy`/
  `Restore proxy` 继续是独立的显式手动操作。
- `v0.2.0-alpha.19` 保持同一发布路径，并在 SCM `Running` 后监督 service-owned
  sing-box process。异常退出会持久化 failed transition/exit detail、清理 runtime
  resources、恢复 managed proxy snapshot 并停止 SCM service；diagnostics 记录 failure detail。
- `v0.2.0-alpha.21` 已发布 Windows managed-client prerelease。它保留相同 MSI/portable
  ZIP/attestation/publish path，并把原生 Win32 GUI 重组为 Home、Nodes,
  Subscriptions、Settings、Diagnostics 和 Advanced。连接状态要求独立的 SCM、core PID
  和当前 interactive-user proxy 证据；service/core/install/preflight/subscription/selector/
  delay 操作在后台完成。它还增加 shared-state tray、current-user Run startup、opt-in
  auto-connect、最多一次 core recovery、exact GUI-owned proxy recovery 和 MSI Run-entry
  cleanup。详情见 [Windows GUI Daily Usability](architecture/windows-gui-daily-usability.md)。
- `v0.2.0-alpha.22` 是当前 Windows source candidate。它明确 desktop/service proxy
  ownership，在 GUI 应用当前用户代理前验证 SCM、live core PID、loopback listener 和适用的
  generated selector API；失败时回滚 GUI-owned proxy。它不将缺失 PID 显示为 `PID 0`，并在
  UAC handoff 前解释权限用途、保留 login-startup 参数。该候选仍需要真实 Windows 桌面验收。
- license/NOTICE marker 当前为 confirmed；若 marker 缺失、非法或回退到 pending，不得生成 release artifact。confirmed 且同 commit CI、checksum、manifest、attestation、release notes、rollback 与 publish eligibility 全部通过后，tag release 可以生成并上传 Linux CLI artifact；符合 Windows eligibility 时也可以上传当前 Windows managed client MSI 四件套和 portable ZIP 四件套。
- 不在本机打包、签名、测试或发布。
- 通过 release summary job 输出发布来源、policy、release-ci-gate、release CI success source contract、release CI gate activation validation contract、release CI gate execution validation contract、release CI gate API implementation plan、iOS Swift/Xcode source tree activation preflight contract、iOS Package.swift source ownership activation preflight contract、iOS Package.swift manifest-only activation validation contract、iOS upload workflow activation validation contract、iOS source tree README placeholder/Package.swift ownership/manifest-only activation/marker/protected environment/manual approval/App Store Connect API secret/archive/export/upload/submission/release asset blocked 状态、Linux package artifact job preflight validation contract、Linux package artifact build command validation contract、Linux package artifact staging file validation contract、Linux package artifact archive creation validation contract、Linux package artifact checksum execution validation contract、Linux package artifact manifest generation validation contract、Linux package artifact manifest checksum validation contract、Linux package workflow artifact bundle upload validation contract、Linux package artifact attestation execution validation contract、Linux package release notes/rollback execution validation contract、Linux package publish eligibility execution validation contract、release-artifact-contract、release-signing-contract、release-rollback-contract、linux-artifact-readiness、Linux foreground stop/release contract、Linux artifact manifest contract、Linux artifact manifest output fields、Linux package runner/toolchain/target contract、Linux package archive staging contract、Linux package checksum/manifest checksum contract、Linux package publish/upload boundary contract、Linux package signing/attestation policy binding contract、Linux package release notes/rollback policy binding contract、Linux package publish eligibility aggregate contract、Linux package license/NOTICE transition validation contract、Linux artifact license/NOTICE source contract 与 status、placeholder、artifact 状态和后续 artifact 门禁。
- 任何真实产物必须先有对应源码、平台设计、GitHub Actions 验证和本文件定义的门禁。

## 发布原则

- CI/CD Only：所有 build、test、lint、security scan、package、sign、notarize、upload 都必须在 GitHub Actions 或官方平台完成。
- Source Of Truth：release 只能基于 Git tag、受控分支或手动指定版本，不接受本地构建产物。
- One Artifact, One Job：每类平台产物使用独立 job，避免一个失败路径污染其他平台。
- Reproducible Inputs：release job 必须记录 commit SHA、tag、workspace manifest、toolchain 和 artifact 名称。
- No Secret In Repo：签名证书、Provisioning Profile、App Store Connect、Windows signing、GitHub token 只能走 GitHub Secrets、Environments 或官方平台。
- Rollback First：每个产物都要有可描述的撤回、替换或禁用路径。

## 发布门禁

真实 artifact job 合入前必须满足：

1. `main` 上对应 commit 的 CI 全部通过，至少覆盖 policy、workspace smoke、语言 build/test/lint/security scan；真实 artifact packaging 前必须按 [Release CI success source contract](architecture/release-ci-success-source-contract.md)、[Linux package release CI gate activation validation contract](architecture/linux-package-release-ci-gate-activation-validation-contract.md)、[Release CI gate execution validation contract](architecture/release-ci-gate-execution-validation-contract.md) 和 [Release CI gate API implementation plan](architecture/release-ci-gate-api-implementation-plan.md) 自动读取同 repository、同 commit、`main` 分支、`completed`/`success` 的 CI run 字段。
2. artifact 对应源码、平台设计和安装/卸载/回滚设计已存在，不能发布 placeholder、空壳或本地生成产物。
3. release workflow 中的每个 artifact job 都显式声明 runner、toolchain、target triple、输入版本、输出文件名、上传路径、staging 目录、顶层目录、文件来源、checksum 文件、manifest 文件和 manifest checksum 文件；首个 Linux `package-linux` 必须先满足 [Linux package artifact job preflight validation contract](architecture/linux-package-artifact-job-preflight-validation-contract.md)、[Linux package artifact build command validation contract](architecture/linux-package-artifact-build-command-validation-contract.md)、[Linux package artifact staging file validation contract](architecture/linux-package-artifact-staging-file-validation-contract.md)、[Linux package artifact archive creation validation contract](architecture/linux-package-artifact-archive-creation-validation-contract.md)、[Linux package artifact checksum execution validation contract](architecture/linux-package-artifact-checksum-execution-validation-contract.md)、[Linux package runner/toolchain/target contract](architecture/linux-package-runner-toolchain-target-contract.md)、[Linux package archive staging contract](architecture/linux-package-archive-staging-contract.md)、[Linux package checksum manifest contract](architecture/linux-package-checksum-manifest-contract.md)、[Linux package publish upload boundary contract](architecture/linux-package-publish-upload-boundary-contract.md)、[Linux package workflow artifact bundle upload validation contract](architecture/linux-package-workflow-artifact-bundle-upload-validation-contract.md)、[Linux package artifact attestation execution validation contract](architecture/linux-package-artifact-attestation-execution-validation-contract.md)、[Linux package release notes/rollback execution validation contract](architecture/linux-package-release-notes-rollback-execution-validation-contract.md)、[Linux package publish eligibility execution validation contract](architecture/linux-package-publish-eligibility-execution-validation-contract.md)、[Linux package signing/attestation policy binding contract](architecture/linux-package-signing-attestation-policy-binding-contract.md)、[Linux package release notes/rollback policy binding contract](architecture/linux-package-release-notes-rollback-policy-binding-contract.md)、[Linux package publish eligibility aggregate contract](architecture/linux-package-publish-eligibility-aggregate-contract.md) 与 [Linux package license/NOTICE transition validation contract](architecture/linux-package-license-notice-transition-validation-contract.md)。
   同一 `package-linux` 加入前还必须满足 [Linux package artifact manifest generation validation contract](architecture/linux-package-artifact-manifest-generation-validation-contract.md) 和 [Linux package artifact manifest checksum validation contract](architecture/linux-package-artifact-manifest-checksum-validation-contract.md)，并在 artifact attestation execution validation contract 激活前保持 release asset upload blocked。
4. 产物必须由 GitHub-hosted runner 或后续受控 runner 生成，并按 publish/upload boundary 先上传同一 release run 的 workflow artifact bundle，再由 publish job 校验后上传 GitHub Release asset。
5. 每个上传产物必须生成 checksum；首个真实 artifact job 至少输出 `artifact_name`、`artifact_path`、`checksum_algorithm`、`checksum_file` 和 `checksum_value`；后续有 signing 或 attestation 能力时必须纳入同一 release run。
6. 真实平台 artifact 发布前必须声明签名或 attestation 策略，并至少输出 `signing_policy`、`signing_status`、`attestation_policy`、`attestation_status`、`provenance_policy` 和 `provenance_file`；首个 Linux artifact 必须按 [Linux package signing/attestation policy binding contract](architecture/linux-package-signing-attestation-policy-binding-contract.md) 和 [Linux package artifact attestation execution validation contract](architecture/linux-package-artifact-attestation-execution-validation-contract.md) 保持 unsigned tarball policy，同时要求 GitHub artifact attestation/provenance 可验证后才允许 publish。
7. 涉及 Apple、Windows 或商店发布的产物必须先完成人工账号、证书、密钥和 Secrets 配置，并记录到 `docs/manual-intervention.md`。
8. 发布说明必须链接对应 CHANGELOG、CI run、release run 和回滚方案。
9. 发布说明必须按 [Linux package release notes/rollback policy binding contract](architecture/linux-package-release-notes-rollback-policy-binding-contract.md) 和 [Linux package release notes/rollback execution validation contract](architecture/linux-package-release-notes-rollback-execution-validation-contract.md) 输出 `rollback_scope`、`rollback_trigger`、`rollback_steps`、`replacement_version`、`rollback_owner`、withdrawal policy 和 replacement policy；publish 前还必须按 [Linux package publish eligibility execution validation contract](architecture/linux-package-publish-eligibility-execution-validation-contract.md) 校验 `package_publish_eligibility_status=eligible`、全部 required gates 和 required fields；公开 asset 不得覆盖同名 tag，只能以新版本替换或发布撤回说明。

## 初始产物矩阵

| 平台/产物 | 初始形态 | Release runner | 发布前置条件 |
| --- | --- | --- | --- |
| Rust crates | 暂不发布到 crates.io | `ubuntu-latest` | 公共 API 稳定、license 与 README 完整、crate publishing policy 单独评审 |
| Linux | `networkcore-linux` CLI tarball | `ubuntu-latest` | [Linux artifact pre-release design](architecture/linux-artifact-pre-release-design.md)、[Linux platform adapter design](architecture/linux-platform-adapter.md)、[Linux CLI entrypoint design](architecture/linux-cli-entrypoint.md)、[Linux CLI runtime wiring design](architecture/linux-cli-runtime-wiring.md)、[Native engine listener and node config design](architecture/native-engine-listener-node-config.md)、[Linux native proxy engine start design](architecture/linux-native-proxy-engine-start.md)、[Linux CLI artifact installation and rollback design](architecture/linux-cli-artifact-installation-rollback.md)、[Linux package artifact manifest design](architecture/linux-package-artifact-manifest.md)、[Linux artifact license notice confirmation design](architecture/linux-artifact-license-notice-confirmation.md)、[Linux package license/NOTICE transition validation contract](architecture/linux-package-license-notice-transition-validation-contract.md)、[Release CI success source contract](architecture/release-ci-success-source-contract.md)、[Linux package release CI gate activation validation contract](architecture/linux-package-release-ci-gate-activation-validation-contract.md)、[Release CI gate execution validation contract](architecture/release-ci-gate-execution-validation-contract.md)、[Release CI gate API implementation plan](architecture/release-ci-gate-api-implementation-plan.md)、[Linux package artifact job preflight validation contract](architecture/linux-package-artifact-job-preflight-validation-contract.md)、[Linux package artifact build command validation contract](architecture/linux-package-artifact-build-command-validation-contract.md)、[Linux package artifact staging file validation contract](architecture/linux-package-artifact-staging-file-validation-contract.md)、[Linux package artifact archive creation validation contract](architecture/linux-package-artifact-archive-creation-validation-contract.md)、[Linux package artifact checksum execution validation contract](architecture/linux-package-artifact-checksum-execution-validation-contract.md)、[Linux package artifact manifest generation validation contract](architecture/linux-package-artifact-manifest-generation-validation-contract.md)、[Linux package artifact manifest checksum validation contract](architecture/linux-package-artifact-manifest-checksum-validation-contract.md)、[Linux package workflow artifact bundle upload validation contract](architecture/linux-package-workflow-artifact-bundle-upload-validation-contract.md)、[Linux package artifact attestation execution validation contract](architecture/linux-package-artifact-attestation-execution-validation-contract.md)、[Linux package release notes/rollback execution validation contract](architecture/linux-package-release-notes-rollback-execution-validation-contract.md)、[Linux package publish eligibility execution validation contract](architecture/linux-package-publish-eligibility-execution-validation-contract.md)、[Linux package runner/toolchain/target contract](architecture/linux-package-runner-toolchain-target-contract.md)、[Linux package archive staging contract](architecture/linux-package-archive-staging-contract.md)、[Linux package checksum manifest contract](architecture/linux-package-checksum-manifest-contract.md)、[Linux package publish upload boundary contract](architecture/linux-package-publish-upload-boundary-contract.md)、[Linux package signing/attestation policy binding contract](architecture/linux-package-signing-attestation-policy-binding-contract.md)、[Linux package release notes/rollback policy binding contract](architecture/linux-package-release-notes-rollback-policy-binding-contract.md) 与 [Linux package publish eligibility aggregate contract](architecture/linux-package-publish-eligibility-aggregate-contract.md) 完成；license/NOTICE marker 当前为 confirmed，tag publish 仍需要同 commit CI、checksum、manifest、attestation、release notes、rollback 和 publish eligibility 全部通过 |
| Windows | `networkcore-windows` managed-client MSI and portable ZIP | `windows-latest` | Current main is the `v0.2.0-alpha.22` candidate. It adds real listener/selector readiness before desktop proxy mutation, explicit proxy ownership, and truthful missing-PID handling to the shared-state tray, current-user Run startup, opt-in one-shot auto-connect/core recovery, exact GUI-owned proxy recovery, and MSI Run-entry cleanup baseline. It retains the generated NodeCatalog selector, loopback controller health/switch/delay, service-owned core supervision, native JSON pass-through, portable ZIP, and MSI path. No LAN controller, Web UI, `urltest`, automatic latency selection, subscription scheduler/group, TUN/DNS interception, or script dispatch is enabled. |
| macOS | 待定义 CLI、app bundle、`.pkg` 或 `.dmg` | `macos-26` | 签名、notarization、entitlement 和 Gatekeeper 路径完成 |
| iOS | App Store Connect 或 TestFlight 路径 | `macos-26` | [iOS Network Extension design](architecture/ios-network-extension-design.md)、[iOS platform adapter source contract](architecture/ios-platform-adapter-source-contract.md)、[iOS Swift Network Extension bridge design](architecture/ios-swift-network-extension-bridge-design.md)、[iOS Swift Xcode bridge source contract](architecture/ios-swift-xcode-bridge-source-contract.md)、[iOS embedded runtime FFI boundary design](architecture/ios-embedded-runtime-ffi-boundary-design.md)、[iOS MITM certificate lifecycle design](architecture/ios-mitm-certificate-lifecycle-design.md)、[iOS entitlement/provisioning source contract](architecture/ios-entitlement-provisioning-source-contract.md)、[iOS App Review/privacy release readiness design](architecture/ios-app-review-privacy-release-readiness-design.md)、[iOS Privacy Manifest source contract](architecture/ios-privacy-manifest-source-contract.md)、[iOS App Review manual confirmation source contract](architecture/ios-app-review-manual-confirmation-source-contract.md)、[iOS TestFlight App Store Connect upload workflow source contract](architecture/ios-testflight-app-store-connect-upload-workflow-source-contract.md)、[iOS upload workflow activation validation contract](architecture/ios-upload-workflow-activation-validation-contract.md)、[iOS Swift/Xcode source tree activation preflight contract](architecture/ios-swift-xcode-source-tree-activation-preflight-contract.md)、[iOS Package.swift source ownership activation preflight contract](architecture/ios-package-swift-source-ownership-activation-preflight-contract.md)、[iOS Package.swift manifest-only activation validation contract](architecture/ios-package-swift-manifest-only-activation-validation-contract.md)、`crates/platform-ios` 首个源码骨架、真实 Swift/Xcode bridge 源码、真实 Rust embedded runtime FFI 源码、真实 certificate lifecycle 源码、真实 entitlement/provisioning 源码、真实 Privacy Manifest 源码、Provisioning Profile、App Privacy disclosure、隐私政策、App Review Notes、TestFlight/App Store Connect 人工确认 marker、upload workflow enabled marker、archive/export、protected environment、manual approval、App Store Connect API、build processing status 和 VPN compliance 完成 |
| Source archive | GitHub release 自动源码包 | GitHub Release | tag、CHANGELOG 和 CI 通过 |

矩阵中的非源码包产物在对应平台设计完成前不得加入 release workflow。
Linux 矩阵前置条件还包括 [Linux package artifact manifest generation validation contract](architecture/linux-package-artifact-manifest-generation-validation-contract.md)、[Linux package artifact manifest checksum validation contract](architecture/linux-package-artifact-manifest-checksum-validation-contract.md)、[Linux package workflow artifact bundle upload validation contract](architecture/linux-package-workflow-artifact-bundle-upload-validation-contract.md)、[Linux package artifact attestation execution validation contract](architecture/linux-package-artifact-attestation-execution-validation-contract.md)、[Linux package release notes/rollback execution validation contract](architecture/linux-package-release-notes-rollback-execution-validation-contract.md) 和 [Linux package publish eligibility execution validation contract](architecture/linux-package-publish-eligibility-execution-validation-contract.md)。

## Workflow 形态

未来 release workflow 应按以下阶段扩展：

1. `release-policy`：检查 AGENT、CI/CD policy、release strategy、版本格式和 tag/ref 一致性。
2. `release-ci-gate`：按 [Release CI success source contract](architecture/release-ci-success-source-contract.md)、[Linux package release CI gate activation validation contract](architecture/linux-package-release-ci-gate-activation-validation-contract.md)、[Release CI gate execution validation contract](architecture/release-ci-gate-execution-validation-contract.md) 和 [Release CI gate API implementation plan](architecture/release-ci-gate-api-implementation-plan.md) 确认当前 commit 对应 CI run 已成功，或在 release workflow 中重新执行等效验证。
3. `release-artifact-contract`：在 placeholder 阶段记录首个 artifact job 必须暴露的 checksum 输出字段，真实产物加入后由 `package-*` job 输出替代。
4. `release-signing-contract`：在 placeholder 阶段记录真实平台 artifact 发布前必须声明的 signing/attestation 输出字段，真实产物加入后由 `sign-*` 或 attestation job 输出替代。
5. `release-rollback-contract`：在 placeholder 阶段记录 release notes 必须暴露的回滚字段，真实发布加入后由 publish 或 post-release summary job 输出替代。
6. `linux-artifact-readiness`、`ios-upload-readiness` 或对应平台 readiness gate：在真实 packaging/upload 前检查源码、设计、人工事项、protected environment、manual approval、secret status 和发布阻断状态。
7. `package-*`：每个平台先按 artifact job preflight validation contract 验证 license/NOTICE、CI gate、checkout、toolchain、build 和 staging 前置条件，再独立构建产物并输出 checksum、manifest 和 manifest checksum，然后按 workflow artifact bundle upload validation contract 上传同一 release run bundle。
8. `attest-*`：需要 attestation/provenance 的平台按 [Linux package artifact attestation execution validation contract](architecture/linux-package-artifact-attestation-execution-validation-contract.md) 从同一 release run workflow artifact bundle 生成证明。
9. `post-release-summary`、`release-notes-rollback-gate` 或等价 pre-publish gate：按 [Linux package release notes/rollback execution validation contract](architecture/linux-package-release-notes-rollback-execution-validation-contract.md) 校验 release notes required fields、rollback fields、withdrawal/replacement policy 和 publish blocking。
10. `sign-*`：需要签名的平台在受控 runner 中读取 GitHub Secrets 或官方平台凭据。
11. `notarize-*`：macOS 产物完成 Apple notarization 后再进入发布资产。
12. `publish-eligibility-gate`：按 [Linux package publish eligibility execution validation contract](architecture/linux-package-publish-eligibility-execution-validation-contract.md) 聚合 release notes/rollback、attestation/provenance、workflow artifact、manifest、CI、license/NOTICE 和 publish/upload gates，只有 `package_publish_eligibility_status=eligible` 时才允许进入发布。
13. `publish-github-release`：上传 release assets、checksums、release notes 和 provenance/attestation 信息。
14. `release-summary` 或等价 post-publish summary：输出产物清单、验证链接、人工事项和回滚说明。

仍处 placeholder 的平台必须保留或替换为等价的显式说明，并继续输出 artifact manifest output contract 与 license/NOTICE source contract 状态，避免误认为对应平台 release 已经可用。

## 版本与回滚

- 版本号采用 `vMAJOR.MINOR.PATCH` tag 形式，alpha 预发布版本使用 `vMAJOR.MINOR.PATCH-alpha.N`，rc 预发布版本使用 `vMAJOR.MINOR.PATCH-rc.N`；当前 release policy gate 已按该格式检查手动版本输入与 tag 名。
- 任何 release 修复都通过新 tag 发布，不覆盖已发布 tag。
- 如果 release 失败在发布前发生，删除 draft 或 failed run artifact 即可；如果 release asset 已公开，必须发布撤回说明并以新版本替换。
- iOS 和商店渠道回滚依赖 App Store Connect 或对应商店能力，必须在发布说明中记录可用路径。
- macOS/Windows 签名凭据泄漏时必须撤销证书、轮换 Secrets，并记录人工处理项。

## 人工介入边界

以下外部事项不能由仓库自动完成：

- 新增 Linux artifact、artifact 文件集合变化或 license/NOTICE 来源变化时的文本确认和确认状态更新；当前 `networkcore-linux` 范围已 confirmed。
- Apple Developer、App Store Connect、Network Extension entitlement、证书、Provisioning Profile、Privacy Manifest/Required Reason API review、App Privacy disclosure、隐私政策、App Review Notes、demo account、review attachment、TestFlight group、export compliance、beta app review、archive/export、App Store Connect API、protected environment、manual approval、build processing status、App Review submission gate 和 VPN compliance。
- Windows 代码签名证书、时间戳服务和商店账号。
- GitHub Environments、branch protection、release approval policy 和 protected tags。
- 第三方发布渠道账号、API token、税务或合规材料。

完成后应把下一步自动化动作写入 `docs/manual-intervention.md`，并继续用 GitHub Actions 验证。

## 下一步

- 真实平台产物进入 release workflow 前，先为目标平台补齐 adapter 设计文档；Linux 首个产物必须先满足 [Linux artifact pre-release design](architecture/linux-artifact-pre-release-design.md)、[Linux platform adapter design](architecture/linux-platform-adapter.md)、[Linux CLI entrypoint design](architecture/linux-cli-entrypoint.md)、[Linux CLI runtime wiring design](architecture/linux-cli-runtime-wiring.md)、[Native engine listener and node config design](architecture/native-engine-listener-node-config.md)、[Linux native proxy engine start design](architecture/linux-native-proxy-engine-start.md)、[Linux CLI artifact installation and rollback design](architecture/linux-cli-artifact-installation-rollback.md)、[Linux package artifact manifest design](architecture/linux-package-artifact-manifest.md)、[Linux artifact license notice confirmation design](architecture/linux-artifact-license-notice-confirmation.md)、[Linux package license/NOTICE transition validation contract](architecture/linux-package-license-notice-transition-validation-contract.md)、[Release CI success source contract](architecture/release-ci-success-source-contract.md)、[Linux package release CI gate activation validation contract](architecture/linux-package-release-ci-gate-activation-validation-contract.md)、[Release CI gate execution validation contract](architecture/release-ci-gate-execution-validation-contract.md)、[Release CI gate API implementation plan](architecture/release-ci-gate-api-implementation-plan.md)、[Linux package artifact job preflight validation contract](architecture/linux-package-artifact-job-preflight-validation-contract.md)、[Linux package artifact build command validation contract](architecture/linux-package-artifact-build-command-validation-contract.md)、[Linux package artifact staging file validation contract](architecture/linux-package-artifact-staging-file-validation-contract.md)、[Linux package artifact archive creation validation contract](architecture/linux-package-artifact-archive-creation-validation-contract.md)、[Linux package artifact checksum execution validation contract](architecture/linux-package-artifact-checksum-execution-validation-contract.md)、[Linux package artifact manifest generation validation contract](architecture/linux-package-artifact-manifest-generation-validation-contract.md)、[Linux package artifact manifest checksum validation contract](architecture/linux-package-artifact-manifest-checksum-validation-contract.md)、[Linux package workflow artifact bundle upload validation contract](architecture/linux-package-workflow-artifact-bundle-upload-validation-contract.md)、[Linux package artifact attestation execution validation contract](architecture/linux-package-artifact-attestation-execution-validation-contract.md)、[Linux package release notes/rollback execution validation contract](architecture/linux-package-release-notes-rollback-execution-validation-contract.md)、[Linux package publish eligibility execution validation contract](architecture/linux-package-publish-eligibility-execution-validation-contract.md)、[Linux package runner/toolchain/target contract](architecture/linux-package-runner-toolchain-target-contract.md)、[Linux package archive staging contract](architecture/linux-package-archive-staging-contract.md)、[Linux package checksum manifest contract](architecture/linux-package-checksum-manifest-contract.md)、[Linux package publish upload boundary contract](architecture/linux-package-publish-upload-boundary-contract.md)、[Linux package signing/attestation policy binding contract](architecture/linux-package-signing-attestation-policy-binding-contract.md)、[Linux package release notes/rollback policy binding contract](architecture/linux-package-release-notes-rollback-policy-binding-contract.md) 和 [Linux package publish eligibility aggregate contract](architecture/linux-package-publish-eligibility-aggregate-contract.md)。
- Release CI gate API read 已激活；Linux CLI `package-linux` 已定义，license/NOTICE marker 当前为 confirmed，但 tag release 仍必须经过同 commit CI、checksum、manifest、attestation、release notes、rollback 和 publish eligibility gates 后才能上传 release asset。
- iOS 发布前还必须按 [iOS Swift Xcode bridge source contract](architecture/ios-swift-xcode-bridge-source-contract.md)、[iOS embedded runtime FFI boundary design](architecture/ios-embedded-runtime-ffi-boundary-design.md)、[iOS MITM certificate lifecycle design](architecture/ios-mitm-certificate-lifecycle-design.md)、[iOS entitlement/provisioning source contract](architecture/ios-entitlement-provisioning-source-contract.md)、[iOS App Review/privacy release readiness design](architecture/ios-app-review-privacy-release-readiness-design.md)、[iOS Privacy Manifest source contract](architecture/ios-privacy-manifest-source-contract.md)、[iOS App Review manual confirmation source contract](architecture/ios-app-review-manual-confirmation-source-contract.md)、[iOS TestFlight App Store Connect upload workflow source contract](architecture/ios-testflight-app-store-connect-upload-workflow-source-contract.md)、[iOS upload workflow activation validation contract](architecture/ios-upload-workflow-activation-validation-contract.md)、[iOS Swift/Xcode source tree activation preflight contract](architecture/ios-swift-xcode-source-tree-activation-preflight-contract.md)、[iOS Package.swift source ownership activation preflight contract](architecture/ios-package-swift-source-ownership-activation-preflight-contract.md) 和 [iOS Package.swift manifest-only activation validation contract](architecture/ios-package-swift-manifest-only-activation-validation-contract.md) 完成真实 Swift/Xcode bridge 源码、Rust embedded runtime FFI 源码、certificate lifecycle 源码、entitlement/provisioning 源码、Privacy Manifest 源码、Provisioning Profile、App Privacy disclosure、隐私政策、App Review Notes、demo account、review attachment、TestFlight/App Store Connect 人工确认 marker、upload workflow enabled marker、VPN compliance 和 GitHub Actions macOS 验证入口；当前继续保持 upload/release blocked 且不新增真实 `Package.swift`。

## 参考

- GitHub Docs: Managing releases in a repository, `https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository`
- GitHub Docs: Storing workflow data as artifacts, `https://docs.github.com/en/actions/using-workflows/storing-workflow-data-as-artifacts`
- GitHub Docs: Using artifact attestations, `https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds`
- Apple Developer Documentation: Notarizing macOS software before distribution, `https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution`
- Apple Developer Account Help: Provisioning with capabilities, `https://developer.apple.com/help/account/reference/provisioning-with-managed-capabilities/`
