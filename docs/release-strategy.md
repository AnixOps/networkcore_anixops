# Release Strategy

本文件定义真实平台产物进入 `.github/workflows/release.yml` 前必须满足的发布策略与门禁。逐版本能力边界见 [Alpha Release Feature Matrix](alpha-release-feature-matrix.md)，人工事项见 `docs/manual-intervention.md`。

## 当前发布状态

- 当前最新 stable 是 `v0.2.0`（2026-10-26，tag 在 `a636b89`）：Linux CLI、Linux 图形客户端 tarball 与 `.deb`、Windows MSI 与 portable ZIP 四件套。上一个 stable 是 `v0.1.0`（Linux-only）。
- `v0.2.0` 之前最后的 prerelease 是 `v0.2.0-rc.2`；更早的 `v0.2.0-beta.5` 与 `v0.2.0-beta.4`（`v0.2.0-beta.3`、`v0.2.0-beta.4` 均为维护者授权的验收候选，未通过真实主机验收）。
- `v0.2.0-beta.5` 的真机验收没有完成，验收改在 `v0.2.0-rc.2` 上进行并已通过。
- 每次 tag release 同时产出 Linux CLI 四件套、Linux 图形客户端 tarball 与 `.deb` 各一套四件套（自 `v0.2.0` 起）、Windows managed client MSI 四件套和 Windows portable ZIP 四件套（archive、sha256、manifest、manifest sha256）。MSI/portable ZIP 不捆绑或静默下载第三方 core。`workflow_dispatch` 只验证，不发布。
- 没有本机打包或发布路径；用户可下载状态以同名 tag workflow 成功结果为准。

Linux artifact release state consistency：

```text
linux-artifact-release-state=confirmed-release-path
linux-artifact-license-notice-status=confirmed
linux-artifact-publish-scope=tag-release-after-all-gates
```

`docs/manual-intervention.md` 中的 license/NOTICE marker 已为 `linux-artifact-license-notice-status=confirmed`。它只解除 license/NOTICE 人工门禁；若 marker 缺失、非法或回退到 pending，`linux-artifact-readiness` 必须失败，且不得继续构建、上传或发布。

## 发布原则

- CI/CD Only：所有 build、test、lint、security scan、package、sign、notarize、upload 都必须在 GitHub Actions 或官方平台完成；不在本机打包、签名、测试或发布。
- Source Of Truth：release 只能基于 Git tag、受控分支或手动指定版本，不接受本地构建产物。
- One Artifact, One Job：每类平台产物使用独立 job，避免一个失败路径污染其他平台。
- Reproducible Inputs：release job 必须记录 commit SHA、tag、workspace manifest、toolchain 和 artifact 名称。
- No Secret In Repo：签名证书、Provisioning Profile、App Store Connect、Windows signing、GitHub token 只能走 GitHub Secrets、Environments 或官方平台。
- Rollback First：每个产物都要有可描述的撤回、替换或禁用路径。

## 发布门禁

真实 artifact job 合入或发布前必须满足：

1. **CI gate**：`release-ci-gate`（job 级 `actions: read`）自动读取同 repository、同 commit、`main` 分支、`completed`/`success` 的 CI run 并校验 `CI summary` job。见 [Release CI success source contract](architecture/release-ci-success-source-contract.md)、[Release CI gate execution validation contract](architecture/release-ci-gate-execution-validation-contract.md)、[Release CI gate API implementation plan](architecture/release-ci-gate-api-implementation-plan.md)、[Linux package release CI gate activation validation contract](architecture/linux-package-release-ci-gate-activation-validation-contract.md)。
2. **源码与设计**：artifact 对应源码、平台设计和安装/卸载/回滚设计已存在，不发布 placeholder、空壳或本地产物。
3. **显式 job 输入**：每个 artifact job 声明 runner、toolchain、target triple、版本、输出文件名、staging 目录、checksum/manifest 文件；Linux 细则见下方 Linux 打包合同。
4. **受控 runner 与 bundle**：产物由 GitHub-hosted runner 生成，先上传同一 release run 的 workflow artifact bundle，再由 publish job 校验后上传 GitHub Release asset。
5. **Checksum**：至少输出 `artifact_name`、`artifact_path`、`checksum_algorithm`（默认 `sha256`）、`checksum_file`、`checksum_value`。
6. **签名/attestation**：输出 `signing_policy`、`signing_status`、`attestation_policy`、`attestation_status`、`provenance_policy`、`provenance_file`。Linux 保持 unsigned tarball，但必须有可验证的 GitHub artifact attestation。
7. **人工前置**：Apple、Windows 签名或商店发布的账号、证书、密钥和 Secrets 先完成并记录到 `docs/manual-intervention.md`。
8. **发布说明与回滚**：链接 CHANGELOG、CI run、release run，并输出 `rollback_scope`、`rollback_trigger`、`rollback_steps`、`replacement_version`、`rollback_owner`、withdrawal/replacement policy。
9. **Publish eligibility**：`publish-eligibility-gate` 聚合上述所有 gate，只有 `package_publish_eligibility_status=eligible` 才进入 `publish-github-release`；公开 asset 不得覆盖同名 tag，只能以新版本替换或发布撤回说明。

## Release workflow

当前 job 依次为：

1. `release-policy`：检查治理文档、版本格式和触发来源；`workflow_dispatch` 必须从 `main` 发起，tag release 必须使用同名版本。
2. `release-ci-gate`：见门禁 1。
3. `release-artifact-contract`、`release-signing-contract`、`release-rollback-contract`：固定 checksum、签名/attestation 和回滚输出字段。
4. 平台 readiness：`linux-artifact-readiness`（检查 Linux 源码、设计、全部打包合同和 license/NOTICE marker）、`windows-cli-artifact-readiness`、`ios-upload-readiness`。
5. `package-linux`：`ubuntu-latest` 上以受版本控制的 `Cargo.lock` 执行 `cargo build --locked --release --package networkcore-linux --bin networkcore-linux --target x86_64-unknown-linux-gnu`，组装 `networkcore-linux-${version}-${target}.tar.gz`、`.sha256`、manifest JSON 和 manifest `.sha256`。
6. `package-windows`：`windows-latest` 上以 Rust GNU target 构建 `networkcore-windows`、`networkcore-windows-gui`、`networkcore-windows-service`，用 WiX 4.0.6 生成 per-machine MSI 与 portable ZIP（schema-version-2 manifest），并做有界 MSI install/uninstall smoke。
7. `attest-linux`、`attest-windows`：下载同 run bundle，重新校验 checksum，对 archive、checksum、manifest、manifest checksum 生成 GitHub artifact attestation。
8. `post-release-summary`、`publish-eligibility-gate`：校验 release notes、rollback、withdrawal/replacement policy 与 eligibility。
9. `publish-github-release`：仅 tag push 时创建同名 GitHub Release 并上传符合 eligibility 的资产。
10. `release-summary`：输出来源、各 gate 与合同状态、人工事项和回滚说明。

未来平台按需增加 `sign-*`（受控 runner 读取 Secrets）和 `notarize-*`（macOS notarization）。仍处 placeholder 的平台必须输出显式 blocked 说明，避免误认为对应 release 已可用。

### Linux 打包合同

`package-linux` 受以下合同约束（均在 [docs/README.md](README.md#linux-发布流水线合同) 中列出）：artifact pre-release design、installation/rollback design、artifact manifest design、license/NOTICE confirmation 与 transition validation、job preflight、build command、staging file、archive creation、checksum execution、manifest generation、manifest checksum、workflow artifact bundle upload、attestation execution、release notes/rollback execution、publish eligibility execution、runner/toolchain/target、archive staging、checksum manifest、publish/upload boundary、signing/attestation policy binding、release notes/rollback policy binding 和 publish eligibility aggregate。

### Windows 发布路径

- **Windows CLI artifact**（历史）：`v0.1.1-alpha.1` 发布 source/release contract，`v0.1.1-alpha.2` 激活 Windows CLI package/publish path，`package-windows` 生成 `networkcore-windows` manual-extract zip 四件套。仅保留为审计记录，合同见 [windows-cli-artifact-source-release-contract.md](architecture/windows-cli-artifact-source-release-contract.md)。
- **Windows managed client MSI**（当前）：自 `v0.2.0-alpha.1` 起发布。安装器注册 automatic SCM service，完整卸载前运行 service `purge`；GUI/service/platform 激活 signed INF driver package、WinINet/WinHTTP system proxy、LocalMachine ROOT CA 和 managed lifecycle 的 apply/rollback。合同见 [Windows Managed Client Source Release Contract](architecture/windows-managed-client-source-release-contract.md)。

| 版本 | 新增（同一 MSI/portable/attestation/publish path） |
|---|---|
| `v0.2.0-alpha.2` | operator-staged sing-box managed process、official ZIP extraction、PID/exit 诊断 |
| `v0.2.0-alpha.3` | install-time service start 异步化；每个 tag 增加 portable ZIP 四件套与 MSI smoke |
| `v0.2.0-alpha.4` | GUI 显式官方 sing-box core install 与本地 profile import |
| `v0.2.0-alpha.5` | service-owned CA lifecycle 与受控 HTTP/1.1 HTTPS MITM |
| `v0.2.0-alpha.6` | 原生 sing-box JSON 直通导入、`sing-box.log` 诊断入口 |
| `v0.2.0-alpha.7` | 原生 JSON `mixed-in` inbound 的 MITM snapshot/restore |
| `v0.2.0-alpha.8` | Hysteria2/TUIC 导入与 direct QUIC 渲染（不进入 MITM） |
| `v0.2.0-alpha.9` | V2Ray-family TLS/REALITY/uTLS/Vision/transport compatibility subset |
| `v0.2.0-alpha.10` | SCM handoff 先于 runtime 配置；坏配置不阻塞 Start，CI 用无效配置验证 |
| `v0.2.0-alpha.11` | GUI `check -c` 预检与本地 diagnostics report |
| `v0.2.0-alpha.12`–`alpha.14` | HTTP(S) 订阅手动导入、`Update URL`、`Load nodes` |
| `v0.2.0-alpha.15`–`alpha.17` | NodeCatalog selector、回环 Clash API `Switch active`、`Test delay`、`Check core` |
| `v0.2.0-alpha.18`–`alpha.19` | service 独占 proxy snapshot；监督 sing-box 子进程并在异常退出时回滚 |
| `v0.2.0-alpha.21` | GUI 重组为 Home/Nodes/Subscriptions/Settings/Diagnostics/Advanced；tray、登录启动、opt-in 自动连接与一次核心恢复（见 [Windows GUI Daily Usability](architecture/windows-gui-daily-usability.md)） |
| `v0.2.0-beta.5` | 应用当前用户代理前独立验证 SCM、`check -c`、PID、loopback listener、selector readback；opt-in 小时级单源订阅刷新；失败回滚 GUI-owned proxy。需真实 Windows 桌面验收 |

不启用：LAN controller、Web UI、`urltest`、自动延迟选择、订阅组、TUN/DNS 拦截、XHTTP/ECH/multiplex 推断、HTTP/2/HTTP/3/QUIC MITM、streaming 和 JavaScript dispatch。

## 产物矩阵

| 平台/产物 | 形态 | Runner | 状态 / 前置条件 |
| --- | --- | --- | --- |
| Rust crates | 暂不发布到 crates.io | `ubuntu-latest` | 公共 API 稳定、license 与 README 完整、crate publishing policy 单独评审 |
| Linux | `networkcore-linux` CLI tarball | `ubuntu-latest` | 已激活；需满足上方 Linux 打包合同和全部门禁 |
| Linux 图形客户端 | `anixops-net` tarball 与 `.deb` | `ubuntu-latest` | 自 `v0.2.0` 起激活（`package-linux-gui`、`attest-linux-gui`）；未签名，依赖 WebKitGTK 4.1 |
| Windows | `networkcore-windows` managed-client MSI 与 portable ZIP | `windows-latest` | 已激活；当前候选 `v0.2.0-beta.5` |
| macOS | 待定义 CLI、app bundle、`.pkg` 或 `.dmg` | `macos-26` | 签名、notarization、entitlement 和 Gatekeeper 路径完成 |
| iOS | TestFlight / App Store Connect | `macos-26` | `ios-upload-readiness` 仍 blocked：需嵌入式 runtime、签名与 Provisioning Profile、Privacy Manifest、App Privacy、隐私政策、App Review Notes、人工确认与 upload enabled marker、protected environment、manual approval、App Store Connect API 和 VPN compliance（各 iOS 合同见 [docs/README.md](README.md#ios)） |
| Source archive | GitHub release 自动源码包 | GitHub Release | tag、CHANGELOG 和 CI 通过 |

矩阵中的非源码包产物在对应平台设计完成前不得加入 release workflow。

## 版本与回滚

- 版本号采用 `vMAJOR.MINOR.PATCH` tag；alpha、beta、rc 预发布分别为 `-alpha.N`、`-beta.N`、`-rc.N`，N 为无前导零的正整数，为保持 Windows Installer 版本排序分别限定 `1-499`、`1-399`、`1-98`。release policy gate 按此检查手动输入与 tag 名。
- 任何 release 修复都通过新 tag 发布，不覆盖已发布 tag。
- 发布前失败：删除 draft 或 failed run artifact；asset 已公开：发布撤回说明并以新版本替换。
- iOS 和商店渠道回滚依赖 App Store Connect 或对应商店能力，须在发布说明中记录。
- macOS/Windows 签名凭据泄漏时必须撤销证书、轮换 Secrets，并记录人工处理项。

## 人工介入边界

以下外部事项不能由仓库自动完成，完成后把下一步自动化动作写入 `docs/manual-intervention.md`：

- 新增 Linux artifact、文件集合变化或 license/NOTICE 来源变化时的文本确认（当前 `networkcore-linux` 范围已 confirmed）。
- Apple Developer、App Store Connect、Network Extension entitlement、证书、Provisioning Profile、Privacy Manifest/Required Reason API review、App Privacy、隐私政策、App Review Notes、demo account、TestFlight group、export compliance、beta app review、protected environment、manual approval、App Review submission 和 VPN compliance。
- Windows 代码签名证书、时间戳服务和商店账号。
- GitHub Environments、branch protection、release approval policy 和 protected tags。
- 第三方发布渠道账号、API token、税务或合规材料。

## 参考

- GitHub Docs: [Managing releases in a repository](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository)
- GitHub Docs: [Storing workflow data as artifacts](https://docs.github.com/en/actions/using-workflows/storing-workflow-data-as-artifacts)
- GitHub Docs: [Using artifact attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds)
- Apple: [Notarizing macOS software before distribution](https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution)
- Apple: [Provisioning with capabilities](https://developer.apple.com/help/account/reference/provisioning-with-managed-capabilities/)
