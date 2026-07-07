# Linux CLI Artifact Installation And Rollback Design

本文件定义首个 `networkcore-linux` CLI 压缩包进入 release workflow 前必须满足的安装、卸载和回滚边界。它承接 [Linux Artifact Pre-Release Design](linux-artifact-pre-release-design.md)、[Linux CLI Entrypoint Design](linux-cli-entrypoint.md)、[Linux Package Artifact Manifest Design](linux-package-artifact-manifest.md)、[Linux Artifact License Notice Confirmation Design](linux-artifact-license-notice-confirmation.md)、[Linux Package License Notice Transition Validation Contract](linux-package-license-notice-transition-validation-contract.md)、[Release CI Success Source Contract](release-ci-success-source-contract.md)、[Linux Package Release CI Gate Activation Validation Contract](linux-package-release-ci-gate-activation-validation-contract.md)、[Release CI Gate Execution Validation Contract](release-ci-gate-execution-validation-contract.md)、[Linux Package Runner Toolchain Target Contract](linux-package-runner-toolchain-target-contract.md)、[Linux Package Archive Staging Contract](linux-package-archive-staging-contract.md)、[Linux Package Checksum Manifest Contract](linux-package-checksum-manifest-contract.md)、[Linux Package Publish Upload Boundary Contract](linux-package-publish-upload-boundary-contract.md)、[Linux Package Workflow Artifact Bundle Upload Validation Contract](linux-package-workflow-artifact-bundle-upload-validation-contract.md)、[Linux Package Artifact Attestation Execution Validation Contract](linux-package-artifact-attestation-execution-validation-contract.md)、[Linux Package Release Notes Rollback Execution Validation Contract](linux-package-release-notes-rollback-execution-validation-contract.md)、[Linux Package Publish Eligibility Execution Validation Contract](linux-package-publish-eligibility-execution-validation-contract.md)、[Linux Package Signing Attestation Policy Binding Contract](linux-package-signing-attestation-policy-binding-contract.md)、[Linux Package Release Notes Rollback Policy Binding Contract](linux-package-release-notes-rollback-policy-binding-contract.md)、[Linux Package Publish Eligibility Aggregate Contract](linux-package-publish-eligibility-aggregate-contract.md) 和 [Release Strategy](../release-strategy.md)，不是当前可下载产物说明。

评估时间：2026-07-06。

## 目标

- 定义首个 Linux CLI 压缩包的目录布局、安装方式和卸载边界。
- 确保首个 artifact 不默认修改系统服务、DNS、路由、防火墙、证书信任或 capability。
- 明确公开 asset 发布后的撤回、替换和用户侧降级路径。
- 为后续 `package-linux` release job 提供可检查的前置条件。

## 非目标

- 不在本文实现 packaging、安装器、daemon、systemd unit、`.deb`、`.rpm` 或发行版仓库。
- 不在本机打包、运行、测试或验收 Linux artifact。
- 不授予 root、`CAP_NET_ADMIN`、TUN 权限、证书信任或系统 DNS 修改能力。
- 不定义后台控制协议、自动升级器或跨发行版包管理策略。

## Artifact 形态

首个 Linux CLI artifact 只能是 GitHub Actions 生成的压缩包，推荐命名为：

`networkcore-linux-${version}-${target}.tar.gz`

压缩包必须包含一个顶层目录：

`networkcore-linux-${version}-${target}/`

首批文件边界：

| 路径 | 要求 |
| --- | --- |
| `bin/networkcore-linux` | 由 GitHub Actions 构建的 CLI 可执行文件 |
| `README.md` 或 `INSTALL.md` | 当前 artifact 的手动运行、安装、卸载和回滚说明 |
| `LICENSE` | 仓库 license 或等价许可说明 |
| `CHANGELOG.md` | 对应版本变更摘要或链接 |

checksum 文件和 sidecar manifest 必须由 release job 单独输出，算法默认为 `sha256`。
checksum 文件命名、sha256 计算顺序和 manifest checksum 交叉校验遵守
[Linux Package Checksum Manifest Contract](linux-package-checksum-manifest-contract.md)，manifest
形态和字段遵守 [Linux Package Artifact Manifest Design](linux-package-artifact-manifest.md)，manifest
checksum sidecar 生成前置验证遵守
[Linux Package Artifact Manifest Checksum Validation Contract](linux-package-artifact-manifest-checksum-validation-contract.md)。
压缩包内不得包含预生成配置、私钥、证书私钥、systemd unit、shell installer、包管理器脚本或自动修改系统状态的脚本。

## 安装边界

首个 artifact 采用手动解压模型，不提供安装器：

1. 用户下载压缩包和 checksum。
2. 用户校验 checksum。
3. 用户解压到自己选择的目录，例如用户目录下的版本化路径。
4. 用户直接运行 `bin/networkcore-linux`，或自行把该二进制加入 `PATH`。

首版安装说明必须明确：

- artifact 不需要 root 安装。
- artifact 不创建系统服务，不后台启动进程。
- artifact 不修改 `/etc/resolv.conf`、systemd-resolved、NetworkManager、路由表、防火墙或证书信任。
- 需要配置的命令继续要求显式 `--config <path>`。
- 如平台能力不足，CLI 通过稳定诊断 code 报告，不在安装阶段尝试修复。

任何 `sudo install`、写入 `/usr/local/bin`、`setcap`、systemd unit、shell installer、`.deb` 或 `.rpm` 都必须先补充单独设计和回滚路径。

## 权限与能力

首个压缩包不得在打包或安装阶段授予 capability。后续如需要 TUN、路由或 DNS 变更能力，必须通过 Linux platform adapter 诊断暴露状态，并在单独设计中定义：

- 需要的 Linux capability 或 root 操作。
- 授权前的用户确认文本。
- 授权状态检测方法。
- 撤销 capability、服务、DNS、路由和证书信任的步骤。
- GitHub Actions 中可验证的安装和回滚合同。

没有上述设计前，`networkcore-linux start` 只能以前台模式尝试运行，并在平台拒绝时返回诊断。

## 卸载边界

首个 artifact 的卸载必须可由用户手动完成：

1. 停止正在前台运行的 `networkcore-linux` 进程。
2. 删除解压出的版本化目录。
3. 删除用户自行创建的 symlink、PATH wrapper 或 shell alias。
4. 删除下载的压缩包和 checksum 文件。

由于首个 artifact 不安装服务、不写系统配置、不授予 capability、不安装证书，卸载不需要清理 systemd、DNS、路由、防火墙或 trust store。若后续版本新增任何系统级修改，必须同步新增可撤销清单，并在 release notes 中说明旧版本用户是否受影响。

## 用户侧回滚

用户侧回滚以版本化目录切换为核心：

- 停止当前前台进程。
- 切换到上一个已保留的解压目录，或重新下载旧版本 artifact。
- 重新校验旧版本 checksum。
- 通过 `networkcore-linux version` 确认运行版本。
- 使用与旧版本兼容的显式配置文件启动。

如果新版本引入配置 schema 变化，release notes 必须说明 downgrade 兼容性。不能无损降级时，必须给出配置恢复或手动迁移路径；没有降级说明不得发布对应 artifact。

## 发布侧回滚

公开 release asset 后不得覆盖同名 tag 或同名 asset。回滚必须按 [Release Strategy](../release-strategy.md) 执行：

| 场景 | 处理 |
| --- | --- |
| 发布前 packaging 失败 | 失败 run 不发布；删除 draft 或丢弃 workflow artifact |
| 发布后发现 artifact 损坏 | 发布撤回说明，并用新版本 tag 替换 |
| checksum 或 provenance 不匹配 | 立即撤回该 release asset，记录触发原因和替代版本 |
| 安装说明错误 | 发布修正文档；如可能导致错误安装，发布撤回说明或新版本 |
| 安全问题 | 发布安全公告，撤回受影响 asset，并要求用户升级到 replacement version |

release notes 和 release summary 必须输出：

- `rollback_scope`
- `rollback_trigger`
- `rollback_steps`
- `replacement_version`
- `rollback_owner`

## `package-linux` 前置条件

真实 `package-linux` job 加入 `.github/workflows/release.yml` 前必须满足：

- `apps/linux-cli` 源码存在，并在 `main` 同 commit 上通过 CI 的 Rust format、lint、test、build 和 dependency audit。
- [Linux Platform Adapter Design](linux-platform-adapter.md)、[Linux CLI Entrypoint Design](linux-cli-entrypoint.md)、[Linux CLI Runtime Wiring Design](linux-cli-runtime-wiring.md)、[Native Engine Listener And Node Config Design](native-engine-listener-node-config.md)、[Linux Native Proxy Engine Start Design](linux-native-proxy-engine-start.md)、[Linux Artifact Pre-Release Design](linux-artifact-pre-release-design.md)、[Linux Package Artifact Manifest Design](linux-package-artifact-manifest.md)、[Linux Artifact License Notice Confirmation Design](linux-artifact-license-notice-confirmation.md)、[Linux Package License Notice Transition Validation Contract](linux-package-license-notice-transition-validation-contract.md)、[Release CI Success Source Contract](release-ci-success-source-contract.md)、[Linux Package Release CI Gate Activation Validation Contract](linux-package-release-ci-gate-activation-validation-contract.md)、[Release CI Gate Execution Validation Contract](release-ci-gate-execution-validation-contract.md)、[Linux Package Artifact Job Preflight Validation Contract](linux-package-artifact-job-preflight-validation-contract.md)、[Linux Package Artifact Build Command Validation Contract](linux-package-artifact-build-command-validation-contract.md)、[Linux Package Runner Toolchain Target Contract](linux-package-runner-toolchain-target-contract.md)、[Linux Package Archive Staging Contract](linux-package-archive-staging-contract.md)、[Linux Package Checksum Manifest Contract](linux-package-checksum-manifest-contract.md)、[Linux Package Publish Upload Boundary Contract](linux-package-publish-upload-boundary-contract.md)、[Linux Package Workflow Artifact Bundle Upload Validation Contract](linux-package-workflow-artifact-bundle-upload-validation-contract.md)、[Linux Package Artifact Attestation Execution Validation Contract](linux-package-artifact-attestation-execution-validation-contract.md)、[Linux Package Release Notes Rollback Execution Validation Contract](linux-package-release-notes-rollback-execution-validation-contract.md)、[Linux Package Publish Eligibility Execution Validation Contract](linux-package-publish-eligibility-execution-validation-contract.md)、[Linux Package Signing Attestation Policy Binding Contract](linux-package-signing-attestation-policy-binding-contract.md)、[Linux Package Release Notes Rollback Policy Binding Contract](linux-package-release-notes-rollback-policy-binding-contract.md)、[Linux Package Publish Eligibility Aggregate Contract](linux-package-publish-eligibility-aggregate-contract.md) 和本文档均通过 CI governance 检查。
- `linux-artifact-readiness` release job 检查 CLI 源码、platform adapter、native listener/node 配置设计、foreground stop/release 源码与合同测试、artifact manifest 合同设计、license/NOTICE confirmation source contract、license/NOTICE transition validation contract、release CI success source contract、release CI gate activation validation contract、release CI gate execution validation contract、artifact job preflight validation contract、artifact build command validation contract、artifact staging file validation contract、package runner/toolchain/target contract、archive staging contract、checksum/manifest checksum contract、publish/upload boundary contract、workflow artifact bundle upload validation contract、artifact attestation execution validation contract、release notes/rollback execution validation contract、publish eligibility execution validation contract、signing/attestation policy binding contract、release notes/rollback policy binding contract、publish eligibility aggregate contract、安装/回滚设计和 license/NOTICE pending marker，并继续阻止 release asset 上传。
- `release-ci-gate` 输出 release CI success source contract、release CI gate execution validation contract 和 required CI run/source 字段，真实 `package-linux` 前必须替换为同 commit 成功 CI run 自动读取门禁。
- `docs/manual-intervention.md` 中的 `linux-artifact-license-notice-status` 必须从 `pending` 切换到 `confirmed` 后，真实 `package-linux` 才能进入后续 CI、checksum、manifest、签名/证明和回滚门禁。
- release job 明确 preflight status、build command status、staging file status、runner、Rust toolchain、target triple、crate、binary、artifact 文件名、staging 目录、顶层目录、文件来源、checksum 文件、manifest 文件、manifest checksum 文件、workflow artifact bundle、retention days、release asset set、attestation execution、release notes/rollback execution、publish eligibility execution、signing policy、attestation policy、provenance reference、release notes policy、rollback policy、withdrawal/replacement policy、publish eligibility aggregate 状态和上传路径，并与 artifact job preflight validation contract、artifact build command validation contract、artifact staging file validation contract、package runner/toolchain/target contract、archive staging contract、checksum manifest contract、publish/upload boundary contract、workflow artifact bundle upload validation contract、artifact attestation execution validation contract、release notes/rollback execution validation contract、publish eligibility execution validation contract、signing/attestation policy binding contract、release notes/rollback policy binding contract、publish eligibility aggregate contract 一致。
- release job 输出 `artifact_name`、`artifact_path`、`checksum_algorithm`、`checksum_file`、`checksum_value`。
- release job 输出 `artifact_manifest_name`、`artifact_manifest_path`、`artifact_manifest_checksum_file`、`artifact_manifest_checksum_value`。
- release job 输出 `signing_policy`、`signing_status`、`attestation_policy`、`attestation_status`、`provenance_policy`、`provenance_file`。
- release job 输出 `release_notes_policy`、`release_notes_status`、`rollback_policy`、`rollback_status`、`withdrawal_policy`、`replacement_policy`。
- release job 输出 `package_publish_eligibility_status`、`package_publish_eligibility_required_gates` 和每个 required gate 的 eligible/blocked 状态。
- placeholder 阶段的 release placeholder 和 release summary 已列出 manifest output contract 字段与 license/NOTICE source contract pending 状态，真实 job 不得删除该可见性。
- release summary 输出安装模型、卸载边界、archive checksum、manifest checksum、回滚字段和 GitHub Actions 验证链接。
- 发布说明链接本文档、CHANGELOG、CI run 和 release run。

缺少任一前置条件时，release workflow 必须继续保持 placeholder 或 readiness-gate 状态，不得上传 Linux artifact。

## 验收条件

- 本文档保持在 README、ROADMAP、Release Strategy、Linux artifact 设计、Linux package artifact job preflight validation contract、Linux package artifact build command validation contract、Linux package artifact staging file validation contract、Linux package workflow artifact bundle upload validation contract、Linux package artifact attestation execution validation contract、Linux package release notes/rollback execution validation contract、Linux package publish eligibility execution validation contract 和 CI policy 中可发现。
- [Linux Package Archive Staging Contract](linux-package-archive-staging-contract.md) 保持与本文档的手动解压、禁止系统变更和顶层目录边界一致。
- `.github/workflows/ci.yml` governance 检查本文档存在和标题。
- TODO 把本设计标记为完成，并指向下一步最小 release workflow 增量。
- 当前 `apps/linux-cli` 仍可作为源码前置条件，但不因本文档完成而自动成为可发布 artifact。
