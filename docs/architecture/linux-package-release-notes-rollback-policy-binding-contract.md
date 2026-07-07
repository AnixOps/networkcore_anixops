# Linux Package Release Notes Rollback Policy Binding Contract

本文定义首个真实 Linux `package-linux` artifact 在进入 publish/upload 前必须遵守的
release notes、rollback summary、withdrawal/replacement 策略和未启用时的 blocked 状态。
当前仍为 placeholder 合同，不定义 `package-linux` job、不生成 release notes、不创建 GitHub
Release、不上传 workflow artifact 或 GitHub Release asset。

评估时间：2026-07-07。

## 目标

- 明确首个 Linux CLI tarball 的 release notes 必填字段。
- 固定 release summary、manifest 和 publish gate 必须读取的 rollback/withdrawal 字段。
- 说明当前未生成 release notes 或 rollback summary 时的 blocked 状态。
- 在 license/NOTICE、同 commit CI success、checksum/manifest checksum、publish/upload 和
  signing/attestation gates 完成前继续阻止真实 artifact。

## 非目标

- 不实现 `package-linux` job。
- 不实现 `publish-github-release`、`post-release-summary` 或等价 release notes job。
- 不创建 GitHub Release、draft release、release notes、workflow artifact 或 release asset。
- 不定义自动升级器、远程撤回开关、包管理器仓库撤回流程或商店渠道回滚策略。
- 不把 GitHub token、API response 原文、runner 本地绝对路径、secret、证书私钥、用户配置、
  人工身份私有信息或安全公告草稿写入 manifest、release notes 或 Step Summary。

## Source Of Truth

首个真实 Linux release notes/rollback 输入必须来自本文档、
[Linux CLI Artifact Installation And Rollback Design](linux-cli-artifact-installation-rollback.md)、
[Linux Package Artifact Manifest Design](linux-package-artifact-manifest.md)、
[Linux Package Publish Upload Boundary Contract](linux-package-publish-upload-boundary-contract.md)、
[Linux Package Signing Attestation Policy Binding Contract](linux-package-signing-attestation-policy-binding-contract.md)、
[Linux Package Publish Eligibility Aggregate Contract](linux-package-publish-eligibility-aggregate-contract.md)、
[Release CI Success Source Contract](release-ci-success-source-contract.md)、`CHANGELOG.md` 和
release workflow 中的显式常量。不得由 maintainer 在 `workflow_dispatch` 中手动输入 rollback
status、withdrawal status、replacement version 或 release asset eligibility 来绕过门禁。

当前首个 Linux release notes/rollback policy 固定为：

| 字段 | 值 |
| --- | --- |
| `package_release_notes_rollback_policy_contract` | `present` |
| `package_release_notes_policy` | `required-before-publish` |
| `package_release_notes_status` | `blocked-not-generated` |
| `package_release_notes_source` | `CHANGELOG.md-and-release-summary` |
| `package_release_notes_required_fields` | `version,artifact,checksums,ci,release,install,signing,rollback,withdrawal,replacement` |
| `package_rollback_policy` | `manual-extract-version-switch` |
| `package_rollback_status` | `blocked-not-summarized` |
| `package_rollback_scope` | `linux-cli-artifact` |
| `package_rollback_trigger` | `checksum-install-runtime-security-or-provenance-defect` |
| `package_rollback_steps` | `withdraw-release-asset-and-publish-replacement-version` |
| `package_replacement_version` | `next-version-required` |
| `package_rollback_owner` | `maintainer` |
| `package_withdrawal_policy` | `withdrawal-not-overwrite` |
| `package_replacement_policy` | `new-version-tag-required` |
| `package_publish_without_rollback` | `blocked` |

首个 Linux release notes 必须说明该 artifact 是手动解压模型，不安装服务、不修改系统状态、
不授予 capability、不安装证书、不提供后台 daemon/control socket。公开 asset 后不得覆盖同名
tag 或同名 asset；修复必须发布新版本，或发布撤回说明并阻止继续推荐受影响 asset。

## Release Notes Binding

真实 release notes 必须至少包含以下可审计信息：

| 字段组 | 必填内容 |
| --- | --- |
| `version` | release version、tag/ref、commit SHA |
| `artifact` | artifact name、target triple、package format、install model |
| `checksums` | archive sha256、manifest sha256、checksum algorithm |
| `ci` | 同 commit 成功 CI run URL 和 run id |
| `release` | release run URL、publish job 名称、asset set |
| `install` | 手动解压、无系统变更、无 service install、无 capability grant |
| `signing` | signing policy、attestation status、provenance reference |
| `rollback` | rollback scope、trigger、steps、replacement version、owner |
| `withdrawal` | withdrawal policy、overwrite/delete policy、用户应采取的动作 |
| `replacement` | replacement policy、next version requirement、downgrade compatibility |

如果新版本引入配置 schema、安装模型、system mutation policy、权限、证书、service 或 daemon 行为
变化，release notes 必须明确 downgrade compatibility 和用户迁移路径。不能说明 downgrade 或
replacement 策略时，不得发布对应 Linux artifact。

## Manifest Binding

真实 `package-linux` manifest 的 release notes/rollback 字段必须与本文档和 release workflow
outputs 完全一致。首个 Linux artifact 的最小发布前状态为：

```json
{
  "release_notes": {
    "release_notes_policy": "required-before-publish",
    "release_notes_status": "published",
    "release_notes_source": "CHANGELOG.md-and-release-summary",
    "withdrawal_policy": "withdrawal-not-overwrite",
    "replacement_policy": "new-version-tag-required"
  },
  "rollback": {
    "rollback_policy": "manual-extract-version-switch",
    "rollback_status": "summarized",
    "rollback_scope": "linux-cli-artifact",
    "rollback_trigger": "checksum-install-runtime-security-or-provenance-defect",
    "rollback_steps": "withdraw-release-asset-and-publish-replacement-version",
    "replacement_version": "next-version-required",
    "rollback_owner": "maintainer"
  }
}
```

当前 placeholder 不生成 manifest，只能输出 blocked 状态：

```json
{
  "release_notes_policy": "required-before-publish",
  "release_notes_status": "blocked-not-generated",
  "rollback_policy": "manual-extract-version-switch",
  "rollback_status": "blocked-not-summarized",
  "withdrawal_policy": "withdrawal-not-overwrite",
  "replacement_policy": "new-version-tag-required",
  "publish_without_rollback": "blocked"
}
```

`replacement_version=next-version-required` 表示公开 asset 出现需要替换的问题时，必须用新的
version tag 发布替代版本；不得覆盖已公开 tag 或同名 asset。

## Job Boundary

真实 release workflow 后续必须按以下顺序处理 Linux release notes/rollback：

1. `package-linux` 生成 archive、archive checksum、manifest 和 manifest checksum。
2. `attest-linux` 输出 GitHub artifact attestation/provenance 状态。
3. rollback/release notes gate 读取 manifest、checksum、CI source、license/NOTICE、install model、
   signing/attestation 和 publish/upload 字段。
4. rollback/release notes gate 输出 release notes required fields 和 rollback summary。
5. `publish-github-release` 在上传前校验 rollback/release notes 状态。
6. 只有 `package_release_notes_status=published` 且 `package_rollback_status=summarized` 时，
   才允许发布 GitHub Release assets。
7. `post-release-summary` 或等价 summary 输出 release asset URL、checksums、CI run、release run、
   attestation/provenance、rollback summary、withdrawal policy 和 replacement policy。

当前 placeholder release 不执行第 1 步及之后的任何真实 release notes、rollback summary、
GitHub Release 或 upload 步骤。

## Rejection Rules

真实 release notes/rollback gate 必须拒绝以下情况：

- `package-linux`、`publish-github-release`、`post-release-summary` 或等价 release notes/publish job
  在本文档和相关 release gates 完成前被定义。
- release notes 缺少 version、artifact、checksums、CI、release、install、signing、rollback、
  withdrawal 或 replacement 字段组。
- release notes 与 manifest、job outputs、release summary、checksum sidecar 或 attestation/provenance
  状态不一致。
- rollback scope、trigger、steps、replacement version 或 owner 缺失。
- withdrawal policy 允许覆盖同名 tag、覆盖同名 asset 或静默删除公开 asset。
- replacement policy 不要求新 version tag。
- publish job 在 `package_release_notes_status=published` 和 `package_rollback_status=summarized`
  前上传 GitHub Release asset。
- release notes 或 summary 输出 secret、token、证书私钥、runner 本地绝对路径、API response 原文、
  私有人工身份信息或未公开安全公告细节。

拒绝时 release workflow 必须失败，并且不得上传 workflow artifact 或 GitHub Release asset。

## Placeholder 行为

当前 release workflow 只能：

- 检查本文档存在和标题。
- 在 `linux-artifact-readiness`、`release-placeholder` 和 release summary 中输出 release
  notes/rollback policy binding 合同。
- 标记 `linux-package-release-notes-rollback-policy-contract=present`。
- 标记 `linux-package-release-notes-policy=required-before-publish`。
- 标记 `linux-package-release-notes-status=blocked-not-generated`。
- 标记 `linux-package-rollback-status=blocked-not-summarized`。
- 标记 `linux-package-withdrawal-policy=withdrawal-not-overwrite`。
- 标记 `linux-package-publish-without-rollback=blocked`。
- 标记 `package-linux=not-defined`、`publish-github-release=not-defined` 和
  `post-release-summary=not-defined` 或等价 blocked 状态。
- 继续不定义 `package-linux`、`publish-github-release` 或 `post-release-summary`。

该 placeholder 只证明 release notes/rollback policy binding 已被记录，不证明当前 release 已经
可以发布 Linux artifact。

## 验收条件

- 本文档保持在 README、ROADMAP、Release Strategy、Linux artifact 设计、Linux package manifest
  设计、Linux package publish/upload boundary contract、Linux package checksum manifest contract、
  Linux package signing/attestation policy binding contract、Linux CLI artifact 安装/回滚设计、
  Linux package publish eligibility aggregate contract、Release CI success source contract、
  Linux package runner/toolchain/target contract、Linux package
  archive staging contract、Linux artifact license/NOTICE confirmation source contract 和 CI policy 中可发现。
- `.github/workflows/ci.yml` governance 检查本文档存在和标题。
- `.github/workflows/release.yml` 的 `linux-artifact-readiness` 检查本文档存在、标题和
  release placeholder/summary 输出字段。
- release placeholder 和 release summary 输出 release notes policy/status、required fields、
  rollback policy/status/scope/trigger/steps/replacement/owner、withdrawal policy、replacement policy
  和 blocked status。
- 不生成 artifact、不定义 `package-linux`、不定义 `publish-github-release`、不定义
  `post-release-summary`、不上传 workflow artifact、不上传 release asset、不在本机执行测试、
  构建、打包或发布。

## 后续工作

- 在 license/NOTICE 人工确认完成前，继续保持 pending marker 并阻止 Linux artifact。
- Linux package publish eligibility aggregate contract 已定义；下一步可以补充 Linux package
  license/NOTICE confirmed-state transition validation contract，仍不生成 artifact。
