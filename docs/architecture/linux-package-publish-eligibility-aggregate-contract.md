# Linux Package Publish Eligibility Aggregate Contract

本文定义首个真实 Linux `package-linux` artifact 进入 publish/upload 前必须满足的
综合发布资格聚合合同。它汇总 license/NOTICE、同 commit CI、runner/toolchain、
archive staging、checksum/manifest、artifact manifest、publish/upload、signing/attestation
以及 release notes/rollback gates 的 eligible/blocked 状态。当前仍为 placeholder 合同，
不定义 `package-linux` job、不上传 workflow artifact、不发布 GitHub Release asset。

评估时间：2026-07-07。

## 目标

- 给首个 Linux CLI tarball 的所有发布前置门禁提供一个机器可读的聚合状态。
- 明确当前 release placeholder 下哪些 gate 只是合同已存在，哪些 gate 仍处于 blocked。
- 防止后续只满足单个 gate 后误把 Linux artifact 判断为可发布。
- 在 license/NOTICE 人工确认、同 commit CI 自动读取、真实 packaging、attestation、
  release notes/rollback 和 publish job 完成前继续阻止真实 artifact。

## 非目标

- 不实现 `package-linux` job。
- 不实现 `publish-github-release`、`attest-linux`、`sign-linux`、`post-release-summary` 或等价 job。
- 不创建 archive、checksum、manifest、attestation、release notes、workflow artifact 或 release asset。
- 不把 GitHub token、API response 原文、runner 本地绝对路径、secret、证书私钥、用户配置、
  人工身份私有信息或安全公告草稿写入 manifest、release notes 或 Step Summary。

## Source Of Truth

首个真实 Linux publish eligibility 输入必须来自本文档、
[Linux Artifact License Notice Confirmation Design](linux-artifact-license-notice-confirmation.md)、
[Linux Package License Notice Transition Validation Contract](linux-package-license-notice-transition-validation-contract.md)、
[Release CI Success Source Contract](release-ci-success-source-contract.md)、
[Linux Package Release CI Gate Activation Validation Contract](linux-package-release-ci-gate-activation-validation-contract.md)、
[Linux Package Artifact Job Preflight Validation Contract](linux-package-artifact-job-preflight-validation-contract.md)、
[Linux Package Runner Toolchain Target Contract](linux-package-runner-toolchain-target-contract.md)、
[Linux Package Archive Staging Contract](linux-package-archive-staging-contract.md)、
[Linux Package Checksum Manifest Contract](linux-package-checksum-manifest-contract.md)、
[Linux Package Artifact Manifest Design](linux-package-artifact-manifest.md)、
[Linux Package Publish Upload Boundary Contract](linux-package-publish-upload-boundary-contract.md)、
[Linux Package Signing Attestation Policy Binding Contract](linux-package-signing-attestation-policy-binding-contract.md)、
[Linux Package Artifact Attestation Execution Validation Contract](linux-package-artifact-attestation-execution-validation-contract.md)、
[Linux Package Release Notes Rollback Policy Binding Contract](linux-package-release-notes-rollback-policy-binding-contract.md)
和 release workflow 中的显式常量。不得由 maintainer 在 `workflow_dispatch` 中手动输入
eligible 状态、CI URL、artifact path、attestation 状态、rollback 状态或 release asset eligibility
来绕过门禁。

当前首个 Linux publish eligibility aggregate 固定为：

| 字段 | 值 |
| --- | --- |
| `package_publish_eligibility_aggregate_contract` | `present` |
| `package_publish_eligibility_status` | `blocked` |
| `package_publish_eligibility_reason` | `license-notice-pending-and-artifact-jobs-not-defined` |
| `package_publish_eligibility_required_gates` | `license_notice,ci,runner_toolchain,archive_staging,checksum_manifest,artifact_manifest,publish_upload,signing_attestation,release_notes_rollback` |
| `package_publish_eligibility_license_notice` | `blocked-pending` |
| `package_publish_eligibility_ci` | `blocked-placeholder` |
| `package_publish_eligibility_runner_toolchain` | `present` |
| `package_publish_eligibility_archive_staging` | `present` |
| `package_publish_eligibility_checksum_manifest` | `present` |
| `package_publish_eligibility_artifact_manifest` | `present` |
| `package_publish_eligibility_publish_upload` | `blocked-placeholder` |
| `package_publish_eligibility_signing_attestation` | `blocked-not-attested` |
| `package_publish_eligibility_release_notes_rollback` | `blocked-not-generated` |
| `package_publish_eligibility_package_linux` | `not-defined` |
| `package_publish_eligibility_workflow_artifact` | `blocked` |
| `package_publish_eligibility_release_asset` | `blocked` |
| `package_publish_eligibility_publish_github_release` | `not-defined` |
| `package_publish_eligibility_post_release_summary` | `not-defined` |
| `package_publish_eligibility_next_action` | `license-notice-confirmation-required` |

`present` 表示合同已存在且可被后续真实 job 读取；不表示该 gate 已经完成真实发布前置条件。
只有所有 required gates 都进入可验证的 eligible 状态，`package_publish_eligibility_status`
才能从 `blocked` 变为 `eligible`。

## Gate 聚合规则

真实 publish eligibility gate 后续必须按以下规则判断：

| Gate | Eligible 条件 | 当前状态 |
| --- | --- | --- |
| `license_notice` | `docs/manual-intervention.md` 中 license/NOTICE 状态为 `confirmed`，且 artifact 文件清单可验证 | `blocked-pending` |
| `ci` | release workflow 按 release CI gate activation validation contract 自动读取同 repository、同 commit、`main` 分支成功 CI run | `blocked-placeholder` |
| `runner_toolchain` | runner、toolchain、target triple、crate、binary 和 format 与合同一致 | `present` |
| `archive_staging` | staging/output/top-level dir、archive path 和允许文件来源与合同一致 | `present` |
| `checksum_manifest` | archive checksum、manifest、manifest checksum 和交叉校验字段真实生成并一致 | `present` |
| `artifact_manifest` | manifest JSON 含所有必需 metadata、license、signing、release notes 和 rollback 字段 | `present` |
| `publish_upload` | workflow artifact bundle 与 release asset set 符合同一 run、required files 和不可覆盖策略 | `blocked-placeholder` |
| `signing_attestation` | GitHub artifact attestation/provenance 对 required files 可验证 | `blocked-not-attested` |
| `release_notes_rollback` | release notes 已发布，rollback summary、withdrawal 和 replacement policy 已总结 | `blocked-not-generated` |

当前 placeholder 中，任何 blocked gate 都会让 aggregate status 保持 `blocked`。真实 publish
job 不得把单个 `present` gate 当作完整 release 资格。

## Manifest Binding

真实 `package-linux` manifest 必须包含 publish eligibility object，并与 release workflow
outputs 完全一致。首个 Linux artifact 的最小发布前状态为：

```json
{
  "publish_eligibility": {
    "status": "eligible",
    "required_gates": [
      "license_notice",
      "ci",
      "runner_toolchain",
      "archive_staging",
      "checksum_manifest",
      "artifact_manifest",
      "publish_upload",
      "signing_attestation",
      "release_notes_rollback"
    ],
    "license_notice": "confirmed",
    "ci": "success",
    "runner_toolchain": "matched",
    "archive_staging": "matched",
    "checksum_manifest": "verified",
    "artifact_manifest": "verified",
    "publish_upload": "ready",
    "signing_attestation": "attested",
    "release_notes_rollback": "published-and-summarized"
  }
}
```

当前 placeholder 不生成 manifest，只能输出 blocked 状态：

```json
{
  "publish_eligibility": {
    "status": "blocked",
    "reason": "license-notice-pending-and-artifact-jobs-not-defined",
    "license_notice": "blocked-pending",
    "ci": "blocked-placeholder",
    "publish_upload": "blocked-placeholder",
    "signing_attestation": "blocked-not-attested",
    "release_notes_rollback": "blocked-not-generated",
    "package_linux": "not-defined",
    "workflow_artifact": "blocked",
    "release_asset": "blocked"
  }
}
```

## Job Boundary

真实 release workflow 后续必须按以下顺序处理 Linux publish eligibility：

1. `release-policy` 确认 version 与触发来源一致。
2. `release-ci-gate` 按 [Linux Package Release CI Gate Activation Validation Contract](linux-package-release-ci-gate-activation-validation-contract.md) 自动读取同 commit 成功 CI run。
3. `linux-artifact-readiness` 确认源码、设计和人工事项状态。
4. `package-linux` 生成 archive、archive checksum、manifest 和 manifest checksum。
5. `package-linux` 上传同一 release run 的 workflow artifact bundle。
6. `attest-linux` 按 [Linux Package Artifact Attestation Execution Validation Contract](linux-package-artifact-attestation-execution-validation-contract.md) 对 archive、checksum、manifest 和 manifest checksum 生成 attestation/provenance。
7. release notes/rollback gate 输出 release notes、rollback、withdrawal 和 replacement 字段。
8. publish eligibility aggregate gate 读取以上所有 job outputs、manifest、manual marker 和 summary 字段。
9. 只有 `package_publish_eligibility_status=eligible` 时，`publish-github-release` 才能上传 GitHub Release assets。
10. `post-release-summary` 输出 release asset URL、checksums、CI run、release run、attestation/provenance、
    rollback summary 和 aggregate eligibility 结果。

当前 placeholder release 不执行第 4 步及之后的任何真实 packaging、attestation、release notes、
aggregate eligibility publish gate 或 upload 步骤。

## Rejection Rules

真实 publish eligibility gate 必须拒绝以下情况：

- `package-linux`、`attest-linux`、`publish-github-release`、`post-release-summary` 或等价 publish job
  在本文档和相关 release gates 完成前被定义。
- 任一 required gate 缺失、状态未知或与 source contract 不一致。
- release CI source 不是同 repository、同 commit、`main` 分支成功 CI run。
- license/NOTICE 状态不是 `confirmed`。
- archive、checksum、manifest、manifest checksum、workflow artifact bundle 或 release asset set
  与对应合同不一致。
- attestation/provenance 未覆盖 required files。
- release notes 未发布，或 rollback、withdrawal、replacement 字段缺失。
- aggregate status 不是 `eligible` 时仍尝试上传 workflow artifact 或 GitHub Release asset。
- aggregate summary 或 manifest 输出 secret、token、证书私钥、runner 本地绝对路径、API response
  原文、私有人工身份信息或未公开安全公告细节。

拒绝时 release workflow 必须失败，并且不得上传 workflow artifact 或 GitHub Release asset。

## Placeholder 行为

当前 release workflow 只能：

- 检查本文档存在和标题。
- 在 `linux-artifact-readiness`、`release-placeholder` 和 release summary 中输出 publish
  eligibility aggregate 合同。
- 标记 `linux-package-publish-eligibility-aggregate-contract=present`。
- 标记 `linux-package-publish-eligibility-status=blocked`。
- 标记 `linux-package-publish-eligibility-license-notice=blocked-pending`。
- 标记 `linux-package-publish-eligibility-ci=blocked-placeholder`。
- 标记 `linux-package-publish-eligibility-release-asset=blocked`。
- 标记 `linux-package-publish-eligibility-next-action=license-notice-confirmation-required`。
- 继续不定义 `package-linux`、`attest-linux`、`sign-linux`、`publish-github-release` 或
  `post-release-summary`。

该 placeholder 只证明 publish eligibility aggregate 已被记录，不证明当前 release 已经可以
发布 Linux artifact。

## 验收条件

- 本文档保持在 README、ROADMAP、Release Strategy、Linux artifact 设计、Linux package manifest
  设计、Linux package publish/upload boundary contract、Linux package checksum manifest contract、
  Linux package signing/attestation policy binding contract、Linux package artifact attestation execution
  validation contract、Linux package release notes/rollback
  policy binding contract、Linux CLI artifact 安装/回滚设计、Release CI success source contract、
  Linux package release CI gate activation validation contract、Linux package artifact job preflight validation
  contract、Linux package runner/toolchain/target contract、Linux package archive staging contract、Linux artifact
  license/NOTICE confirmation source contract、Linux package license/NOTICE transition validation contract 和
  CI policy 中可发现。
- `.github/workflows/ci.yml` governance 检查本文档存在和标题。
- `.github/workflows/release.yml` 的 `linux-artifact-readiness` 检查本文档存在、标题和
  release placeholder/summary 输出字段。
- release placeholder 和 release summary 输出 aggregate status、blocking reason、required gates、
  per-gate eligible/blocked 状态、package/publish job not-defined 状态和 next action。
- 不生成 artifact、不定义 `package-linux`、不定义 `publish-github-release`、不定义
  `post-release-summary`、不上传 workflow artifact、不上传 release asset、不在本机执行测试、
  构建、打包或发布。

## 后续工作

- 在 license/NOTICE 人工确认完成前，继续保持 pending marker 并阻止 Linux artifact。
- Linux package license/NOTICE transition validation contract、Linux package release CI gate activation
  validation contract、Linux package artifact job preflight validation contract、Linux package artifact build
  command validation contract、Linux package artifact staging file validation contract、Linux package artifact
  archive creation validation contract 和 Linux package artifact checksum execution validation contract 已定义；
  Linux package artifact manifest generation validation contract、Linux package artifact manifest checksum validation contract、Linux package workflow artifact bundle upload validation contract 和 Linux package artifact attestation execution validation contract 已定义；下一步可以补充 Linux package release notes/rollback execution validation contract，仍不发布 release asset。
