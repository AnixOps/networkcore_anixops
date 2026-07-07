# Linux Package Publish Eligibility Execution Validation Contract

本文定义首个 Linux artifact 在 release notes/rollback execution 完成后，未来
publish eligibility gate 真正执行时必须满足的验证合同。当前仍是 placeholder；本文只固定输入来源、
eligible 字段、required gates、失败边界和当前 blocked 状态，不定义 `package-linux`、
`attest-linux`、`publish-eligibility-gate`、`publish-github-release`、`post-release-summary`
或等价 publish job，不创建 GitHub Release 或上传 release asset。

评估时间：2026-07-07。

## 目标

- 固定 publish eligibility execution 只能在 release notes/rollback execution、attestation/provenance、
  workflow artifact bundle、manifest、checksum 和 release CI source 全部可验证后运行。
- 明确 `package_publish_eligibility_status=eligible` 前必须校验的 required gates 和字段。
- 拒绝缺失 gate、blocked gate、未知状态、与 manifest/release summary 不一致或试图绕过
  publish/upload boundary 的 release。
- 在当前 placeholder 阶段继续阻止 `publish-github-release`、GitHub Release、workflow artifact 和
  release asset。

## 非目标

- 不实现 `package-linux`、`attest-linux`、`publish-eligibility-gate`、`publish-github-release`、
  `post-release-summary` 或等价 job。
- 不创建 archive、checksum、manifest、workflow artifact、attestation、release notes、GitHub Release
  或 release asset。
- 不调用 GitHub Releases API、`gh release create`、third-party release action、upload-release-asset
  API 或 `actions/upload-artifact`。
- 不完成 license/NOTICE 人工确认，也不把 pending 状态伪装成 eligible。
- 不把 GitHub token、OIDC token、API response 原文、runner 本地绝对路径、secret、证书私钥、用户配置、
  人工身份私有信息或未公开安全公告细节写入 manifest、release notes、eligibility summary 或
  Step Summary。

## Source Of Truth

首个 Linux publish eligibility execution 输入必须来自本文档、
[Linux Package Publish Eligibility Aggregate Contract](linux-package-publish-eligibility-aggregate-contract.md)、
[Linux Package Release Notes Rollback Execution Validation Contract](linux-package-release-notes-rollback-execution-validation-contract.md)、
[Linux Package Artifact Attestation Execution Validation Contract](linux-package-artifact-attestation-execution-validation-contract.md)、
[Linux Package Workflow Artifact Bundle Upload Validation Contract](linux-package-workflow-artifact-bundle-upload-validation-contract.md)、
[Linux Package Artifact Manifest Checksum Validation Contract](linux-package-artifact-manifest-checksum-validation-contract.md)、
[Linux Package Artifact Manifest Generation Validation Contract](linux-package-artifact-manifest-generation-validation-contract.md)、
[Linux Package Artifact Checksum Execution Validation Contract](linux-package-artifact-checksum-execution-validation-contract.md)、
[Linux Package Artifact Archive Creation Validation Contract](linux-package-artifact-archive-creation-validation-contract.md)、
[Linux Package Artifact Staging File Validation Contract](linux-package-artifact-staging-file-validation-contract.md)、
[Linux Package Artifact Build Command Validation Contract](linux-package-artifact-build-command-validation-contract.md)、
[Linux Package Artifact Job Preflight Validation Contract](linux-package-artifact-job-preflight-validation-contract.md)、
[Linux Package Release CI Gate Activation Validation Contract](linux-package-release-ci-gate-activation-validation-contract.md)、
[Release CI Gate Execution Validation Contract](release-ci-gate-execution-validation-contract.md)、
[Release CI Gate API Implementation Plan](release-ci-gate-api-implementation-plan.md)、
[Release CI Success Source Contract](release-ci-success-source-contract.md)、
[Linux Package License Notice Transition Validation Contract](linux-package-license-notice-transition-validation-contract.md)、
[Linux Package Publish Upload Boundary Contract](linux-package-publish-upload-boundary-contract.md)、
[Linux Package Signing Attestation Policy Binding Contract](linux-package-signing-attestation-policy-binding-contract.md)、
[Linux Package Release Notes Rollback Policy Binding Contract](linux-package-release-notes-rollback-policy-binding-contract.md)、
`docs/manual-intervention.md` 和 release workflow 中的显式常量。不得由 maintainer 在
`workflow_dispatch` 中手动输入 eligible 状态、gate 状态、artifact path、release URL 或 release asset
eligibility 来绕过门禁。

当前 placeholder 固定为：

| 字段 | 值 |
| --- | --- |
| `package_publish_eligibility_execution_contract` | `present` |
| `package_publish_eligibility_execution_status` | `blocked-placeholder` |
| `package_publish_eligibility_execution_source` | `linux-artifact-readiness` |
| `package_publish_eligibility_execution_current_mode` | `contract-only-no-eligibility-execution` |
| `package_publish_eligibility_execution_required_job` | `publish-eligibility-gate` |
| `package_publish_eligibility_execution_job_status` | `not-defined` |
| `package_publish_eligibility_execution_upstream_job` | `post-release-summary` |
| `package_publish_eligibility_execution_upstream_status` | `not-defined` |
| `package_publish_eligibility_execution_aggregate_contract` | `present` |
| `package_publish_eligibility_execution_aggregate_status` | `blocked` |
| `package_publish_eligibility_execution_required_gates` | `license_notice,ci,runner_toolchain,archive_staging,checksum_manifest,artifact_manifest,publish_upload,signing_attestation,release_notes_rollback` |
| `package_publish_eligibility_execution_required_fields` | `status,reason,required_gates,license_notice,ci,runner_toolchain,archive_staging,checksum_manifest,artifact_manifest,publish_upload,signing_attestation,release_notes_rollback,package_linux,workflow_artifact,release_asset,publish_github_release,post_release_summary` |
| `package_publish_eligibility_execution_eligible_status_field` | `package_publish_eligibility_status` |
| `package_publish_eligibility_execution_eligible_value` | `eligible` |
| `package_publish_eligibility_execution_current_eligible_value` | `blocked` |
| `package_publish_eligibility_execution_blocking_reason` | `license-notice-pending-and-artifact-jobs-not-defined` |
| `package_publish_eligibility_execution_missing_gate` | `blocked` |
| `package_publish_eligibility_execution_unknown_gate` | `blocked` |
| `package_publish_eligibility_execution_publish_without_eligible` | `blocked` |
| `package_publish_eligibility_execution_workflow_artifact` | `blocked` |
| `package_publish_eligibility_execution_release_asset` | `blocked` |
| `package_publish_eligibility_execution_release_creation` | `blocked` |
| `package_publish_eligibility_execution_publish_job` | `publish-github-release` |
| `package_publish_eligibility_execution_publish_job_status` | `not-defined` |
| `package_publish_eligibility_execution_next_action` | `license-notice-and-artifact-gates-before-publish-eligibility` |

`blocked-placeholder` 表示 release workflow 已记录 future publish eligibility execution 的验证要求，
但当前 release 仍不得执行 publish eligibility gate、创建 GitHub Release、定义 publish jobs 或上传任何
artifact。

## Future Publish Eligibility Execution

未来真实 publish eligibility execution gate 必须在 release notes/rollback execution 完成且所有 required
gate 的机器状态可验证后运行。该 gate 可以使用保留的 `publish-eligibility-gate` job 名称，或等价的
pre-publish step；但任何实现都必须在 `publish-github-release` 上传 asset 前完成 eligibility 校验。

future job 边界：

```yaml
publish-eligibility-gate:
  needs:
    - post-release-summary
  steps:
    - name: Validate Linux publish eligibility
      run: |
        # Future implementation only. Current workflow must not define this job.
        # Read same-run job outputs, manifest, checksums, CI source, attestation,
        # release notes, rollback summary and manual license/NOTICE status.
        # Emit package_publish_eligibility_status=eligible only when every gate is verified.
```

字段规则：

| 字段组 | 要求 |
| --- | --- |
| status | 只有所有 required gates 可验证通过时才允许 `eligible` |
| reason | blocked 时必须输出稳定 blocking reason；eligible 时必须为空或 `none` |
| required_gates | 必须与 aggregate contract 和 manifest `publish_eligibility.required_gates` 完全一致 |
| license_notice | 必须为 `confirmed`，且来自独立人工确认提交和 `docs/manual-intervention.md` |
| ci | 必须来自同 repository、同 commit、`main` 分支成功 CI run |
| runner_toolchain | runner、toolchain、target、crate、binary 和 package format 必须匹配合同 |
| archive_staging | staging/output/top-level dir、archive path 和允许文件来源必须匹配合同 |
| checksum_manifest | archive checksum、manifest 和 manifest checksum 必须真实生成并交叉校验 |
| artifact_manifest | manifest JSON 必须包含 release、install、signing、rollback 和 publish eligibility 字段 |
| publish_upload | workflow artifact bundle、retention、required files 和 release asset set 必须匹配合同 |
| signing_attestation | GitHub artifact attestation/provenance 必须覆盖 required files |
| release_notes_rollback | release notes required fields、rollback required fields、withdrawal/replacement policy 必须通过 |
| package_linux | 必须是当前 release run 的 `package-linux` success result |
| workflow_artifact | 必须来自同一 release run，不能来自旧 run、人工上传或外部 artifact |
| release_asset | 只有 eligibility 为 `eligible` 后才允许进入 GitHub Release upload |
| publish_github_release | 只能依赖 eligible gate；不得自行重算或覆盖 gate 结果 |
| post_release_summary | 必须引用 publish eligibility 结果、release asset、CI run、release run 和 rollback summary |

## Failure Boundary

真实 publish eligibility execution gate 必须在以下情况失败，并且不得执行 release asset upload、
补发 workflow artifact 或替换既有 workflow artifact：

- 任一 required gate 缺失、为 `blocked-*`、`not-defined`、`unknown`，或与 source contract 不一致。
- `package_publish_eligibility_status=eligible` 但任一 gate 未提供可验证成功证据。
- release CI source 不是同 repository、同 commit、`main` 分支成功 CI run。
- license/NOTICE 状态不是 `confirmed`，或确认字段不满足 transition validation contract。
- archive、checksum、manifest、manifest checksum、workflow artifact bundle、attestation/provenance、
  release notes 或 rollback summary 与对应合同不一致。
- workflow artifact 来自旧 run、外部上传、人工复制、不同 commit 或不同 repository。
- release asset set 包含未在 publish/upload boundary 中声明的文件，或允许覆盖同名 tag/asset。
- publish job 在 eligibility status 不是 `eligible` 时创建 GitHub Release、上传 asset 或渲染公开
  release body。
- eligibility summary、manifest、release notes 或 Step Summary 输出 secret、token、证书私钥、runner
  本地绝对路径、API response 原文、私有人工身份信息或未公开安全公告细节。
- workflow 在本 gate 激活前定义 `publish-eligibility-gate`、`publish-github-release`，调用 GitHub
  Releases API、使用 release action、创建 GitHub Release 或上传 GitHub Release asset。

失败时 release workflow 必须失败在 publish eligibility gate 内或之前，不得创建 publish job 可消费的
release asset。

## Release Workflow 边界

当前 placeholder release 只能：

- 检查本文档存在和标题。
- 检查本文档包含 status、required gates、required fields、eligible status field、future execution、
  failure boundary 和 release asset blocked 边界。
- 检查 publish eligibility aggregate contract、release notes/rollback execution validation contract、
  artifact attestation execution validation contract 和 publish/upload boundary contract 可发现。
- 在 `linux-artifact-readiness`、release placeholder 和 release summary 中输出 publish eligibility
  execution validation contract。
- 标记 `linux-package-publish-eligibility-execution-contract=present`。
- 标记 `linux-package-publish-eligibility-execution-status=blocked-placeholder`。
- 标记 `linux-package-publish-eligibility-execution-required-job=publish-eligibility-gate`。
- 标记 `linux-package-publish-eligibility-execution-job-status=not-defined`。
- 标记 `linux-package-publish-eligibility-execution-upstream-job=post-release-summary`。
- 标记 `linux-package-publish-eligibility-execution-upstream-status=not-defined`。
- 标记 `linux-package-publish-eligibility-execution-aggregate-status=blocked`。
- 标记 `linux-package-publish-eligibility-execution-required-gates=license_notice,ci,runner_toolchain,archive_staging,checksum_manifest,artifact_manifest,publish_upload,signing_attestation,release_notes_rollback`。
- 标记 `linux-package-publish-eligibility-execution-required-fields=status,reason,required_gates,license_notice,ci,runner_toolchain,archive_staging,checksum_manifest,artifact_manifest,publish_upload,signing_attestation,release_notes_rollback,package_linux,workflow_artifact,release_asset,publish_github_release,post_release_summary`。
- 标记 `linux-package-publish-eligibility-execution-eligible-status-field=package_publish_eligibility_status`。
- 标记 `linux-package-publish-eligibility-execution-current-eligible-value=blocked`。
- 标记 `linux-package-publish-eligibility-execution-missing-gate=blocked`。
- 标记 `linux-package-publish-eligibility-execution-unknown-gate=blocked`。
- 标记 `linux-package-publish-eligibility-execution-publish-without-eligible=blocked`。
- 标记 `linux-package-publish-eligibility-execution-workflow-artifact=blocked`。
- 标记 `linux-package-publish-eligibility-execution-release-asset=blocked`。
- 标记 `linux-package-publish-eligibility-execution-release-creation=blocked`。
- 标记 `linux-package-publish-eligibility-execution-publish-job=publish-github-release`。
- 标记 `linux-package-publish-eligibility-execution-publish-job-status=not-defined`。
- 标记 `linux-package-publish-eligibility-execution-next-action=license-notice-and-artifact-gates-before-publish-eligibility`。
- 继续不定义 `package-linux`、`attest-linux`、`publish-eligibility-gate`、
  `publish-github-release`、`post-release-summary` 或等价 publish job。
- 继续不调用 GitHub Releases API、`gh release create`、release action、upload-release-asset API
  或 `actions/upload-artifact`。

## 验收条件

- 本文档保持在 README、ROADMAP、Release Strategy、Linux package publish eligibility aggregate
  contract、release CI gate API implementation plan、Linux package release notes/rollback execution validation contract、Linux package
  artifact attestation execution validation contract、Linux package publish/upload boundary contract、
  Linux package artifact manifest design、Linux CLI artifact 安装/回滚设计和 CI policy 中可发现。
- `.github/workflows/ci.yml` governance 检查本文档存在、标题、status、required gates、required
  fields、eligible status field、future execution 和 release workflow placeholder 输出字段。
- `.github/workflows/release.yml` 的 `linux-artifact-readiness` 检查本文档存在、标题、placeholder
  fields、required gates、required fields、future execution、failure boundary、forbidden release
  action/API guards 和 `publish-eligibility-gate` 未定义状态。
- release placeholder 和 release summary 输出 publish eligibility execution status、required job、
  upstream release notes/rollback job/status、aggregate status、required gates、required fields、
  eligible status field、publish blocking、release asset blocked、publish job not-defined 和 next action。
- 当前不生成 artifact、不定义 `package-linux`、不定义 `attest-linux`、不定义
  `publish-eligibility-gate`、不定义 `publish-github-release`、不定义 `post-release-summary`、
  不创建 GitHub Release、不上传 workflow artifact、不上传 release asset、不在本机执行测试、构建、
  打包或发布。

## 后续工作

- 在 license/NOTICE 人工确认、artifact job preflight、build command、
  staging file、archive creation、checksum execution、manifest generation、manifest checksum、
  workflow artifact bundle upload、attestation execution、release notes/rollback execution 和 publish
  eligibility execution gates 激活前，继续保持 `package-linux`、`attest-linux`、
  `publish-eligibility-gate`、`publish-github-release` 和 `post-release-summary` 未定义。
- release CI gate execution validation contract 和 release CI gate API implementation 已激活；下一步必须完成 license/NOTICE 和 artifact gates，并继续阻止 `package-linux` 和 GitHub Release asset。
