# Linux Package Release Notes Rollback Execution Validation Contract

本文定义首个 Linux artifact 在 attestation/provenance 完成后，未来 release
notes、rollback summary、withdrawal policy 和 replacement policy 进入 publish gate 前必须满足的
执行验证合同。当前仍是 placeholder；本文只固定输入来源、required fields、失败边界和当前 blocked
状态，不定义 `package-linux`、`attest-linux`、`publish-github-release`、`post-release-summary`
或等价 release notes/publish job，不生成 GitHub Release 或上传 release asset。

评估时间：2026-07-07。

## 目标

- 固定 release notes/rollback execution 只能在 archive、checksum、manifest、workflow artifact bundle
  和 GitHub artifact attestation/provenance 全部完成后运行。
- 明确 release notes required fields、rollback required fields、withdrawal/replacement policy 的
  机器可读校验边界。
- 拒绝缺失 rollback summary、缺失 withdrawal/replacement policy、与 manifest/attestation 不一致或
  试图绕过 publish eligibility aggregate 的 release。
- 在当前 placeholder 阶段继续阻止 GitHub Release、release asset 和 post-release summary。

## 非目标

- 不实现 `package-linux`、`attest-linux`、`publish-github-release`、`post-release-summary`
  或等价 job。
- 不创建 archive、checksum、manifest、workflow artifact、attestation、GitHub Release、release notes
  或 release asset。
- 不调用 GitHub Releases API、`gh release create`、third-party release action 或 upload-release-asset API。
- 不完成 license/NOTICE 人工确认。
- 不把 GitHub token、OIDC token、API response 原文、runner 本地绝对路径、secret、证书私钥、用户配置、
  人工身份私有信息或未公开安全公告细节写入 manifest、release notes、rollback summary 或 Step Summary。

## Source Of Truth

首个 Linux release notes/rollback execution 输入必须来自本文档、
[Linux Package Release Notes Rollback Policy Binding Contract](linux-package-release-notes-rollback-policy-binding-contract.md)、
[Linux Package Artifact Attestation Execution Validation Contract](linux-package-artifact-attestation-execution-validation-contract.md)、
[Linux Package Signing Attestation Policy Binding Contract](linux-package-signing-attestation-policy-binding-contract.md)、
[Linux Package Workflow Artifact Bundle Upload Validation Contract](linux-package-workflow-artifact-bundle-upload-validation-contract.md)、
[Linux Package Artifact Manifest Design](linux-package-artifact-manifest.md)、
[Linux Package Publish Upload Boundary Contract](linux-package-publish-upload-boundary-contract.md)、
[Linux Package Publish Eligibility Aggregate Contract](linux-package-publish-eligibility-aggregate-contract.md)、
[Linux Package License Notice Transition Validation Contract](linux-package-license-notice-transition-validation-contract.md)、
[Release CI Success Source Contract](release-ci-success-source-contract.md)、`CHANGELOG.md` 和 release workflow
中的显式常量。不得由 maintainer 在 `workflow_dispatch` 中手动输入 release notes status、rollback
status、withdrawal policy、replacement version 或 release asset eligibility 来绕过门禁。

当前 placeholder 固定为：

| 字段 | 值 |
| --- | --- |
| `package_release_notes_rollback_execution_contract` | `present` |
| `package_release_notes_rollback_execution_status` | `blocked-placeholder` |
| `package_release_notes_rollback_execution_source` | `linux-artifact-readiness` |
| `package_release_notes_rollback_execution_current_mode` | `contract-only-no-release-notes` |
| `package_release_notes_rollback_execution_required_job` | `post-release-summary` |
| `package_release_notes_rollback_execution_job_status` | `not-defined` |
| `package_release_notes_rollback_execution_upstream_job` | `attest-linux` |
| `package_release_notes_rollback_execution_upstream_status` | `not-defined` |
| `package_release_notes_rollback_execution_attestation_status` | `blocked-not-attested` |
| `package_release_notes_rollback_execution_provenance_status` | `blocked-not-generated` |
| `package_release_notes_rollback_execution_release_notes_source` | `CHANGELOG.md-and-release-summary` |
| `package_release_notes_rollback_execution_release_notes_status` | `blocked-not-generated` |
| `package_release_notes_rollback_execution_release_notes_required_fields` | `version,artifact,checksums,ci,release,install,signing,rollback,withdrawal,replacement` |
| `package_release_notes_rollback_execution_release_body_status` | `blocked-not-rendered` |
| `package_release_notes_rollback_execution_rollback_policy` | `manual-extract-version-switch` |
| `package_release_notes_rollback_execution_rollback_status` | `blocked-not-summarized` |
| `package_release_notes_rollback_execution_rollback_required_fields` | `rollback_scope,rollback_trigger,rollback_steps,replacement_version,rollback_owner` |
| `package_release_notes_rollback_execution_withdrawal_policy` | `withdrawal-not-overwrite` |
| `package_release_notes_rollback_execution_replacement_policy` | `new-version-tag-required` |
| `package_release_notes_rollback_execution_missing_rollback` | `blocked` |
| `package_release_notes_rollback_execution_publish_without_release_notes` | `blocked` |
| `package_release_notes_rollback_execution_publish_without_rollback` | `blocked` |
| `package_release_notes_rollback_execution_release_asset` | `blocked` |
| `package_release_notes_rollback_execution_publish_job` | `publish-github-release` |
| `package_release_notes_rollback_execution_publish_job_status` | `not-defined` |
| `package_release_notes_rollback_execution_next_action` | `publish-eligibility-execution-after-release-notes-rollback` |

`blocked-placeholder` 表示 release workflow 已记录 future release notes/rollback execution 的验证要求，
但当前 release 仍不得生成 release notes、创建 GitHub Release、定义 publish/post-release jobs 或上传
release asset。

## Future Release Notes Rollback Execution

未来真实 release notes/rollback execution gate 必须在 `attest-linux` 完成且 attestation/provenance
状态可验证后运行。该 gate 可以使用保留的 `post-release-summary` job 名称，或等价的 release
notes/rollback gate；但任何实现都必须在 `publish-github-release` 上传 asset 前完成 required field
校验。

future job 边界：

```yaml
post-release-summary:
  needs:
    - attest-linux
  steps:
    - name: Validate Linux release notes and rollback summary
      run: |
        # Future implementation only. Current workflow must not define this job.
        # Validate manifest, checksums, CI source, release source, attestation,
        # install model, rollback, withdrawal and replacement fields before publish.
```

字段规则：

| 字段组 | 要求 |
| --- | --- |
| upstream | 必须读取同一 release run 的 `attest-linux` result 和 provenance reference |
| manifest | 必须读取 `networkcore-linux-${version}-${target}.manifest.json` 和 manifest checksum |
| checksums | 必须包含 archive sha256 和 manifest sha256 |
| ci | 必须引用同 repository、同 commit、`main` 分支成功 CI run |
| release | 必须引用当前 release run URL、version、ref 和 commit SHA |
| install | 必须声明 manual-extract、无 service install、无 capability grant、无 certificate install |
| signing | 必须声明 unsigned-no-detached-signature、GitHub artifact attestation required 和 provenance reference |
| rollback | 必须包含 scope、trigger、steps、replacement version 和 owner |
| withdrawal | 必须是 `withdrawal-not-overwrite`，不得允许覆盖同名 tag 或同名 asset |
| replacement | 必须是 `new-version-tag-required`，不得用覆盖旧 asset 代替新版本 |

## Failure Boundary

真实 release notes/rollback execution gate 必须在以下情况失败，并且不得执行 release asset upload：

- `attest-linux` 未完成、未依赖当前 release run 的 `package-linux`，或 attestation/provenance 不可验证。
- release notes 缺少 version、artifact、checksums、CI、release、install、signing、rollback、
  withdrawal 或 replacement 字段组。
- rollback scope、trigger、steps、replacement version 或 owner 任一缺失。
- release notes 与 manifest、checksum sidecar、release summary、CI source、attestation/provenance 或
  publish/upload boundary 字段不一致。
- withdrawal policy 允许覆盖同名 tag、覆盖同名 asset、静默删除公开 asset 或隐瞒受影响版本。
- replacement policy 不要求新 version tag。
- release body、rollback summary、manifest 或 Step Summary 输出 secret、token、证书私钥、runner
  本地绝对路径、API response 原文、私有人工身份信息或未公开安全公告细节。
- workflow 在本 gate 激活前定义 `post-release-summary`、调用 GitHub Releases API、使用 release
  action、创建 GitHub Release 或上传 GitHub Release asset。
- publish job 在 release notes status 可验证、rollback status summarized 且 publish eligibility
  aggregate 变为 eligible 前上传 GitHub Release asset。

失败时 release workflow 必须失败在 release notes/rollback gate 内或之前，不得创建 publish job 可消费的
release asset。

## Release Workflow 边界

当前 placeholder release 只能：

- 检查本文档存在和标题。
- 检查本文档包含 current placeholder fields、required fields、rollback fields、withdrawal/replacement
  policy、future execution、failure boundary 和 release asset blocked 边界。
- 检查 release notes/rollback policy binding contract、artifact attestation execution validation contract
  和 publish eligibility aggregate contract 可发现。
- 在 `linux-artifact-readiness`、release placeholder 和 release summary 中输出 release notes/rollback
  execution validation contract。
- 标记 `linux-package-release-notes-rollback-execution-contract=present`。
- 标记 `linux-package-release-notes-rollback-execution-status=blocked-placeholder`。
- 标记 `linux-package-release-notes-rollback-execution-required-job=post-release-summary`。
- 标记 `linux-package-release-notes-rollback-execution-job-status=not-defined`。
- 标记 `linux-package-release-notes-rollback-execution-upstream-job=attest-linux`。
- 标记 `linux-package-release-notes-rollback-execution-upstream-status=not-defined`。
- 标记 `linux-package-release-notes-rollback-execution-attestation-status=blocked-not-attested`。
- 标记 `linux-package-release-notes-rollback-execution-provenance-status=blocked-not-generated`。
- 标记 `linux-package-release-notes-rollback-execution-release-notes-source=CHANGELOG.md-and-release-summary`。
- 标记 `linux-package-release-notes-rollback-execution-release-notes-status=blocked-not-generated`。
- 标记 `linux-package-release-notes-rollback-execution-release-notes-required-fields=version,artifact,checksums,ci,release,install,signing,rollback,withdrawal,replacement`。
- 标记 `linux-package-release-notes-rollback-execution-release-body-status=blocked-not-rendered`。
- 标记 `linux-package-release-notes-rollback-execution-rollback-policy=manual-extract-version-switch`。
- 标记 `linux-package-release-notes-rollback-execution-rollback-status=blocked-not-summarized`。
- 标记 `linux-package-release-notes-rollback-execution-rollback-required-fields=rollback_scope,rollback_trigger,rollback_steps,replacement_version,rollback_owner`。
- 标记 `linux-package-release-notes-rollback-execution-withdrawal-policy=withdrawal-not-overwrite`。
- 标记 `linux-package-release-notes-rollback-execution-replacement-policy=new-version-tag-required`。
- 标记 `linux-package-release-notes-rollback-execution-missing-rollback=blocked`。
- 标记 `linux-package-release-notes-rollback-execution-publish-without-release-notes=blocked`。
- 标记 `linux-package-release-notes-rollback-execution-publish-without-rollback=blocked`。
- 标记 `linux-package-release-notes-rollback-execution-release-asset=blocked`。
- 标记 `linux-package-release-notes-rollback-execution-publish-job=publish-github-release`。
- 标记 `linux-package-release-notes-rollback-execution-publish-job-status=not-defined`。
- 标记 `linux-package-release-notes-rollback-execution-next-action=publish-eligibility-execution-after-release-notes-rollback`。
- 继续不定义 `package-linux`、`attest-linux`、`publish-github-release`、`post-release-summary`
  或等价 release notes/publish job。
- 继续不调用 GitHub Releases API、`gh release create`、release action 或 upload-release-asset API。

## 验收条件

- 本文档保持在 README、ROADMAP、Release Strategy、Linux package release notes/rollback policy binding
  contract、Linux package artifact attestation execution validation contract、Linux package publish eligibility
  aggregate contract、Linux package artifact manifest design、Linux CLI artifact 安装/回滚设计和 CI policy
  中可发现。
- `.github/workflows/ci.yml` governance 检查本文档存在、标题、status、release notes required fields、
  rollback required fields、withdrawal/replacement policy、future execution 和 release workflow
  placeholder 输出字段。
- `.github/workflows/release.yml` 的 `linux-artifact-readiness` 检查本文档存在、标题、placeholder
  fields、required fields、rollback fields、withdrawal/replacement policy、future execution、failure
  boundary、forbidden release action/API guards 和 `post-release-summary` 未定义状态。
- release placeholder 和 release summary 输出 release notes/rollback execution status、required job、
  upstream attestation job/status、release notes required fields、rollback required fields、
  withdrawal/replacement policy、publish blocking、release asset blocked、publish job not-defined 和 next action。
- 当前不生成 artifact、不定义 `package-linux`、不定义 `attest-linux`、不定义
  `publish-github-release`、不定义 `post-release-summary`、不创建 GitHub Release、不上传 workflow
  artifact、不上传 release asset、不在本机执行测试、构建、打包或发布。

## 后续工作

- 在 license/NOTICE 人工确认、release CI gate activation、artifact job preflight、build command、
  staging file、archive creation、checksum execution、manifest generation、manifest checksum、
  workflow artifact bundle upload、attestation execution 和 release notes/rollback execution gates 激活前，
  继续保持 `package-linux`、`attest-linux`、`publish-github-release` 和 `post-release-summary` 未定义。
- 下一步可以补充 Linux package publish eligibility execution validation contract，明确 release notes/rollback
  execution 完成后如何聚合全部 gate 并继续阻止 GitHub Release asset。
