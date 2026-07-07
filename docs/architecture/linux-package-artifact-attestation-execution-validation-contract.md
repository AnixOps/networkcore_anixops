# Linux Package Artifact Attestation Execution Validation Contract

本文定义首个 Linux workflow artifact bundle 上传完成后，未来 `attest-linux` job
生成 GitHub artifact attestation/provenance 前必须满足的验证合同。当前仍是 placeholder；
本文只固定 attestation 输入来源、subject 文件集合、权限要求、action 边界、provenance
状态和 release asset 继续阻断状态，不定义 `package-linux`、`attest-linux`、
`sign-linux`、`publish-github-release` 或 `post-release-summary` job。

评估时间：2026-07-07。

## 目标

- 固定 attestation 只能基于同一 release run workflow artifact bundle 中的 archive、
  archive checksum、manifest 和 manifest checksum 四个文件生成。
- 明确 future `attest-linux` 必须在 workflow artifact bundle upload 完成后执行。
- 固定 GitHub artifact attestation/provenance 所需的 action、subject path 模式和权限。
- 拒绝旧 run artifact、不同 commit artifact、外部 URL、runner cache、人工上传文件或
  `workflow_dispatch` 输入绕过 provenance gate。
- 在 attestation/provenance gate 未激活时继续阻止 GitHub Release asset upload。

## 非目标

- 不实现 `package-linux`、`attest-linux`、`sign-linux`、`publish-github-release`、
  `post-release-summary` 或等价 job。
- 不运行 `cargo build`、不创建 archive、不计算 checksum、不写 manifest、不上传 workflow artifact。
- 不调用 `actions/attest`，不启用 `id-token: write` 或 `attestations: write`。
- 不生成 GitHub artifact attestation、SBOM attestation、provenance bundle 或 release asset。
- 不完成 license/NOTICE 人工确认。
- 不启用 release CI gate 的 GitHub API 读取。
- 不把 GitHub token、OIDC token、API response 原文、runner 本地绝对路径、secret、证书私钥、
  用户配置或未公开安全公告细节写入 manifest、attestation subject、release notes 或 Step Summary。

## Source Of Truth

首个 Linux package artifact attestation execution 输入必须来自本文档、
[Linux Package Workflow Artifact Bundle Upload Validation Contract](linux-package-workflow-artifact-bundle-upload-validation-contract.md)、
[Linux Package Signing Attestation Policy Binding Contract](linux-package-signing-attestation-policy-binding-contract.md)、
[Linux Package Publish Upload Boundary Contract](linux-package-publish-upload-boundary-contract.md)、
[Linux Package Artifact Manifest Checksum Validation Contract](linux-package-artifact-manifest-checksum-validation-contract.md)、
[Linux Package Artifact Manifest Generation Validation Contract](linux-package-artifact-manifest-generation-validation-contract.md)、
[Linux Package Checksum Manifest Contract](linux-package-checksum-manifest-contract.md)、
[Linux Package Release Notes Rollback Policy Binding Contract](linux-package-release-notes-rollback-policy-binding-contract.md)、
[Linux Package Release Notes Rollback Execution Validation Contract](linux-package-release-notes-rollback-execution-validation-contract.md)、
[Linux Package Publish Eligibility Aggregate Contract](linux-package-publish-eligibility-aggregate-contract.md)、
[Linux Package Publish Eligibility Execution Validation Contract](linux-package-publish-eligibility-execution-validation-contract.md)、
runner/toolchain/target contract、release policy 认可的 version 和 release workflow 中的显式常量。

当前 placeholder 固定为：

| 字段 | 值 |
| --- | --- |
| `package_artifact_attestation_execution_contract` | `present` |
| `package_artifact_attestation_execution_status` | `blocked-placeholder` |
| `package_artifact_attestation_execution_source` | `linux-artifact-readiness` |
| `package_artifact_attestation_execution_current_mode` | `contract-only-no-attestation` |
| `package_artifact_attestation_execution_required_job` | `attest-linux` |
| `package_artifact_attestation_execution_job_status` | `not-defined` |
| `package_artifact_attestation_execution_package_job` | `package-linux` |
| `package_artifact_attestation_execution_package_job_status` | `not-defined` |
| `package_artifact_attestation_execution_workflow_artifact_bundle_status` | `blocked-placeholder` |
| `package_artifact_attestation_execution_download_source` | `same-run-workflow-artifact` |
| `package_artifact_attestation_execution_bundle_name` | `networkcore-linux-${version}-${target}-release-bundle` |
| `package_artifact_attestation_execution_subjects` | `archive,archive_sha256,manifest,manifest_sha256` |
| `package_artifact_attestation_execution_subject_path_mode` | `explicit-files` |
| `package_artifact_attestation_execution_action` | `actions/attest` |
| `package_artifact_attestation_execution_action_version` | `v4` |
| `package_artifact_attestation_execution_action_status` | `blocked` |
| `package_artifact_attestation_execution_required_permissions` | `contents-read,id-token-write,attestations-write` |
| `package_artifact_attestation_execution_permissions_status` | `not-enabled` |
| `package_artifact_attestation_execution_attestation_policy` | `github-artifact-attestation-required` |
| `package_artifact_attestation_execution_attestation_status` | `blocked-not-attested` |
| `package_artifact_attestation_execution_provenance_policy` | `github-build-provenance-required` |
| `package_artifact_attestation_execution_provenance_file` | `github-artifact-attestation` |
| `package_artifact_attestation_execution_provenance_status` | `blocked-not-generated` |
| `package_artifact_attestation_execution_publish_without_attestation` | `blocked` |
| `package_artifact_attestation_execution_release_asset` | `blocked` |
| `package_artifact_attestation_execution_publish_job` | `publish-github-release` |
| `package_artifact_attestation_execution_publish_job_status` | `not-defined` |
| `package_artifact_attestation_execution_next_action` | `release-notes-rollback-execution-after-attestation` |

`blocked-placeholder` 表示 release workflow 已记录 future attestation execution 的验证要求，
但当前 release 仍不得定义 `attest-linux` job、启用 attestation permissions、调用
`actions/attest` 或上传 release asset。

## Future Attestation Execution

未来真实 `attest-linux` job 必须在 workflow artifact bundle upload status 为 `complete` 后，
只下载同一 release run 的 workflow artifact bundle，并对四个 explicit subject files 生成
GitHub artifact attestation/provenance。GitHub 文档要求 binary provenance attestation workflow
配置 `contents: read`、`id-token: write` 和 `attestations: write`，并在构建产物完成后调用
`actions/attest@v4` 的 `subject-path`。

future job 边界：

```yaml
attest-linux:
  needs:
    - package-linux
  permissions:
    contents: read
    id-token: write
    attestations: write
  steps:
    - uses: actions/download-artifact@v4
      with:
        name: networkcore-linux-${version}-${target}-release-bundle
        path: dist/linux/${target}/attestation-inputs

    - name: Generate Linux artifact attestations
      uses: actions/attest@v4
      with:
        subject-path: |
          dist/linux/${target}/attestation-inputs/networkcore-linux-${version}-${target}.tar.gz
          dist/linux/${target}/attestation-inputs/networkcore-linux-${version}-${target}.tar.gz.sha256
          dist/linux/${target}/attestation-inputs/networkcore-linux-${version}-${target}.manifest.json
          dist/linux/${target}/attestation-inputs/networkcore-linux-${version}-${target}.manifest.json.sha256
```

字段规则：

| 字段 | 要求 |
| --- | --- |
| required job | `attest-linux` |
| upstream job | `package-linux` |
| download source | 只能是同一 release run workflow artifact bundle |
| bundle name | 固定为 `networkcore-linux-${version}-${target}-release-bundle` |
| subject files | 必须且只能包含 archive、archive checksum、manifest、manifest checksum |
| subject path mode | 必须列出四个 explicit files，不能使用目录 glob |
| action | 使用 `actions/attest@v4` |
| permissions | future job 必须声明 `contents: read`、`id-token: write`、`attestations: write` |
| provenance source | GitHub artifact attestation |
| release asset | attestation execution gate 不得上传 GitHub Release asset |

## Failure Boundary

真实 attestation execution gate 必须在以下情况失败，并且不得执行 release asset upload：

- workflow artifact bundle upload status 不是 `complete`。
- license/NOTICE 仍为 pending，release CI gate 仍为 placeholder，或 package publish eligibility
  仍为 blocked。
- `attest-linux` 未依赖当前 release run 的 `package-linux`。
- downloaded artifact name 与 `networkcore-linux-${version}-${target}-release-bundle` 不一致。
- downloaded bundle 缺少 archive、archive checksum、manifest 或 manifest checksum。
- subject file set 多于或少于四个 required files。
- subject path 使用目录 glob，导致额外文件进入 attestation subject。
- subject 来自旧 run artifact、不同 commit artifact、不同 branch artifact、外部 URL、
  runner cache、临时目录、人工上传文件或 `workflow_dispatch` 输入。
- `actions/attest` 版本、subject path、permissions 或 provenance policy 与本文档不一致。
- workflow 在本 gate 激活前启用 `id-token: write`、`attestations: write` 或调用 `actions/attest`。
- manifest、release summary 或 job outputs 中的 attestation/provenance 字段不一致。
- publish job 在 `package_artifact_attestation_execution_attestation_status=attested` 和
  provenance reference 可验证前上传 GitHub Release asset。

失败时 release workflow 必须失败在 `attest-linux` 内或之前，不得创建 publish job 可消费的
release asset。

## Release Workflow 边界

当前 placeholder release 只能：

- 检查本文档存在和标题。
- 检查本文档包含 current placeholder fields、required permissions、subjects、future attestation
  execution、failure boundary 和 release asset blocked 边界。
- 检查 workflow artifact bundle upload validation contract、signing/attestation policy binding
  contract、publish/upload boundary contract 和 publish eligibility execution validation contract 可发现。
- 在 `linux-artifact-readiness`、release placeholder 和 release summary 中输出 artifact
  attestation execution validation contract。
- 标记 `linux-package-artifact-attestation-execution-contract=present`。
- 标记 `linux-package-artifact-attestation-execution-status=blocked-placeholder`。
- 标记 `linux-package-artifact-attestation-execution-required-job=attest-linux`。
- 标记 `linux-package-artifact-attestation-execution-job-status=not-defined`。
- 标记 `linux-package-artifact-attestation-execution-package-job=package-linux`。
- 标记 `linux-package-artifact-attestation-execution-package-job-status=not-defined`。
- 标记 `linux-package-artifact-attestation-execution-workflow-artifact-bundle=blocked-placeholder`。
- 标记 `linux-package-artifact-attestation-execution-download-source=same-run-workflow-artifact`。
- 标记 `linux-package-artifact-attestation-execution-bundle-name=networkcore-linux-${version}-${target}-release-bundle`。
- 标记 `linux-package-artifact-attestation-execution-subjects=archive,archive_sha256,manifest,manifest_sha256`。
- 标记 `linux-package-artifact-attestation-execution-subject-path-mode=explicit-files`。
- 标记 `linux-package-artifact-attestation-execution-action=actions/attest`。
- 标记 `linux-package-artifact-attestation-execution-action-version=v4`。
- 标记 `linux-package-artifact-attestation-execution-action-status=blocked`。
- 标记 `linux-package-artifact-attestation-execution-required-permissions=contents-read,id-token-write,attestations-write`。
- 标记 `linux-package-artifact-attestation-execution-permissions-status=not-enabled`。
- 标记 `linux-package-artifact-attestation-execution-attestation-policy=github-artifact-attestation-required`。
- 标记 `linux-package-artifact-attestation-execution-attestation-status=blocked-not-attested`。
- 标记 `linux-package-artifact-attestation-execution-provenance-policy=github-build-provenance-required`。
- 标记 `linux-package-artifact-attestation-execution-provenance-file=github-artifact-attestation`。
- 标记 `linux-package-artifact-attestation-execution-provenance-status=blocked-not-generated`。
- 标记 `linux-package-artifact-attestation-execution-publish-without-attestation=blocked`。
- 标记 `linux-package-artifact-attestation-execution-release-asset=blocked`。
- 标记 `linux-package-artifact-attestation-execution-publish-job=publish-github-release`。
- 标记 `linux-package-artifact-attestation-execution-publish-job-status=not-defined`。
- 标记 `linux-package-artifact-attestation-execution-next-action=release-notes-rollback-execution-after-attestation`。
- 继续不定义 `package-linux`、`attest-linux`、`sign-linux`、`publish-github-release` 或
  `post-release-summary`。
- 继续不启用 `id-token: write`、`attestations: write` 或 `actions/attest`。

## 验收条件

- 本文档保持在 README、ROADMAP、Release Strategy、Linux package workflow artifact bundle upload
  validation contract、Linux package publish/upload boundary contract、Linux package signing/attestation
  policy binding contract、Linux package release notes/rollback policy binding contract、Linux package
  release notes/rollback execution validation contract、Linux package publish eligibility aggregate contract、
  Linux package publish eligibility execution validation contract、Linux CLI artifact 安装/回滚设计和 CI policy
  中可发现。
- `.github/workflows/ci.yml` governance 检查本文档存在、标题、status、required permissions、
  subjects、future attestation execution 和 release workflow placeholder 输出字段。
- `.github/workflows/release.yml` 的 `linux-artifact-readiness` 检查本文档存在、标题、placeholder
  fields、required permissions、subjects、future attestation execution、failure boundary、
  forbidden permission/action guards 和 `attest-linux` 未定义状态。
- release placeholder 和 release summary 输出 artifact attestation execution status、required job、
  workflow artifact bundle blocked、download source、bundle name、subjects、subject path mode、
  action blocked、required permissions、permissions status、attestation/provenance blocked、release asset
  blocked、publish job not-defined 和 next action。
- 当前不生成 artifact、不定义 `package-linux`、不定义 `attest-linux`、不定义 `sign-linux`、
  不定义 `publish-github-release`、不启用 `id-token: write`、不启用 `attestations: write`、
  不调用 `actions/attest`、不上传 workflow artifact、不上传 release asset、不在本机执行测试、
  构建、打包或发布。

## 后续工作

- 在 license/NOTICE 人工确认、release CI gate activation、artifact job preflight、build command、
  staging file、archive creation、checksum execution、manifest generation、manifest checksum、
  workflow artifact bundle upload、attestation execution 和 release notes/rollback execution gates 激活前，
  继续保持 `package-linux`、`attest-linux` 和 `post-release-summary` 未定义。
- Linux package publish eligibility execution validation contract 已定义；下一步可以补充 release CI gate
  execution validation contract，明确 release workflow 如何自动读取同 commit 成功 CI run，并继续阻止
  GitHub Release asset。
