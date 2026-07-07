# Linux Package Publish Upload Boundary Contract

本文定义首个真实 `package-linux`、后续 publish job 和 GitHub Release asset upload
加入 `.github/workflows/release.yml` 前必须遵守的上传边界、workflow artifact retention、
release asset 阻断和不可覆盖策略。当前仍为 placeholder 合同，不定义 `package-linux`
job、不定义 publish job、不上传 workflow artifact、不发布 GitHub Release asset。

评估时间：2026-07-07。

## 目标

- 固定首个 Linux CLI artifact 从 `package-linux` 到 publish job 的上传边界。
- 明确 workflow artifact bundle 名称、上传来源目录、保留天数和后续 publish 下载来源。
- 明确 GitHub Release asset 的文件集合、上传前字段和禁止覆盖策略。
- 在 license/NOTICE 人工确认、同 commit CI success gate、checksum/manifest checksum、
  signing/attestation、rollback 和 release notes gate 完成前继续阻止真实上传。

## 非目标

- 不实现 `package-linux` job。
- 不实现 `publish-github-release` job。
- 不创建或上传 workflow artifact。
- 不创建 GitHub Release、draft release 或 release asset。
- 不定义签名、attestation、provenance 的具体策略；该策略必须由单独合同声明。
- 不把 GitHub token、API response 原文、runner 本地绝对路径、secret、证书私钥或用户配置写入
  manifest、release notes 或 Step Summary。

## Source Of Truth

首个真实 Linux publish/upload 输入必须来自本文档、
[Linux Package Runner Toolchain Target Contract](linux-package-runner-toolchain-target-contract.md)、
[Linux Package Archive Staging Contract](linux-package-archive-staging-contract.md)、
[Linux Package Checksum Manifest Contract](linux-package-checksum-manifest-contract.md)、
[Linux Package Artifact Manifest Design](linux-package-artifact-manifest.md)、
[Linux Package Signing Attestation Policy Binding Contract](linux-package-signing-attestation-policy-binding-contract.md)、
[Linux Package Release Notes Rollback Policy Binding Contract](linux-package-release-notes-rollback-policy-binding-contract.md)、
[Linux Package Publish Eligibility Aggregate Contract](linux-package-publish-eligibility-aggregate-contract.md)、
[Linux Package License Notice Transition Validation Contract](linux-package-license-notice-transition-validation-contract.md)
和 release workflow
中的显式常量。不得由 maintainer 在 `workflow_dispatch` 中手动输入上传目录、asset 名称、
retention 天数或 release asset 覆盖策略来绕过门禁。

当前首个 Linux publish/upload boundary 固定为：

| 字段 | 值 |
| --- | --- |
| `package_publish_upload_boundary_contract` | `present` |
| `package_upload_mode` | `blocked-placeholder` |
| `package_workflow_artifact_upload` | `blocked-until-package-linux-success` |
| `package_release_asset_upload` | `blocked-until-publish-gates-pass` |
| `package_upload_source_dir` | `dist/linux/${target}/artifacts` |
| `package_workflow_artifact_name` | `networkcore-linux-${version}-${target}-release-bundle` |
| `package_workflow_artifact_retention_days` | `14` |
| `package_workflow_artifact_required_files` | `archive,archive_sha256,manifest,manifest_sha256` |
| `package_publish_job_name` | `publish-github-release` |
| `package_publish_download_source` | `same-run-workflow-artifact` |
| `package_release_asset_required_files` | `archive,archive_sha256,manifest,manifest_sha256` |
| `package_release_asset_overwrite_policy` | `forbidden` |
| `package_release_asset_delete_policy` | `withdrawal-not-overwrite` |
| `package_release_asset_visibility` | `blocked-placeholder` |

`version` 必须来自 release policy 认可的 release version，`target` 必须等于
`x86_64-unknown-linux-gnu`，除非先更新 runner/toolchain/target、archive staging、checksum
manifest、manifest 和本文档。

## Workflow Artifact Boundary

真实 `package-linux` job 后续只能把最终可发布文件作为一个 workflow artifact bundle
交给后续 publish job。首个 bundle 必须包含且只包含以下文件：

| 文件 | 来源 |
| --- | --- |
| `networkcore-linux-${version}-${target}.tar.gz` | `package_archive_path` |
| `networkcore-linux-${version}-${target}.tar.gz.sha256` | `package_archive_checksum_path` |
| `networkcore-linux-${version}-${target}.manifest.json` | `package_manifest_path` |
| `networkcore-linux-${version}-${target}.manifest.json.sha256` | `package_manifest_checksum_path` |

workflow artifact 规则：

- artifact name 必须等于 `package_workflow_artifact_name`。
- upload path 必须来自 `package_upload_source_dir` 下的 required files。
- retention days 必须固定为 `14`，除非本文档和 CI policy 先更新。
- artifact 不得包含 staging 目录、Cargo target 目录、runner cache、测试日志、源码树、
  `.git`、secret、token、配置文件、证书私钥或临时目录。
- artifact 不得在 license/NOTICE confirmed、release CI success source、checksum/manifest
  checksum、signing/attestation 和 rollback gates 完成前上传。

## Release Asset Boundary

真实 `publish-github-release` job 后续只能从同一 release run 的 workflow artifact bundle
下载 Linux 文件，并重新校验 required files 后上传 GitHub Release asset。不得从本地文件、
maintainer 上传文件、旧 run artifact、不同 commit artifact、不同 branch artifact 或外部 URL
发布 Linux release asset。

首个 Linux release asset set 必须包含：

- archive。
- archive checksum sidecar。
- manifest。
- manifest checksum sidecar。

如果后续 signing/attestation policy 要求 signature、attestation 或 provenance 文件，必须先更新
本文档、manifest 设计和 signing/attestation 合同，再加入 release asset set。

## Upload Order

真实 release workflow 后续必须按以下顺序执行上传相关步骤：

1. `release-policy` 确认 version 与触发来源一致。
2. `release-ci-gate` 读取同 repository、同 commit、`main` 分支成功 CI run。
3. `linux-artifact-readiness` 确认源码、设计、manual intervention 和 placeholder 阻断状态。
4. `package-linux` 在 GitHub Actions runner 中生成 archive、checksum、manifest 和 manifest checksum。
5. `package-linux` 校验 required files、manifest cross-check 和 release summary output fields。
6. `package-linux` 上传同一 run 的 workflow artifact bundle，并设置 retention days。
7. `attest-linux` 按 [Linux Package Signing Attestation Policy Binding Contract](linux-package-signing-attestation-policy-binding-contract.md) 读取同一 run bundle，并输出 GitHub artifact attestation/provenance 状态。
8. rollback/release notes gate 按 [Linux Package Release Notes Rollback Policy Binding Contract](linux-package-release-notes-rollback-policy-binding-contract.md) 输出 rollback 字段、withdrawal policy 和 replacement policy。
9. `publish-github-release` 从同一 run 下载 workflow artifact bundle。
10. `publish-github-release` 重新校验 file set、checksum、manifest checksum、CI source、signing/attestation
    状态、rollback 字段和 license/NOTICE 状态。
11. `publish-github-release` 上传 GitHub Release assets。
12. `post-release-summary` 输出 release asset URL、checksum、manifest、CI run、release run、签名/证明
    状态和回滚字段。

当前 placeholder release 不执行第 4 步及之后的任何真实上传步骤。

## Rejection Rules

真实 upload gate 必须拒绝以下情况：

- `package-linux`、`attest-linux`、`publish-github-release` 或等价 upload job 在本文档、signing/attestation policy binding、release notes/rollback policy binding 和 publish eligibility aggregate contract 完成前被定义。
- workflow artifact name、upload source dir、retention days 或 required file set 与本文档不一致。
- workflow artifact 包含 required files 以外的文件。
- publish job 从同一 release run 以外的 artifact、runner 本地文件、外部 URL 或人工上传文件读取。
- release asset set 缺少 archive、archive checksum、manifest 或 manifest checksum。
- release asset 文件名与 package runner/toolchain/target、archive staging 或 checksum manifest 合同不一致。
- release asset 试图覆盖同名 tag 或同名 asset。
- release asset 在 license/NOTICE confirmed、release CI success source、checksum/manifest checksum、
  signing/attestation、rollback 和 release notes gates 完成前上传。

拒绝时 release workflow 必须失败，并且不得上传 workflow artifact 或 GitHub Release asset。

## Placeholder 行为

当前 release workflow 只能：

- 检查本文档存在和标题。
- 在 `linux-artifact-readiness`、`release-placeholder` 和 release summary 中输出 publish/upload
  boundary 合同。
- 标记 `linux-package-publish-upload-boundary-contract=present`。
- 标记 `linux-package-workflow-artifact-upload=blocked`。
- 标记 `linux-package-release-asset-upload=blocked`。
- 标记 `package-linux=not-defined` 和 `publish-github-release=not-defined` 或等价 blocked 状态。
- 继续不定义 `package-linux` 或 `publish-github-release`。

该 placeholder 只证明 publish/upload boundary 合同已被记录，不证明当前 release 已经可以
发布 Linux artifact。

## 验收条件

- 本文档保持在 README、ROADMAP、Release Strategy、Linux artifact 设计、Linux package
  manifest 设计、Linux package checksum manifest contract、Linux package signing/attestation
  policy binding contract、Linux package release notes/rollback policy binding contract、
  Linux package publish eligibility aggregate contract、
  Linux CLI artifact 安装/回滚设计、Release CI success source contract、
  Linux package runner/toolchain/target contract、Linux package archive staging contract、Linux artifact
  license/NOTICE confirmation source contract 和 CI policy 中可发现。
- `.github/workflows/ci.yml` governance 检查本文档存在和标题。
- `.github/workflows/release.yml` 的 `linux-artifact-readiness` 检查本文档存在、标题和
  release placeholder/summary 输出字段。
- release placeholder 和 release summary 输出 workflow artifact name、retention days、upload source
  dir、required files、publish job name、download source、release asset set、overwrite policy 和
  blocked status。
- 不生成 artifact、不定义 `package-linux`、不定义 `publish-github-release`、不上传 workflow
  artifact、不上传 release asset、不在本机执行测试、构建、打包或发布。

## 后续工作

- 在 license/NOTICE 人工确认完成前，继续保持 pending marker 并阻止 Linux artifact。
- Linux package signing/attestation policy binding contract、release notes/rollback policy binding
  contract、publish eligibility aggregate contract、license/NOTICE transition validation contract 和
  release CI gate activation validation contract 已定义；下一步可以补充 Linux package artifact job
  preflight validation contract，仍不生成 artifact。
