# Linux Package Workflow Artifact Bundle Upload Validation Contract

本文定义首个 Linux `package-linux` job 在未来 manifest checksum sidecar 生成后，
上传同一 release run workflow artifact bundle 前必须满足的验证合同。当前仍是 placeholder；
本文只固定 bundle 文件集、来源目录、artifact 名称、retention、同一 run 边界和 release asset
继续阻断状态，不定义 `package-linux` job、不构建、不打包、不上传 workflow artifact、不发布
GitHub Release asset。

评估时间：2026-07-07。

## 目标

- 固定首个 Linux CLI release bundle 必须包含且只包含 archive、archive checksum、manifest 和
  manifest checksum 四个文件。
- 明确 workflow artifact upload 只能在 manifest checksum validation 完成后执行。
- 防止 maintainer 使用 staging 目录、Cargo target 目录、旧 run artifact、外部 URL、runner cache
  或人工输入路径绕过 release bundle integrity gates。
- 在 workflow artifact bundle upload gate 未激活时继续阻止 GitHub Release asset upload。

## 非目标

- 不实现 `package-linux`、`publish-github-release`、`attest-linux`、`sign-linux`、
  `post-release-summary` 或等价 job。
- 不运行 `cargo build`、不复制 staging files、不创建 archive、不运行 `sha256sum`、
  不写 manifest、不计算 manifest checksum、不调用 `actions/upload-artifact`。
- 不生成 attestation/provenance、不生成 release notes、不发布 GitHub Release asset。
- 不完成 license/NOTICE 人工确认。
- 不启用 release CI gate 的 GitHub API 读取。
- 不把 runner 本地绝对路径、Cargo cache、target 目录、临时路径、secret、token、
  用户配置、环境变量原文、GitHub API response 原文或未公开安全公告细节写入 manifest、
  workflow artifact、release notes 或 Step Summary。

## Source Of Truth

首个 Linux package workflow artifact bundle upload 输入必须来自本文档、
[Linux Package Artifact Manifest Checksum Validation Contract](linux-package-artifact-manifest-checksum-validation-contract.md)、
[Linux Package Artifact Manifest Generation Validation Contract](linux-package-artifact-manifest-generation-validation-contract.md)、
[Linux Package Checksum Manifest Contract](linux-package-checksum-manifest-contract.md)、
[Linux Package Publish Upload Boundary Contract](linux-package-publish-upload-boundary-contract.md)、
[Linux Package Signing Attestation Policy Binding Contract](linux-package-signing-attestation-policy-binding-contract.md)、
[Linux Package Artifact Attestation Execution Validation Contract](linux-package-artifact-attestation-execution-validation-contract.md)、
[Linux Package Release Notes Rollback Policy Binding Contract](linux-package-release-notes-rollback-policy-binding-contract.md)、
[Linux Package Release Notes Rollback Execution Validation Contract](linux-package-release-notes-rollback-execution-validation-contract.md)、
[Linux Package Publish Eligibility Aggregate Contract](linux-package-publish-eligibility-aggregate-contract.md)、
[Linux Package Publish Eligibility Execution Validation Contract](linux-package-publish-eligibility-execution-validation-contract.md)、
runner/toolchain/target contract、release policy 认可的 version 和 release workflow 中的显式常量。

当前 placeholder 固定为：

| 字段 | 值 |
| --- | --- |
| `package_workflow_artifact_bundle_upload_contract` | `present` |
| `package_workflow_artifact_bundle_upload_status` | `blocked-placeholder` |
| `package_workflow_artifact_bundle_upload_source` | `linux-artifact-readiness` |
| `package_workflow_artifact_bundle_upload_current_mode` | `contract-only-no-workflow-artifact-upload` |
| `package_workflow_artifact_bundle_upload_required_job` | `package-linux` |
| `package_workflow_artifact_bundle_upload_job_status` | `not-defined` |
| `package_workflow_artifact_bundle_upload_manifest_checksum_status` | `blocked-placeholder` |
| `package_workflow_artifact_bundle_upload_source_dir` | `dist/linux/${target}/artifacts` |
| `package_workflow_artifact_bundle_upload_name` | `networkcore-linux-${version}-${target}-release-bundle` |
| `package_workflow_artifact_bundle_upload_retention_days` | `14` |
| `package_workflow_artifact_bundle_upload_required_files` | `archive,archive_sha256,manifest,manifest_sha256` |
| `package_workflow_artifact_bundle_upload_archive_name` | `networkcore-linux-${version}-${target}.tar.gz` |
| `package_workflow_artifact_bundle_upload_archive_checksum_name` | `networkcore-linux-${version}-${target}.tar.gz.sha256` |
| `package_workflow_artifact_bundle_upload_manifest_name` | `networkcore-linux-${version}-${target}.manifest.json` |
| `package_workflow_artifact_bundle_upload_manifest_checksum_name` | `networkcore-linux-${version}-${target}.manifest.json.sha256` |
| `package_workflow_artifact_bundle_upload_same_run` | `required` |
| `package_workflow_artifact_bundle_upload_upload_action` | `actions/upload-artifact` |
| `package_workflow_artifact_bundle_upload_upload_action_status` | `blocked` |
| `package_workflow_artifact_bundle_upload_release_asset` | `blocked` |
| `package_workflow_artifact_bundle_upload_publish_job` | `publish-github-release` |
| `package_workflow_artifact_bundle_upload_publish_job_status` | `not-defined` |
| `package_workflow_artifact_bundle_upload_next_action` | `attestation-after-workflow-artifact-bundle` |

`blocked-placeholder` 表示 release workflow 已记录未来 workflow artifact bundle upload 的验证要求，
但当前 release 仍不得创建 `package-linux` job、调用 `actions/upload-artifact` 或上传 release asset。

## Future Workflow Artifact Upload

未来真实 `package-linux` job 必须在 manifest checksum validation status 为 `complete` 后，
先校验 upload source dir 和四个 required files，再上传同一 release run workflow artifact bundle：

```bash
upload_dir="dist/linux/${target}/artifacts"
bundle_name="networkcore-linux-${version}-${target}-release-bundle"
required_files=(
  "networkcore-linux-${version}-${target}.tar.gz"
  "networkcore-linux-${version}-${target}.tar.gz.sha256"
  "networkcore-linux-${version}-${target}.manifest.json"
  "networkcore-linux-${version}-${target}.manifest.json.sha256"
)

for file in "${required_files[@]}"; do
  test -f "${upload_dir}/${file}"
  test -s "${upload_dir}/${file}"
done

find "${upload_dir}" -maxdepth 1 -type f | wc -l | grep -qx '4'
```

后续 upload step 必须使用显式文件路径，而不是目录 glob：

```yaml
- uses: actions/upload-artifact@v4
  with:
    name: networkcore-linux-${version}-${target}-release-bundle
    path: |
      dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.tar.gz
      dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.tar.gz.sha256
      dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.manifest.json
      dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.manifest.json.sha256
    retention-days: 14
    if-no-files-found: error
```

字段规则：

| 字段 | 要求 |
| --- | --- |
| source dir | 固定为 `dist/linux/${target}/artifacts` |
| bundle name | 固定为 `networkcore-linux-${version}-${target}-release-bundle` |
| required files | 必须且只能包含 archive、archive checksum、manifest、manifest checksum |
| retention days | 固定为 `14` |
| upload action | 使用 `actions/upload-artifact` |
| path mode | 必须列出四个显式文件路径，不能使用目录 glob |
| same run | bundle 只能由当前 release run 的 `package-linux` job 上传 |
| publish source | 后续 publish job 只能下载同一 release run 的 workflow artifact bundle |
| release asset | workflow artifact bundle upload gate 不得上传 GitHub Release asset |

## Failure Boundary

真实 workflow artifact bundle upload gate 必须在以下情况失败，并且不得执行 release asset upload：

- manifest checksum validation status 不是 `complete`。
- license/NOTICE 仍为 pending，或 release CI gate 仍为 placeholder。
- `dist/linux/${target}/artifacts` 不存在、为空、不是目录，或来源目录与本文档不一致。
- 任一 required file 不存在、为空、不是普通文件，或文件名与本文档不一致。
- source dir 中存在 required files 以外的普通文件。
- upload path 来自 staging 目录、Cargo target 目录、runner cache、临时目录、旧 run artifact、
  外部 URL、人工上传文件或 `workflow_dispatch` 输入。
- workflow artifact name、retention days、required file set 或 upload action 与本文档不一致。
- 使用目录 glob 导致额外文件进入 bundle。
- archive 在 checksum、manifest 或 manifest checksum 缺失时被单独上传。
- workflow artifact upload 后直接上传 release asset，绕过 attestation/provenance、release notes/rollback
  和 publish eligibility gates。

失败时 release workflow 必须失败在 `package-linux` 内或之前，不得创建 publish job 可消费的
release asset。

## Release Workflow 边界

当前 placeholder release 只能：

- 检查本文档存在和标题。
- 检查本文档包含 current placeholder fields、source dir、required files、future workflow
  artifact upload、failure boundary 和 release asset blocked 边界。
- 检查 manifest checksum contract、publish/upload boundary contract 和 signing/attestation policy
  binding contract 可发现。
- 在 `linux-artifact-readiness`、release placeholder 和 release summary 中输出 workflow artifact
  bundle upload validation contract。
- 标记 `linux-package-workflow-artifact-bundle-upload-contract=present`。
- 标记 `linux-package-workflow-artifact-bundle-upload-status=blocked-placeholder`。
- 标记 `linux-package-workflow-artifact-bundle-upload-required-job=package-linux`。
- 标记 `linux-package-workflow-artifact-bundle-upload-manifest-checksum=blocked-placeholder`。
- 标记 `linux-package-workflow-artifact-bundle-upload-source-dir=dist/linux/${target}/artifacts`。
- 标记 `linux-package-workflow-artifact-bundle-upload-name=networkcore-linux-${version}-${target}-release-bundle`。
- 标记 `linux-package-workflow-artifact-bundle-upload-retention-days=14`。
- 标记 `linux-package-workflow-artifact-bundle-upload-required-files=archive,archive_sha256,manifest,manifest_sha256`。
- 标记 `linux-package-workflow-artifact-bundle-upload-archive-name=networkcore-linux-${version}-${target}.tar.gz`。
- 标记 `linux-package-workflow-artifact-bundle-upload-archive-checksum-name=networkcore-linux-${version}-${target}.tar.gz.sha256`。
- 标记 `linux-package-workflow-artifact-bundle-upload-manifest-name=networkcore-linux-${version}-${target}.manifest.json`。
- 标记 `linux-package-workflow-artifact-bundle-upload-manifest-checksum-name=networkcore-linux-${version}-${target}.manifest.json.sha256`。
- 标记 `linux-package-workflow-artifact-bundle-upload-same-run=required`。
- 标记 `linux-package-workflow-artifact-bundle-upload-upload-action=actions/upload-artifact`。
- 标记 `linux-package-workflow-artifact-bundle-upload-upload-action-status=blocked`。
- 标记 `linux-package-workflow-artifact-bundle-upload-release-asset=blocked`。
- 标记 `linux-package-workflow-artifact-bundle-upload-publish-job=publish-github-release`。
- 标记 `linux-package-workflow-artifact-bundle-upload-publish-job-status=not-defined`。
- 标记 `linux-package-workflow-artifact-bundle-upload-next-action=attestation-after-workflow-artifact-bundle`。
- 继续不定义 `package-linux`、`publish-github-release`、`attest-linux`、`sign-linux` 或
  `post-release-summary`。

## 验收条件

- 本文档保持在 README、ROADMAP、Release Strategy、Linux package artifact manifest checksum
  validation contract、Linux package checksum manifest contract、Linux package publish/upload
  boundary contract、Linux package signing/attestation policy binding contract、Linux package artifact
  attestation execution validation contract、Linux package release notes/rollback execution validation
  contract、Linux package publish eligibility aggregate contract、Linux package publish eligibility execution
  validation contract、
  Linux CLI artifact 安装/回滚设计和 CI policy 中可发现。
- `.github/workflows/ci.yml` governance 检查本文档存在、标题、source dir、required files、
  future workflow artifact upload 和 release workflow placeholder 输出字段。
- `.github/workflows/release.yml` 的 `linux-artifact-readiness` 检查本文档存在、标题、placeholder
  fields、source dir、required files、future workflow artifact upload、failure boundary 和
  `package-linux` 未定义状态。
- release placeholder 和 release summary 输出 workflow artifact bundle upload status、required job、
  manifest checksum blocked、source dir、bundle name、retention days、required files、same-run requirement、
  upload action blocked、release asset blocked、publish job not-defined 和 next action。
- 当前不生成 artifact、不定义 `package-linux`、不定义 `publish-github-release`、不定义
  `attest-linux`、不调用 `actions/upload-artifact`、不上传 workflow artifact、不上传 release asset、
  不在本机执行测试、构建、打包或发布。

## 后续工作

- 在 license/NOTICE 人工确认、release CI gate API read、artifact job preflight、build command、
  staging file、archive creation、checksum execution、manifest generation、manifest checksum 和 workflow
  artifact bundle upload gates 激活前，继续保持 `package-linux` 未定义。
- Linux package artifact attestation execution validation contract、Linux package release notes/rollback execution
  validation contract、Linux package publish eligibility execution validation contract、release CI gate execution
  validation contract 和 release CI gate API implementation plan 已定义；下一步可以实现 `release-ci-gate`
  API read，并继续阻止 GitHub Release asset。
