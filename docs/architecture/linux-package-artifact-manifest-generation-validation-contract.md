# Linux Package Artifact Manifest Generation Validation Contract

本文定义首个 Linux `package-linux` job 在未来 archive checksum sidecar 写入完成后生成
artifact manifest JSON 前必须满足的 manifest generation 验证合同。当前仍是 placeholder；
本文只固定 manifest 文件名、路径、必需 JSON 字段、archive/checksum 交叉引用和继续不计算
manifest checksum 或上传 artifact 的边界，不定义 `package-linux` job、不构建、不复制文件、
不创建 archive、不计算 checksum、不写 manifest、不上传 artifact。

评估时间：2026-07-07。

## 目标

- 固定首个 Linux CLI artifact manifest JSON 的文件名、路径、schema version 和必需字段。
- 明确 manifest 只能在 archive checksum sidecar 写入并校验后生成。
- 防止 maintainer 使用缺字段 manifest、旧 run metadata、本地产物或 runner cache 绕过
  archive checksum 和 manifest gates。
- 在 manifest generation gate 未激活时继续阻止 manifest checksum、workflow artifact 和
  GitHub Release asset。

## 非目标

- 不实现 `package-linux`、`publish-github-release`、`attest-linux`、`sign-linux`、
  `post-release-summary` 或等价 job。
- 不运行 `cargo build`、不复制 staging files、不创建 archive、不运行 `sha256sum`、
  不写 archive checksum sidecar、不写 manifest JSON、不写 manifest checksum sidecar、
  attestation、release notes 或 upload step。
- 不完成 license/NOTICE 人工确认。
- 不启用 release CI gate 的 GitHub API 读取。
- 不把 runner 本地绝对路径、Cargo cache、target 目录、临时路径、secret、token、
  用户配置、环境变量原文、GitHub API response 原文或未公开安全公告细节写入 manifest、
  release notes 或 Step Summary。

## Source Of Truth

首个 Linux package artifact manifest generation 输入必须来自本文档、
[Linux Package Artifact Checksum Execution Validation Contract](linux-package-artifact-checksum-execution-validation-contract.md)、
[Linux Package Artifact Manifest Design](linux-package-artifact-manifest.md)、
[Linux Package Checksum Manifest Contract](linux-package-checksum-manifest-contract.md)、
[Linux Package Archive Staging Contract](linux-package-archive-staging-contract.md)、
[Linux Package Publish Upload Boundary Contract](linux-package-publish-upload-boundary-contract.md)、
release policy 认可的 version、runner/toolchain/target contract 和 release workflow 中的显式常量。

当前 placeholder 固定为：

| 字段 | 值 |
| --- | --- |
| `package_artifact_manifest_generation_contract` | `present` |
| `package_artifact_manifest_generation_status` | `blocked-placeholder` |
| `package_artifact_manifest_generation_source` | `linux-artifact-readiness` |
| `package_artifact_manifest_generation_current_mode` | `contract-only-no-manifest` |
| `package_artifact_manifest_generation_required_job` | `package-linux` |
| `package_artifact_manifest_generation_job_status` | `not-defined` |
| `package_artifact_manifest_generation_checksum_execution_status` | `blocked-placeholder` |
| `package_artifact_manifest_generation_schema_version` | `1` |
| `package_artifact_manifest_generation_artifact_kind` | `linux-cli-tarball` |
| `package_artifact_manifest_generation_package_format` | `tar.gz` |
| `package_artifact_manifest_generation_manifest_name` | `networkcore-linux-${version}-${target}.manifest.json` |
| `package_artifact_manifest_generation_manifest_path` | `dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.manifest.json` |
| `package_artifact_manifest_generation_archive_name` | `networkcore-linux-${version}-${target}.tar.gz` |
| `package_artifact_manifest_generation_archive_path` | `dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.tar.gz` |
| `package_artifact_manifest_generation_checksum_name` | `networkcore-linux-${version}-${target}.tar.gz.sha256` |
| `package_artifact_manifest_generation_checksum_path` | `dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.tar.gz.sha256` |
| `package_artifact_manifest_generation_required_fields` | `schema_version,artifact_kind,package_format,artifact_name,target_triple,version,commit_sha,source_ref,ci_run_url,release_run_url,runner,rust_toolchain,archive,checksum,included_files,install_model,system_mutation_policy,license_notice_status,signing,release_notes,rollback,publish_eligibility` |
| `package_artifact_manifest_generation_archive_file_field` | `archive.file_name` |
| `package_artifact_manifest_generation_archive_path_field` | `archive.relative_path` |
| `package_artifact_manifest_generation_checksum_algorithm_field` | `checksum.algorithm` |
| `package_artifact_manifest_generation_checksum_file_field` | `checksum.file_name` |
| `package_artifact_manifest_generation_checksum_value_field` | `checksum.value` |
| `package_artifact_manifest_generation_included_files` | `bin/networkcore-linux,INSTALL.md,LICENSE,CHANGELOG.md` |
| `package_artifact_manifest_generation_install_model` | `manual-extract` |
| `package_artifact_manifest_generation_system_mutation_policy` | `none` |
| `package_artifact_manifest_generation_manifest_checksum` | `blocked` |
| `package_artifact_manifest_generation_upload` | `blocked` |
| `package_artifact_manifest_generation_next_action` | `manifest-checksum-after-manifest` |

`blocked-placeholder` 表示 release workflow 已记录未来 manifest generation 的验证要求，但当前
release 仍不得创建 job、写 manifest、计算 manifest checksum 或上传 artifact。

## Future Manifest Generation

未来真实 `package-linux` job 必须在 checksum execution status 为 `complete` 且 archive
checksum sidecar 校验通过后，按以下顺序生成 manifest JSON：

1. 读取 release policy 认可的 `version`、runner/toolchain/target contract 固定的 `target`、
   当前 release run SHA/ref/run URL 和同 commit 成功 CI run URL。
2. 固定 `manifest_name=networkcore-linux-${version}-${target}.manifest.json`。
3. 固定 `manifest_path=dist/linux/${target}/artifacts/${manifest_name}`。
4. 读取 `networkcore-linux-${version}-${target}.tar.gz.sha256` 中的 archive digest。
5. 生成 UTF-8 JSON manifest，写入所有 `package_artifact_manifest_generation_required_fields`。
6. 写入 `archive.file_name`、`archive.relative_path`、`checksum.algorithm`、`checksum.file_name`
   和 `checksum.value`。
7. 交叉校验 `checksum.value` 与 archive checksum sidecar digest 完全一致。
8. 交叉校验 `archive.file_name`、`archive.relative_path`、`checksum.file_name` 与合同固定的
   archive/checksum 文件名和路径完全一致。
9. 在计算 manifest checksum 前完成稳定序列化；manifest checksum gate 不得在 manifest
   generation gate 内执行。

字段规则：

| 字段 | 要求 |
| --- | --- |
| schema version | 固定为 JSON number `1` |
| artifact kind | 固定为 `linux-cli-tarball` |
| package format | 固定为 `tar.gz` |
| manifest file | 必须位于 `dist/linux/${target}/artifacts`，且不得放入 archive 内部 |
| archive fields | 必须引用 archive creation gate 输出的最终 `.tar.gz` 文件 |
| checksum fields | 必须引用 checksum execution gate 输出的 archive checksum sidecar |
| included files | 至少包含 `bin/networkcore-linux`、`INSTALL.md`、`LICENSE`、`CHANGELOG.md` |
| install model | 固定为 `manual-extract` |
| system mutation policy | 固定为 `none` |
| manifest checksum | manifest generation gate 不得计算或写入 manifest checksum sidecar |
| upload | manifest generation gate 不得上传 workflow artifact 或 release asset |

## Failure Boundary

真实 manifest generation gate 必须在以下情况失败，并且不得执行 manifest checksum、workflow
artifact upload 或 release asset upload：

- checksum execution status 不是 `complete`。
- license/NOTICE 仍为 pending，或 release CI gate 仍为 placeholder。
- manifest name、manifest path、archive name/path、checksum name/path、target、schema version、
  artifact kind 或 package format 与合同不一致。
- archive checksum sidecar 不存在、为空、不是普通文件、格式不符合
  `sha256sum-two-space-file-name`，或 digest 不是 64 位小写十六进制。
- manifest 缺少任一 `package_artifact_manifest_generation_required_fields`。
- manifest 写入绝对路径、runner workspace、Cargo cache、target 目录、URL、secret、token、
  环境变量原文、GitHub API response 原文、私钥、用户配置或未公开安全公告细节。
- `archive.file_name`、`archive.relative_path`、`checksum.algorithm`、`checksum.file_name` 或
  `checksum.value` 与 archive/checksum sidecar 不一致。
- manifest 在 archive checksum sidecar 写入前生成，或 manifest 写入 archive 内部。
- manifest 后直接上传 workflow artifact 或 release asset，绕过 manifest checksum、
  signing/attestation、release notes/rollback 和 publish eligibility gates。

失败时 release workflow 必须失败在 `package-linux` 内或之前，不得创建 publish job 可消费的 artifact。

## Release Workflow 边界

当前 placeholder release 只能：

- 检查本文档存在和标题。
- 检查本文档包含 current placeholder fields、future manifest generation、required fields、
  failure boundary 和 manifest checksum/upload blocked 边界。
- 检查 checksum execution contract、checksum manifest contract、manifest design 和 publish/upload
  boundary contract 可发现。
- 在 `linux-artifact-readiness`、release placeholder 和 release summary 中输出 manifest generation
  validation contract。
- 标记 `linux-package-artifact-manifest-generation-contract=present`。
- 标记 `linux-package-artifact-manifest-generation-status=blocked-placeholder`。
- 标记 `linux-package-artifact-manifest-generation-required-job=package-linux`。
- 标记 `linux-package-artifact-manifest-generation-checksum-execution=blocked-placeholder`。
- 标记 `linux-package-artifact-manifest-generation-schema-version=1`。
- 标记 `linux-package-artifact-manifest-generation-artifact-kind=linux-cli-tarball`。
- 标记 `linux-package-artifact-manifest-generation-package-format=tar.gz`。
- 标记 `linux-package-artifact-manifest-generation-manifest-name=networkcore-linux-${version}-${target}.manifest.json`。
- 标记 `linux-package-artifact-manifest-generation-manifest-path=dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.manifest.json`。
- 标记 `linux-package-artifact-manifest-generation-archive-name=networkcore-linux-${version}-${target}.tar.gz`。
- 标记 `linux-package-artifact-manifest-generation-archive-path=dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.tar.gz`。
- 标记 `linux-package-artifact-manifest-generation-checksum-name=networkcore-linux-${version}-${target}.tar.gz.sha256`。
- 标记 `linux-package-artifact-manifest-generation-checksum-path=dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.tar.gz.sha256`。
- 标记 `linux-package-artifact-manifest-generation-required-fields=schema_version,artifact_kind,package_format,artifact_name,target_triple,version,commit_sha,source_ref,ci_run_url,release_run_url,runner,rust_toolchain,archive,checksum,included_files,install_model,system_mutation_policy,license_notice_status,signing,release_notes,rollback,publish_eligibility`。
- 标记 `linux-package-artifact-manifest-generation-archive-file-field=archive.file_name`。
- 标记 `linux-package-artifact-manifest-generation-archive-path-field=archive.relative_path`。
- 标记 `linux-package-artifact-manifest-generation-checksum-algorithm-field=checksum.algorithm`。
- 标记 `linux-package-artifact-manifest-generation-checksum-file-field=checksum.file_name`。
- 标记 `linux-package-artifact-manifest-generation-checksum-value-field=checksum.value`。
- 标记 `linux-package-artifact-manifest-generation-included-files=bin/networkcore-linux,INSTALL.md,LICENSE,CHANGELOG.md`。
- 标记 `linux-package-artifact-manifest-generation-install-model=manual-extract`。
- 标记 `linux-package-artifact-manifest-generation-system-mutation-policy=none`。
- 标记 `linux-package-artifact-manifest-generation-manifest-checksum=blocked`。
- 标记 `linux-package-artifact-manifest-generation-upload=blocked`。
- 标记 `linux-package-artifact-manifest-generation-next-action=manifest-checksum-after-manifest`。
- 继续不定义 `package-linux`、`publish-github-release`、`attest-linux`、`sign-linux` 或
  `post-release-summary`。

## Manifest Binding

真实 manifest 必须至少能表达以下与 archive checksum sidecar 的绑定：

```json
{
  "schema_version": 1,
  "artifact_kind": "linux-cli-tarball",
  "package_format": "tar.gz",
  "artifact_name": "networkcore-linux-v0.1.0-x86_64-unknown-linux-gnu.tar.gz",
  "archive": {
    "file_name": "networkcore-linux-v0.1.0-x86_64-unknown-linux-gnu.tar.gz",
    "relative_path": "dist/linux/x86_64-unknown-linux-gnu/artifacts/networkcore-linux-v0.1.0-x86_64-unknown-linux-gnu.tar.gz"
  },
  "checksum": {
    "algorithm": "sha256",
    "file_name": "networkcore-linux-v0.1.0-x86_64-unknown-linux-gnu.tar.gz.sha256",
    "value": "<archive-sha256>"
  }
}
```

示例不是当前 artifact 事实；真实 job 必须写入 release run 的实际值并补齐所有 required fields。

## 验收条件

- 本文档保持在 README、ROADMAP、Release Strategy、Linux package artifact checksum execution
  validation contract、Linux package checksum manifest contract、Linux package manifest 设计、
  Linux package publish/upload boundary contract、Linux CLI artifact 安装/回滚设计和 CI policy
  中可发现。
- `.github/workflows/ci.yml` governance 检查本文档存在、标题和 release workflow placeholder 输出字段。
- `.github/workflows/release.yml` 的 `linux-artifact-readiness` 检查本文档存在、标题、placeholder
  fields、future manifest generation、required fields、failure boundary 和 `package-linux` 未定义状态。
- release placeholder 和 release summary 输出 manifest generation status、required job、checksum
  execution blocked、schema version、artifact kind、package format、manifest name/path、archive
  name/path、checksum name/path、required fields、cross-check fields、included files、install model、
  system mutation policy、manifest checksum blocked、upload blocked 和 next action。
- 当前不生成 artifact、不定义 `package-linux`、不定义 `publish-github-release`、不创建 archive、
  不计算 checksum、不写 manifest、不计算 manifest checksum、不上传 workflow artifact、不上传
  release asset、不在本机执行测试、构建、打包或发布。

## 后续工作

- 在 license/NOTICE 人工确认、release CI gate activation、artifact job preflight、build command、
  staging file、archive creation 和 checksum execution gates 激活前，继续保持 `package-linux` 未定义。
- 下一步可以补充 Linux package artifact manifest checksum validation contract，明确真实 manifest
  JSON 生成后计算 manifest sha256、写 manifest checksum sidecar 和仍不 upload 的边界。
