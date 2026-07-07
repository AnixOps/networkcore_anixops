# Linux Package Artifact Checksum Execution Validation Contract

本文定义首个 Linux `package-linux` job 在未来真实 archive 创建完成后计算 archive checksum
前必须满足的 checksum execution 验证合同。当前仍是 placeholder；本文只固定 `sha256`
算法、archive checksum sidecar 文件名和路径、record format、失败条件和继续不写 manifest
或上传 artifact 的边界，不定义 `package-linux` job、不构建、不复制文件、不创建 archive、
不计算 checksum、不写 manifest、不上传 artifact。

评估时间：2026-07-07。

## 目标

- 固定首个 Linux CLI artifact 的 archive checksum 算法、文件名、路径和记录格式。
- 明确 checksum 必须覆盖最终 `.tar.gz` bytes，且只在 archive creation 完成后计算。
- 防止 maintainer 使用手写 digest、本地产物、旧 workflow artifact 或 runner cache 绕过
  archive creation 和 checksum gates。
- 在 checksum execution gate 未激活时继续阻止 manifest、manifest checksum、workflow artifact
  和 GitHub Release asset。

## 非目标

- 不实现 `package-linux`、`publish-github-release`、`attest-linux`、`sign-linux`、
  `post-release-summary` 或等价 job。
- 不运行 `cargo build`、不复制 staging files、不创建 archive、不运行 `sha256sum`、
  不写 checksum sidecar、不写 manifest、attestation、release notes 或 upload step。
- 不完成 license/NOTICE 人工确认。
- 不启用 release CI gate 的 GitHub API 读取。
- 不把 runner 本地绝对路径、Cargo cache、target 目录、临时路径、secret、token、
  用户配置、环境变量原文、GitHub API response 原文或未公开安全公告细节写入 checksum、
  manifest、release notes 或 Step Summary。

## Source Of Truth

首个 Linux package artifact checksum execution 输入必须来自本文档、
[Linux Package Artifact Archive Creation Validation Contract](linux-package-artifact-archive-creation-validation-contract.md)、
[Linux Package Checksum Manifest Contract](linux-package-checksum-manifest-contract.md)、
[Linux Package Artifact Manifest Design](linux-package-artifact-manifest.md)、
[Linux Package Publish Upload Boundary Contract](linux-package-publish-upload-boundary-contract.md)、
release policy 认可的 version、runner/toolchain/target contract 和 release workflow 中的显式常量。

当前 placeholder 固定为：

| 字段 | 值 |
| --- | --- |
| `package_artifact_checksum_execution_contract` | `present` |
| `package_artifact_checksum_execution_status` | `blocked-placeholder` |
| `package_artifact_checksum_execution_source` | `linux-artifact-readiness` |
| `package_artifact_checksum_execution_current_mode` | `contract-only-no-checksum` |
| `package_artifact_checksum_execution_required_job` | `package-linux` |
| `package_artifact_checksum_execution_job_status` | `not-defined` |
| `package_artifact_checksum_execution_archive_creation_status` | `blocked-placeholder` |
| `package_artifact_checksum_execution_algorithm` | `sha256` |
| `package_artifact_checksum_execution_archive_name` | `networkcore-linux-${version}-${target}.tar.gz` |
| `package_artifact_checksum_execution_archive_path` | `dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.tar.gz` |
| `package_artifact_checksum_execution_checksum_name` | `networkcore-linux-${version}-${target}.tar.gz.sha256` |
| `package_artifact_checksum_execution_checksum_path` | `dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.tar.gz.sha256` |
| `package_artifact_checksum_execution_record_format` | `sha256sum-two-space-file-name` |
| `package_artifact_checksum_execution_checksum_value` | `blocked-before-archive` |
| `package_artifact_checksum_execution_checksum_file_write` | `blocked` |
| `package_artifact_checksum_execution_manifest` | `blocked` |
| `package_artifact_checksum_execution_upload` | `blocked` |
| `package_artifact_checksum_execution_next_action` | `manifest-generation-after-checksum` |

`blocked-placeholder` 表示 release workflow 已记录未来 checksum execution 的验证要求，但当前
release 仍不得创建 job、计算 checksum、写 sidecar、写 manifest 或上传 artifact。

## Future Checksum Command

未来真实 `package-linux` job 必须在 archive creation status 为 `complete` 且 archive path
校验通过后，按以下顺序计算 archive checksum：

```bash
archive_name="networkcore-linux-${version}-${target}.tar.gz"
archive_path="dist/linux/${target}/artifacts/${archive_name}"
checksum_path="dist/linux/${target}/artifacts/${archive_name}.sha256"
archive_digest="$(sha256sum "${archive_path}" | awk '{print $1}')"
printf '%s  %s\n' "${archive_digest}" "${archive_name}" > "${checksum_path}"
grep -Eq "^[0-9a-f]{64}  ${archive_name}$" "${checksum_path}"
```

字段规则：

| 字段 | 要求 |
| --- | --- |
| checksum algorithm | 固定为 `sha256` |
| archive input | 必须是 archive creation gate 输出的最终 `.tar.gz` 文件 |
| checksum file | 必须位于 `dist/linux/${target}/artifacts`，且不得放入 archive 内部 |
| record format | 必须为 `<64 lowercase hex><two spaces><archive basename>` |
| archive basename | 必须为 `networkcore-linux-${version}-${target}.tar.gz`，不得包含 `/` 或 `..` |
| checksum value | 必须由当前 release run 对最终 archive bytes 计算，不能手写或复用旧 run |
| manifest | checksum execution gate 不得直接写 manifest |
| upload | checksum execution gate 不得上传 workflow artifact 或 release asset |

## Failure Boundary

真实 checksum execution gate 必须在以下情况失败，并且不得执行 manifest、manifest checksum、
workflow artifact upload 或 release asset upload：

- archive creation status 不是 `complete`。
- license/NOTICE 仍为 pending，或 release CI gate 仍为 placeholder。
- archive name、archive path、checksum name、checksum path、target 或 algorithm 与合同不一致。
- archive path 不存在、为空、不是普通文件、路径逃逸 output dir，或来自旧 run/cache/本机产物。
- checksum digest 不是 64 位小写十六进制 `sha256`。
- checksum sidecar 不是单行 `<digest><two spaces><archive basename>` 格式。
- checksum sidecar 记录了绝对路径、目录、URL、多行内容、注释、JSON、YAML 或额外 metadata。
- checksum 在 archive 最终完成前计算，或 checksum sidecar 写入 archive 内部。
- checksum 后直接上传 workflow artifact 或 release asset，绕过 manifest、manifest checksum、
  signing/attestation、release notes/rollback 和 publish eligibility gates。

失败时 release workflow 必须失败在 `package-linux` 内或之前，不得创建 publish job 可消费的 artifact。

## Release Workflow 边界

当前 placeholder release 只能：

- 检查本文档存在和标题。
- 检查本文档包含 current placeholder fields、future checksum command、record format、failure
  boundary 和 manifest/upload blocked 边界。
- 检查 archive creation contract、checksum manifest contract、manifest design 和 publish/upload
  boundary contract 可发现。
- 在 `linux-artifact-readiness`、release placeholder 和 release summary 中输出 checksum execution
  validation contract。
- 标记 `linux-package-artifact-checksum-execution-contract=present`。
- 标记 `linux-package-artifact-checksum-execution-status=blocked-placeholder`。
- 标记 `linux-package-artifact-checksum-execution-required-job=package-linux`。
- 标记 `linux-package-artifact-checksum-execution-archive-creation=blocked-placeholder`。
- 标记 `linux-package-artifact-checksum-execution-algorithm=sha256`。
- 标记 `linux-package-artifact-checksum-execution-archive-name=networkcore-linux-${version}-${target}.tar.gz`。
- 标记 `linux-package-artifact-checksum-execution-archive-path=dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.tar.gz`。
- 标记 `linux-package-artifact-checksum-execution-checksum-name=networkcore-linux-${version}-${target}.tar.gz.sha256`。
- 标记 `linux-package-artifact-checksum-execution-checksum-path=dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.tar.gz.sha256`。
- 标记 `linux-package-artifact-checksum-execution-record-format=sha256sum-two-space-file-name`。
- 标记 `linux-package-artifact-checksum-execution-checksum-value=blocked-before-archive`。
- 标记 `linux-package-artifact-checksum-execution-checksum-file-write=blocked`。
- 标记 `linux-package-artifact-checksum-execution-manifest=blocked`。
- 标记 `linux-package-artifact-checksum-execution-upload=blocked`。
- 标记 `linux-package-artifact-checksum-execution-next-action=manifest-generation-after-checksum`。
- 继续不定义 `package-linux`、`publish-github-release`、`attest-linux`、`sign-linux` 或
  `post-release-summary`。

## Manifest Binding

真实 manifest 必须能追溯到 checksum execution 输出：

```json
{
  "checksum": {
    "contract": "docs/architecture/linux-package-artifact-checksum-execution-validation-contract.md",
    "algorithm": "sha256",
    "file_name": "networkcore-linux-v0.1.0-x86_64-unknown-linux-gnu.tar.gz.sha256",
    "record_format": "sha256sum-two-space-file-name",
    "archive_file_name": "networkcore-linux-v0.1.0-x86_64-unknown-linux-gnu.tar.gz",
    "value": "<archive-sha256>"
  }
}
```

manifest 不得写入 runner 本地绝对路径、Cargo cache path、token、secret、GitHub API
response 原文、私钥、用户配置、维护者私有身份或未公开安全公告细节。

## 验收条件

- 本文档保持在 README、ROADMAP、Release Strategy、Linux package artifact archive creation
  validation contract、Linux package checksum manifest contract、Linux package manifest 设计、
  Linux package publish/upload boundary contract、Linux CLI artifact 安装/回滚设计和 CI policy
  中可发现。
- `.github/workflows/ci.yml` governance 检查本文档存在、标题和 release workflow placeholder 输出字段。
- `.github/workflows/release.yml` 的 `linux-artifact-readiness` 检查本文档存在、标题、placeholder
  fields、future checksum command、record format、failure boundary 和 `package-linux` 未定义状态。
- release placeholder 和 release summary 输出 checksum execution status、required job、archive
  creation blocked、algorithm、archive name/path、checksum name/path、record format、checksum value
  blocked、checksum file write blocked、manifest blocked、upload blocked 和 next action。
- 当前不生成 artifact、不定义 `package-linux`、不定义 `publish-github-release`、不创建
  archive、不计算 checksum、不写 manifest、不上传 workflow artifact、不上传 release asset、
  不在本机执行测试、构建、打包或发布。

## 后续工作

- 在 license/NOTICE 人工确认、release CI gate activation、artifact job preflight、build command、
  staging file 和 archive creation gates 激活前，继续保持 `package-linux` 未定义。
- Linux package artifact manifest generation validation contract、Linux package artifact manifest checksum validation contract 和 Linux package workflow artifact bundle upload validation contract 已定义；下一步可以补充 Linux package artifact attestation execution validation contract，仍不发布 release asset。
