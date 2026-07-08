# Linux Package Artifact Manifest Checksum Validation Contract

> Current activation note: Linux artifact release path is now `linux-artifact-release-state=confirmed-release-path`. `package-linux`, attestation, publish eligibility, and GitHub Release upload are owned by GitHub Actions; any older blocked, not-defined, or current-placeholder wording below describes the historical pre-activation boundary unless a section explicitly states the post-activation state.


本文定义首个 Linux `package-linux` job 在未来 artifact manifest JSON 稳定写入后计算
manifest checksum sidecar 前必须满足的验证合同。当前仍是 placeholder；本文只固定
manifest checksum 文件名、路径、算法、record format、校验顺序和继续不上传 artifact 的边界，
不定义 `package-linux` job、不构建、不复制文件、不创建 archive、不计算 archive checksum、
不写 manifest、不计算 manifest checksum、不上传 artifact。

评估时间：2026-07-07。

## 目标

- 固定首个 Linux CLI artifact manifest checksum sidecar 的文件名、路径、算法和 `sha256sum`
  两空格文件名格式。
- 明确 manifest checksum 只能在 manifest JSON 稳定序列化、写入并校验完成后计算。
- 防止 maintainer 使用旧 manifest、绝对路径 checksum record、多行 sidecar、URL、runner cache
  或本地产物绕过 artifact integrity gates。
- 在 manifest checksum gate 未激活时继续阻止 workflow artifact upload 和 GitHub Release asset upload。

## 非目标

- 不实现 `package-linux`、`publish-github-release`、`attest-linux`、`sign-linux`、
  `post-release-summary` 或等价 job。
- 不运行 `cargo build`、不复制 staging files、不创建 archive、不运行 `sha256sum`、
  不写 archive checksum sidecar、不写 manifest JSON、不写 manifest checksum sidecar、
  不生成 attestation、release notes 或 upload step。
- 不完成 license/NOTICE 人工确认。
- 不把 runner 本地绝对路径、Cargo cache、target 目录、临时路径、secret、token、
  用户配置、环境变量原文、GitHub API response 原文或未公开安全公告细节写入 manifest、
  checksum sidecar、release notes 或 Step Summary。

## Source Of Truth

首个 Linux package artifact manifest checksum 输入必须来自本文档、
[Linux Package Artifact Manifest Generation Validation Contract](linux-package-artifact-manifest-generation-validation-contract.md)、
[Linux Package Artifact Manifest Design](linux-package-artifact-manifest.md)、
[Linux Package Checksum Manifest Contract](linux-package-checksum-manifest-contract.md)、
[Linux Package Artifact Checksum Execution Validation Contract](linux-package-artifact-checksum-execution-validation-contract.md)、
[Linux Package Publish Upload Boundary Contract](linux-package-publish-upload-boundary-contract.md)、
[Linux Package Workflow Artifact Bundle Upload Validation Contract](linux-package-workflow-artifact-bundle-upload-validation-contract.md)、
release policy 认可的 version、runner/toolchain/target contract 和 release workflow 中的显式常量。

当前 placeholder 固定为：

| 字段 | 值 |
| --- | --- |
| `package_artifact_manifest_checksum_contract` | `present` |
| `package_artifact_manifest_checksum_status` | `blocked-placeholder` |
| `package_artifact_manifest_checksum_source` | `linux-artifact-readiness` |
| `package_artifact_manifest_checksum_current_mode` | `contract-only-no-manifest-checksum` |
| `package_artifact_manifest_checksum_required_job` | `package-linux` |
| `package_artifact_manifest_checksum_job_status` | `not-defined` |
| `package_artifact_manifest_checksum_manifest_generation_status` | `blocked-placeholder` |
| `package_artifact_manifest_checksum_algorithm` | `sha256` |
| `package_artifact_manifest_checksum_manifest_name` | `networkcore-linux-${version}-${target}.manifest.json` |
| `package_artifact_manifest_checksum_manifest_path` | `dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.manifest.json` |
| `package_artifact_manifest_checksum_name` | `networkcore-linux-${version}-${target}.manifest.json.sha256` |
| `package_artifact_manifest_checksum_path` | `dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.manifest.json.sha256` |
| `package_artifact_manifest_checksum_record_format` | `sha256sum-two-space-file-name` |
| `package_artifact_manifest_checksum_value` | `blocked-before-manifest` |
| `package_artifact_manifest_checksum_file_write` | `blocked` |
| `package_artifact_manifest_checksum_workflow_artifact` | `blocked` |
| `package_artifact_manifest_checksum_release_asset` | `blocked` |
| `package_artifact_manifest_checksum_upload` | `blocked` |
| `package_artifact_manifest_checksum_next_action` | `workflow-artifact-upload-after-manifest-checksum` |

`blocked-placeholder` 表示 release workflow 已记录未来 manifest checksum 的验证要求，但当前
release 仍不得创建 job、写 manifest checksum sidecar、上传 workflow artifact 或上传 release asset。

## Future Manifest Checksum Command

未来真实 `package-linux` job 必须在 manifest generation status 为 `complete` 且 manifest JSON
稳定序列化完成后，按以下顺序计算 manifest checksum sidecar：

```bash
manifest_name="networkcore-linux-${version}-${target}.manifest.json"
manifest_path="dist/linux/${target}/artifacts/${manifest_name}"
manifest_checksum_path="dist/linux/${target}/artifacts/${manifest_name}.sha256"
manifest_digest="$(sha256sum "${manifest_path}" | awk '{print $1}')"
printf '%s  %s\n' "${manifest_digest}" "${manifest_name}" > "${manifest_checksum_path}"
grep -Eq "^[0-9a-f]{64}  ${manifest_name}$" "${manifest_checksum_path}"
```

字段规则：

| 字段 | 要求 |
| --- | --- |
| manifest checksum algorithm | 固定为 `sha256` |
| manifest checksum file | 必须位于 `dist/linux/${target}/artifacts`，不得放入 archive 内部 |
| manifest checksum name | 固定为 `networkcore-linux-${version}-${target}.manifest.json.sha256` |
| manifest checksum record | 固定为 `<manifest-sha256>  networkcore-linux-${version}-${target}.manifest.json` |
| spacing | digest 和文件名之间必须恰好两个 ASCII 空格 |
| digest | 必须是 64 位小写十六进制 SHA-256 digest |
| record target | 必须只包含 manifest 文件名，不得包含目录、绝对路径、URL 或 shell expansion |
| file content | sidecar 必须只有一行 checksum record，并以 newline 结尾 |
| workflow artifact | manifest checksum gate 不得上传 workflow artifact |
| release asset | manifest checksum gate 不得上传 GitHub Release asset |

## Failure Boundary

真实 manifest checksum gate 必须在以下情况失败，并且不得执行 workflow artifact upload 或
release asset upload：

- manifest generation status 不是 `complete`。
- license/NOTICE 仍为 pending，或 release CI gate 不是 active。
- manifest JSON 不存在、为空、不是普通文件，或路径不等于
  `dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.manifest.json`。
- manifest 在计算 checksum 前仍可能被后续步骤修改，或 checksum 在稳定序列化完成前计算。
- manifest checksum name/path 与本文档不一致。
- manifest digest 不是 64 位小写十六进制 SHA-256。
- sidecar record 不是 `sha256sum-two-space-file-name` 格式。
- sidecar record 使用一个空格、tab、多个文件名、目录、绝对路径、URL、glob、shell expansion、
  多行 metadata、runner workspace 或本地临时路径。
- sidecar 写入后 manifest 被修改，或 sidecar digest 与最终 manifest 内容不一致。
- manifest checksum 后直接上传 workflow artifact 或 release asset，绕过 workflow artifact
  bundle validation、signing/attestation、release notes/rollback 和 publish eligibility gates。

失败时 release workflow 必须失败在 `package-linux` 内或之前，不得创建 publish job 可消费的 artifact。

## Release Workflow 边界

当前 placeholder release 只能：

- 检查本文档存在和标题。
- 检查本文档包含 current placeholder fields、record format、checksum path、future manifest
  checksum command、failure boundary 和 upload blocked 边界。
- 检查 manifest generation contract、checksum manifest contract、manifest design 和 publish/upload
  boundary contract 可发现。
- 在 `linux-artifact-readiness`、release placeholder 和 release summary 中输出 manifest checksum
  validation contract。
- 标记 `linux-package-artifact-manifest-checksum-contract=present`。
- 标记 `linux-package-artifact-manifest-checksum-status=blocked-placeholder`。
- 标记 `linux-package-artifact-manifest-checksum-required-job=package-linux`。
- 标记 `linux-package-artifact-manifest-checksum-manifest-generation=blocked-placeholder`。
- 标记 `linux-package-artifact-manifest-checksum-algorithm=sha256`。
- 标记 `linux-package-artifact-manifest-checksum-manifest-name=networkcore-linux-${version}-${target}.manifest.json`。
- 标记 `linux-package-artifact-manifest-checksum-manifest-path=dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.manifest.json`。
- 标记 `linux-package-artifact-manifest-checksum-checksum-name=networkcore-linux-${version}-${target}.manifest.json.sha256`。
- 标记 `linux-package-artifact-manifest-checksum-checksum-path=dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.manifest.json.sha256`。
- 标记 `linux-package-artifact-manifest-checksum-record-format=sha256sum-two-space-file-name`。
- 标记 `linux-package-artifact-manifest-checksum-checksum-value=blocked-before-manifest`。
- 标记 `linux-package-artifact-manifest-checksum-checksum-file-write=blocked`。
- 标记 `linux-package-artifact-manifest-checksum-workflow-artifact=blocked`。
- 标记 `linux-package-artifact-manifest-checksum-release-asset=blocked`。
- 标记 `linux-package-artifact-manifest-checksum-upload=blocked`。
- 标记 `linux-package-artifact-manifest-checksum-next-action=workflow-artifact-upload-after-manifest-checksum`。
- 继续不定义 `package-linux`、`publish-github-release`、`attest-linux`、`sign-linux` 或
  `post-release-summary`。

## Checksum Binding

真实 manifest checksum sidecar 必须只绑定最终 manifest JSON：

```text
<manifest-sha256>  networkcore-linux-v0.1.0-x86_64-unknown-linux-gnu.manifest.json
```

示例不是当前 artifact 事实；真实 job 必须写入 release run 的实际 version、target 和 digest。

## 验收条件

- 本文档保持在 README、ROADMAP、Release Strategy、Linux package artifact manifest generation
  validation contract、Linux package checksum manifest contract、Linux package manifest 设计、
  Linux package publish/upload boundary contract、Linux package workflow artifact bundle upload
  validation contract、Linux CLI artifact 安装/回滚设计和 CI policy 中可发现。
- `.github/workflows/ci.yml` governance 检查本文档存在、标题、record format、checksum path、
  future manifest checksum command 和 release workflow placeholder 输出字段。
- `.github/workflows/release.yml` 的 `linux-artifact-readiness` 检查本文档存在、标题、placeholder
  fields、record format、checksum path、future manifest checksum command、failure boundary 和
  `package-linux` 未定义状态。
- release placeholder 和 release summary 输出 manifest checksum status、required job、manifest
  generation blocked、algorithm、manifest name/path、checksum name/path、record format、checksum
  value blocked、checksum file write blocked、workflow artifact blocked、release asset blocked、
  upload blocked 和 next action。
- 当前不生成 artifact、不定义 `package-linux`、不定义 `publish-github-release`、不创建 archive、
  不计算 archive checksum、不写 manifest、不计算 manifest checksum、不上传 workflow artifact、
  不上传 release asset、不在本机执行测试、构建、打包或发布。

## 后续工作

- 在 license/NOTICE 人工确认、release CI gate activation、artifact job preflight、build command、
  staging file、archive creation、checksum execution、manifest generation 和 manifest checksum gates
  激活前，继续保持 `package-linux` 未定义。
- Linux package workflow artifact bundle upload validation contract 已定义；下一步可以补充 Linux
  package artifact attestation execution validation contract，明确 workflow artifact bundle 上传后对
  archive、archive checksum、manifest 和 manifest checksum 生成 GitHub artifact attestation/provenance、
  拒绝旧 run/外部 artifact 和仍不发布 GitHub Release asset 的边界。
