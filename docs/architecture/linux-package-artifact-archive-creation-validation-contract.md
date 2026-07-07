# Linux Package Artifact Archive Creation Validation Contract

本文定义首个 Linux `package-linux` job 在未来真实 staging file 校验通过后创建 `.tar.gz`
archive 前必须满足的 archive creation 验证合同。当前仍是 placeholder；本文只固定
archive 名称、路径、单顶层目录、tar 命令形态、失败条件和继续不生成 checksum/manifest
或上传 artifact 的边界，不定义 `package-linux` job、不构建、不复制文件、不创建 staging
目录、不创建 archive、不计算 checksum、不写 manifest、不上传 artifact。

评估时间：2026-07-07。

## 目标

- 固定首个 Linux CLI artifact 的 archive 文件名、输出路径和 `tar.gz` 格式。
- 明确真实 archive 必须只包含一个顶层目录 `networkcore-linux-${version}-${target}/`。
- 让后续 checksum、manifest、signing/attestation、release notes/rollback 和 publish gates
  读取同一组 archive creation 输出字段。
- 在 archive creation gate 未激活时继续阻止 checksum、manifest、workflow artifact 和
  GitHub Release asset。

## 非目标

- 不实现 `package-linux`、`publish-github-release`、`attest-linux`、`sign-linux`、
  `post-release-summary` 或等价 job。
- 不运行 `cargo build`、不复制 staging files、不创建 staging 目录、不运行 `tar`、
  不计算 checksum、不写 manifest、attestation、release notes 或 upload step。
- 不完成 license/NOTICE 人工确认。
- 不启用 release CI gate 的 GitHub API 读取。
- 不把 runner 本地绝对路径、Cargo cache、target 目录、临时路径、secret、token、
  用户配置、环境变量原文、GitHub API response 原文或未公开安全公告细节写入 archive、
  manifest、release notes 或 Step Summary。

## Source Of Truth

首个 Linux package artifact archive creation 输入必须来自本文档、
[Linux Package Artifact Staging File Validation Contract](linux-package-artifact-staging-file-validation-contract.md)、
[Linux Package Archive Staging Contract](linux-package-archive-staging-contract.md)、
[Linux Package Checksum Manifest Contract](linux-package-checksum-manifest-contract.md)、
[Linux Package Artifact Manifest Design](linux-package-artifact-manifest.md)、
[Linux CLI Artifact Installation And Rollback Design](linux-cli-artifact-installation-rollback.md)、
release policy 认可的 version、runner/toolchain/target contract 和 release workflow 中的显式常量。

当前 placeholder 固定为：

| 字段 | 值 |
| --- | --- |
| `package_artifact_archive_creation_contract` | `present` |
| `package_artifact_archive_creation_status` | `blocked-placeholder` |
| `package_artifact_archive_creation_source` | `linux-artifact-readiness` |
| `package_artifact_archive_creation_current_mode` | `contract-only-no-archive` |
| `package_artifact_archive_creation_required_job` | `package-linux` |
| `package_artifact_archive_creation_job_status` | `not-defined` |
| `package_artifact_archive_creation_staging_file_status` | `blocked-placeholder` |
| `package_artifact_archive_creation_staging_root` | `dist/linux/${target}/staging` |
| `package_artifact_archive_creation_staging_dir` | `dist/linux/${target}/staging/networkcore-linux-${version}-${target}` |
| `package_artifact_archive_creation_output_dir` | `dist/linux/${target}/artifacts` |
| `package_artifact_archive_creation_top_level_dir` | `networkcore-linux-${version}-${target}` |
| `package_artifact_archive_creation_archive_name` | `networkcore-linux-${version}-${target}.tar.gz` |
| `package_artifact_archive_creation_archive_path` | `dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.tar.gz` |
| `package_artifact_archive_creation_archive_format` | `tar.gz` |
| `package_artifact_archive_creation_single_top_level_dir` | `required` |
| `package_artifact_archive_creation_required_files` | `bin/networkcore-linux,INSTALL.md,LICENSE,CHANGELOG.md` |
| `package_artifact_archive_creation_optional_files` | `NOTICE` |
| `package_artifact_archive_creation_tar_args` | `-czf,${archive_path},-C,${staging_root},${top_level_dir}` |
| `package_artifact_archive_creation_archive_checksum` | `blocked` |
| `package_artifact_archive_creation_manifest` | `blocked` |
| `package_artifact_archive_creation_upload` | `blocked` |
| `package_artifact_archive_creation_next_action` | `checksum-manifest-after-archive` |

`blocked-placeholder` 表示 release workflow 已记录未来 archive creation 的验证要求，但当前
release 仍不得创建 job、创建 archive、计算 checksum、写 manifest 或上传 artifact。

## Future Archive Command

未来真实 `package-linux` job 必须在 staging file status 为 `complete` 且 staging 目录内容
校验通过后，按以下顺序创建 archive：

```bash
mkdir -p "dist/linux/${target}/artifacts"
tar -czf "dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.tar.gz" \
  -C "dist/linux/${target}/staging" \
  "networkcore-linux-${version}-${target}"
test -f "dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.tar.gz"
test -s "dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.tar.gz"
```

archive content listing 必须满足：

| 规则 | 要求 |
| --- | --- |
| top-level directory | archive 内所有路径必须位于 `networkcore-linux-${version}-${target}/` 下 |
| required files | 必须包含 `bin/networkcore-linux`、`INSTALL.md`、`LICENSE` 和 `CHANGELOG.md` |
| optional NOTICE | license/NOTICE confirmed source 要求 NOTICE 时必须包含，否则不得生成伪 NOTICE |
| forbidden files | 不得包含 `target/`、Cargo cache、`.git`、runner 绝对路径、secret、token、用户配置、测试日志或源码树全量副本 |
| archive location | archive 必须写入 `dist/linux/${target}/artifacts` |
| archive checksum | archive creation gate 不得计算或写入 checksum sidecar |
| manifest | archive creation gate 不得写 manifest |
| upload | archive creation gate 不得上传 workflow artifact 或 release asset |

真实 job 可以使用 runner 自带 `tar`，但必须保持 POSIX 路径和单顶层目录语义。后续如要加入
owner/group、mtime 或 reproducible archive 策略，必须先更新本文档、checksum/manifest 合同和
manifest 设计。

## Failure Boundary

真实 archive creation gate 必须在以下情况失败，并且不得执行 checksum、manifest、
workflow artifact upload 或 release asset upload：

- staging file status 不是 `complete`，或 staging 目录未通过 allowlist 校验。
- license/NOTICE 仍为 pending，或 release CI gate 仍为 placeholder。
- archive name、archive path、output dir、staging root、top-level dir 或 target 与合同不一致。
- `tar` 命令没有使用 `-C ${staging_root} ${top_level_dir}`，导致 archive 内不是单顶层目录。
- archive 缺少 required files，或 NOTICE 处理不符合 confirmed source。
- archive 包含 forbidden files、runner 绝对路径、secret、token、用户配置、源码树全量副本、
  cache、测试日志或 staging 顶层目录之外的路径。
- archive path 不在 `dist/linux/${target}/artifacts` 下。
- archive creation 后直接上传 workflow artifact 或 release asset，绕过 checksum/manifest、
  signing/attestation、release notes/rollback 和 publish eligibility gates。

失败时 release workflow 必须失败在 `package-linux` 内或之前，不得创建 publish job 可消费的 artifact。

## Release Workflow 边界

当前 placeholder release 只能：

- 检查本文档存在和标题。
- 检查本文档包含 current placeholder fields、future archive command、single top-level directory、
  required files、failure boundary 和 checksum/manifest/upload blocked 边界。
- 检查 archive staging contract、staging file validation contract、checksum manifest contract、
  manifest design 和 installation/rollback design 可发现。
- 在 `linux-artifact-readiness`、release placeholder 和 release summary 中输出 archive creation
  validation contract。
- 标记 `linux-package-artifact-archive-creation-contract=present`。
- 标记 `linux-package-artifact-archive-creation-status=blocked-placeholder`。
- 标记 `linux-package-artifact-archive-creation-required-job=package-linux`。
- 标记 `linux-package-artifact-archive-creation-staging-file=blocked-placeholder`。
- 标记 `linux-package-artifact-archive-creation-output-dir=dist/linux/${target}/artifacts`。
- 标记 `linux-package-artifact-archive-creation-top-level-dir=networkcore-linux-${version}-${target}`。
- 标记 `linux-package-artifact-archive-creation-archive-name=networkcore-linux-${version}-${target}.tar.gz`。
- 标记 `linux-package-artifact-archive-creation-archive-path=dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.tar.gz`。
- 标记 `linux-package-artifact-archive-creation-archive-format=tar.gz`。
- 标记 `linux-package-artifact-archive-creation-single-top-level-dir=required`。
- 标记 `linux-package-artifact-archive-creation-required-files=bin/networkcore-linux,INSTALL.md,LICENSE,CHANGELOG.md`。
- 标记 `linux-package-artifact-archive-creation-checksum=blocked`。
- 标记 `linux-package-artifact-archive-creation-manifest=blocked`。
- 标记 `linux-package-artifact-archive-creation-upload=blocked`。
- 标记 `linux-package-artifact-archive-creation-next-action=checksum-manifest-after-archive`。
- 继续不定义 `package-linux`、`publish-github-release`、`attest-linux`、`sign-linux` 或
  `post-release-summary`。

## Manifest Binding

真实 manifest 必须能追溯到 archive creation 输出：

```json
{
  "archive_creation": {
    "contract": "docs/architecture/linux-package-artifact-archive-creation-validation-contract.md",
    "archive_name": "networkcore-linux-v0.1.0-x86_64-unknown-linux-gnu.tar.gz",
    "archive_path": "dist/linux/x86_64-unknown-linux-gnu/artifacts/networkcore-linux-v0.1.0-x86_64-unknown-linux-gnu.tar.gz",
    "archive_format": "tar.gz",
    "top_level_dir": "networkcore-linux-v0.1.0-x86_64-unknown-linux-gnu",
    "single_top_level_dir": true,
    "required_files": [
      "bin/networkcore-linux",
      "INSTALL.md",
      "LICENSE",
      "CHANGELOG.md"
    ]
  }
}
```

manifest 不得写入 runner 本地绝对路径、Cargo cache path、token、secret、GitHub API
response 原文、私钥、用户配置、维护者私有身份或未公开安全公告细节。

## 验收条件

- 本文档保持在 README、ROADMAP、Release Strategy、Linux package artifact staging file validation
  contract、Linux package archive staging contract、Linux package checksum manifest contract、
  Linux package manifest 设计、Linux CLI artifact 安装/回滚设计和 CI policy 中可发现。
- `.github/workflows/ci.yml` governance 检查本文档存在、标题和 release workflow placeholder 输出字段。
- `.github/workflows/release.yml` 的 `linux-artifact-readiness` 检查本文档存在、标题、placeholder
  fields、future archive command、single top-level directory、required files、failure boundary 和
  `package-linux` 未定义状态。
- release placeholder 和 release summary 输出 archive creation status、required job、staging file blocked、
  output dir、top-level dir、archive name/path/format、single top-level dir、required files、
  checksum blocked、manifest blocked、upload blocked 和 next action。
- 当前不生成 artifact、不定义 `package-linux`、不定义 `publish-github-release`、不创建
  staging 目录、不创建 archive、不计算 checksum、不写 manifest、不上传 workflow artifact、
  不上传 release asset、不在本机执行测试、构建、打包或发布。

## 后续工作

- 在 license/NOTICE 人工确认、release CI gate activation、artifact job preflight、build command
  和 staging file gates 激活前，继续保持 `package-linux` 未定义。
- Linux package artifact manifest generation validation contract、Linux package artifact manifest checksum validation contract 和 Linux package workflow artifact bundle upload validation contract 已定义；下一步可以补充 Linux package artifact attestation execution validation contract，仍不发布 release asset。
