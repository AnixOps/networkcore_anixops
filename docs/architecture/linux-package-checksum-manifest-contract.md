# Linux Package Checksum Manifest Contract

> Current activation note: Linux artifact release path is now `linux-artifact-release-state=confirmed-release-path`. `package-linux`, attestation, publish eligibility, and GitHub Release upload are owned by GitHub Actions; any older blocked, not-defined, or current-placeholder wording below describes the historical pre-activation boundary unless a section explicitly states the post-activation state.


本文定义首个真实 `package-linux` job 加入 `.github/workflows/release.yml` 前必须遵守的
archive checksum、manifest checksum、文件命名、计算顺序和交叉校验合同。当前仍为
placeholder 合同，不定义 `package-linux` job、不构建、不打包、不计算 checksum、不上传
artifact。

评估时间：2026-07-07。

## 目标

- 固定首个 Linux CLI archive checksum 与 manifest checksum 的 sidecar 文件命名和路径。
- 明确 `sha256` 计算顺序，避免 manifest 记录未最终确定的 archive 或 checksum。
- 让 release summary、sidecar manifest、checksum 文件和后续 publish gate 使用同一组字段。
- 在 license/NOTICE 人工确认、同 commit CI success gate、签名/证明、回滚和 upload gate
  完成前继续阻止真实 `package-linux` job。

## 非目标

- 不实现 `package-linux` job。
- 不运行 cargo build、不创建 archive、不计算真实 checksum、不写入 manifest 文件。
- 不定义签名、attestation 或 provenance 策略；该策略必须由单独合同声明。
- 不把 runner 本地绝对路径、secret、token、证书私钥、API response 原文或用户配置写入
  manifest 或 checksum 文件。

## Source Of Truth

首个真实 Linux checksum 输入必须来自本文档、
[Linux Package Runner Toolchain Target Contract](linux-package-runner-toolchain-target-contract.md)、
[Linux Package Archive Staging Contract](linux-package-archive-staging-contract.md) 和
[Linux Package Artifact Manifest Design](linux-package-artifact-manifest.md)。不得由 maintainer
在 `workflow_dispatch` 中手动输入 checksum 文件名、checksum 路径或 checksum 值来绕过门禁。

当前首个 Linux checksum/manifest checksum 固定为：

| 字段 | 值 |
| --- | --- |
| `package_checksum_algorithm` | `sha256` |
| `package_archive_name` | `networkcore-linux-${version}-${target}.tar.gz` |
| `package_archive_path` | `dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.tar.gz` |
| `package_archive_checksum_name` | `networkcore-linux-${version}-${target}.tar.gz.sha256` |
| `package_archive_checksum_path` | `dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.tar.gz.sha256` |
| `package_manifest_name` | `networkcore-linux-${version}-${target}.manifest.json` |
| `package_manifest_path` | `dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.manifest.json` |
| `package_manifest_checksum_name` | `networkcore-linux-${version}-${target}.manifest.json.sha256` |
| `package_manifest_checksum_path` | `dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.manifest.json.sha256` |
| `package_checksum_record_format` | `<sha256><two spaces><file-name>` |
| `package_manifest_archive_file_field` | `archive.file_name` |
| `package_manifest_checksum_algorithm_field` | `checksum.algorithm` |
| `package_manifest_archive_checksum_field` | `checksum.value` |

`version` 必须来自 release policy 认可的 release version，`target` 必须等于
`x86_64-unknown-linux-gnu`，除非先更新 runner/toolchain/target、archive staging、manifest 和
本文档。

## Checksum 文件格式

archive checksum 文件必须只包含一行 POSIX `sha256sum` 风格记录：

```text
<archive-sha256>  networkcore-linux-${version}-${target}.tar.gz
```

manifest checksum 文件必须只包含一行 POSIX `sha256sum` 风格记录：

```text
<manifest-sha256>  networkcore-linux-${version}-${target}.manifest.json
```

记录规则：

- digest 必须是 64 位小写十六进制 `sha256`。
- digest 与文件名之间必须是两个 ASCII 空格。
- 文件名必须是 basename，不得包含 `/`、`..`、runner workspace、绝对路径或 URL。
- checksum 文件必须位于 `dist/linux/${target}/artifacts`，且不得放入 archive 内部。
- checksum 文件不得包含多行、注释、shell 命令、JSON、YAML 或额外 metadata。

## 计算顺序

真实 `package-linux` job 后续必须按以下顺序生成和校验 checksum/manifest：

1. 确认 license/NOTICE 状态为 `confirmed`。
2. 确认 release CI success source、runner/toolchain/target、archive staging、manifest 和本文合同均已通过。
3. 按 archive staging contract 创建最终 `.tar.gz` archive。
4. 对最终 archive bytes 计算 `sha256`。
5. 写入 archive checksum sidecar 文件。
6. 生成 manifest JSON，并写入 archive 文件名、archive 相对路径、checksum algorithm 和 archive checksum value。
7. 交叉校验 manifest 中的 archive 文件名和 checksum 字段与 archive checksum sidecar 完全一致。
8. 对最终 manifest JSON bytes 计算 `sha256`。
9. 写入 manifest checksum sidecar 文件。
10. 交叉校验 manifest checksum sidecar 文件名、路径和 digest。
11. 输出 archive、archive checksum、manifest 和 manifest checksum 字段到 job outputs 与 Step Summary。
12. 只有后续 signing/attestation、rollback、license/NOTICE 和 publish/upload gates 全部通过后，publish job 才能上传。

manifest 不得反向参与 archive checksum。archive checksum 只覆盖 `.tar.gz` bytes；
manifest checksum 只覆盖最终 manifest JSON bytes。

## Manifest 交叉校验

真实 packaging gate 必须读取或生成结构化 manifest，并校验：

| Manifest 字段 | 必须匹配 |
| --- | --- |
| `archive.file_name` | `package_archive_name` |
| `archive.relative_path` | `package_archive_path` |
| `checksum.algorithm` | `package_checksum_algorithm` |
| `checksum.file_name` | `package_archive_checksum_name` |
| `checksum.value` | archive checksum sidecar 中的 digest |
| job output `artifact_name` | `package_archive_name` |
| job output `checksum_file` | `package_archive_checksum_path` |
| job output `checksum_value` | `checksum.value` |
| job output `artifact_manifest_name` | `package_manifest_name` |
| job output `artifact_manifest_path` | `package_manifest_path` |
| job output `artifact_manifest_checksum_file` | `package_manifest_checksum_path` |
| job output `artifact_manifest_checksum_value` | manifest checksum sidecar 中的 digest |

manifest JSON 必须在计算 manifest checksum 前完成稳定序列化。真实 job 必须避免在 manifest
checksum 生成后继续修改 manifest。

## Rejection Rules

真实 packaging gate 必须拒绝以下情况：

- checksum algorithm 不是 `sha256`。
- archive checksum 或 manifest checksum 文件名、路径与本文档不一致。
- checksum 文件记录包含绝对路径、相对目录、URL、多行内容或额外 metadata。
- archive checksum 在 archive 最终完成前计算，或 manifest checksum 在 manifest 最终完成前计算。
- manifest 缺少 `archive.file_name`、`archive.relative_path`、`checksum.algorithm`、
  `checksum.file_name` 或 `checksum.value`。
- manifest 中 archive 文件名、路径、checksum algorithm 或 checksum value 与 checksum sidecar 不一致。
- job outputs 与 manifest 或 checksum sidecar 不一致。
- job 在 license/NOTICE confirmed、release CI success source、checksum/manifest checksum、
  signing/attestation、rollback 和 upload gates 完成前上传 workflow artifact 或 GitHub Release asset。

拒绝时 release workflow 必须失败，并且不得上传 workflow artifact 或 GitHub Release asset。

## Placeholder 行为

当前 release workflow 只能：

- 检查本文档存在和标题。
- 在 `linux-artifact-readiness`、`release-placeholder` 和 release summary 中输出 checksum/manifest
  checksum 合同。
- 标记 `linux-package-checksum-manifest-contract=present`。
- 标记 `package-linux=not-defined` 或等价 blocked 状态。
- 继续不定义 `package-linux`。

该 placeholder 只证明 checksum/manifest checksum 合同已被记录，不证明当前 release 已经可以
发布 Linux artifact。

## 验收条件

- 本文档保持在 README、ROADMAP、Release Strategy、Linux artifact 设计、Linux package
  manifest 设计、Linux package publish/upload boundary contract、Linux CLI artifact 安装/回滚设计、
  Linux package signing/attestation policy binding contract、Linux package release notes/rollback
  policy binding contract、Linux package publish eligibility aggregate contract、Release CI success source contract、
  Linux package artifact job preflight validation contract、Linux package runner/toolchain/target contract、
  Linux package archive staging contract、Linux artifact license/NOTICE confirmation source contract、
  [Linux Package Artifact Manifest Checksum Validation Contract](linux-package-artifact-manifest-checksum-validation-contract.md)
  和 CI policy 中可发现。
- `.github/workflows/ci.yml` governance 检查本文档存在和标题。
- `.github/workflows/release.yml` 的 `linux-artifact-readiness` 检查本文档存在、标题和
  release placeholder/summary 输出字段。
- release placeholder 和 release summary 输出 archive checksum name/path、manifest name/path、
  manifest checksum name/path、checksum record format 和 manifest cross-check 字段。
- 不生成 artifact、不定义 `package-linux`、不上传 release asset、不在本机执行测试、
  构建、打包或发布。

## 后续工作

- 当前 Linux artifact release state 为 `linux-artifact-release-state=confirmed-release-path`；后续 tag release 继续通过 release workflow 门禁。
- Linux package publish/upload boundary contract、signing/attestation policy binding contract、
  release notes/rollback policy binding contract、publish eligibility aggregate contract 和
  license/NOTICE transition validation contract、release CI gate activation validation contract 已定义；
  Linux package artifact job preflight validation contract、Linux package artifact build command validation contract、Linux package artifact staging file validation contract、Linux package artifact archive creation validation contract 和 Linux package artifact checksum execution validation contract 已定义；Linux package artifact manifest generation validation contract、Linux package artifact manifest checksum validation contract、Linux package workflow artifact bundle upload validation contract、Linux package artifact attestation execution validation contract、Linux package release notes/rollback execution validation contract 和 Linux package publish eligibility execution validation contract 已定义；release CI gate execution validation contract 和 release CI gate API implementation 已激活；当前 license/NOTICE 和 artifact gates 已进入 confirmed release path；后续 tag release 继续通过 release workflow、同 commit CI、checksum、manifest、attestation、release notes、rollback 和 publish eligibility gates 生成和发布 Linux assets。
