# Linux Package Runner Toolchain Target Contract

本文定义首个真实 `package-linux` job 加入 `.github/workflows/release.yml` 前必须遵守的
runner、Rust toolchain 和 target triple 输入合同。当前仍为 placeholder 合同，不定义
`package-linux` job、不构建、不打包、不上传 artifact。

评估时间：2026-07-07。

## 目标

- 为首个 Linux CLI artifact 固定可审计的 packaging 平台输入。
- 明确后续 `package-linux` job 必须在 GitHub Actions 中声明和输出的 runner、
  Rust toolchain、target triple、crate、binary 和 archive naming 字段。
- 让 release summary、artifact manifest 和后续 publish/upload gate 使用同一组平台输入字段。
- 让 archive staging、checksum/manifest checksum 与 publish/upload boundary 合同复用同一组 version、target、archive name 和顶层目录字段。
- 让 signing/attestation policy binding 合同复用同一组 version、target 和 artifact file set。
- 让 release notes/rollback policy binding 合同复用同一组 version、target、install model 和 artifact naming 字段。
- 在 license/NOTICE 人工确认、同 commit CI success gate、checksum/manifest checksum、签名/证明、回滚和 upload gate 完成前继续阻止真实 artifact。

## 非目标

- 不实现 `package-linux` job。
- 不安装 Rust target、不运行 cargo build、不创建 archive、不计算 checksum。
- 不添加 musl、cross、Docker、`.deb`、`.rpm`、AppImage 或 container image packaging。
- 不把 runner 本地绝对路径、Cargo cache、target 目录、secret、token 或环境变量原文写入 manifest。

## Source Of Truth

首个真实 Linux packaging job 的平台输入必须来自本文件和 release workflow 中的显式常量。
不得由 maintainer 在 `workflow_dispatch` 中手动输入 runner、toolchain 或 target 来绕过门禁。

当前首个 Linux artifact 固定为：

| 字段 | 值 |
| --- | --- |
| `package_runner` | `ubuntu-latest` |
| `package_runner_kind` | `github-hosted` |
| `rust_toolchain` | `stable` |
| `rust_profile` | `minimal` |
| `rust_target_triple` | `x86_64-unknown-linux-gnu` |
| `package_crate` | `apps/linux-cli` |
| `package_binary` | `networkcore-linux` |
| `package_format` | `tar.gz` |
| `package_install_model` | `manual-extract` |
| `package_system_mutation_policy` | `none` |

后续如需要 `x86_64-unknown-linux-musl`、`aarch64-unknown-linux-gnu`、Docker cross build、
受控 self-hosted runner 或发行版包，必须先更新本文档、release strategy、manifest
设计和安装/回滚设计，并通过 CI governance 检查。

## Required Package Inputs

真实 `package-linux` job 必须从 release workflow 自动确定并在 Step Summary、job outputs
和 manifest 中暴露以下字段：

| 字段 | 要求 |
| --- | --- |
| `package_runner` | 必须为 `ubuntu-latest`，除非本文档先更新 |
| `package_runner_kind` | 必须为 `github-hosted` 或后续已批准受控 runner |
| `rust_toolchain` | 必须为 `stable` |
| `rust_profile` | 必须为 `minimal` |
| `rust_target_triple` | 首个 artifact 固定为 `x86_64-unknown-linux-gnu` |
| `package_crate` | 固定为 `apps/linux-cli` |
| `package_binary` | 固定为 `networkcore-linux` |
| `package_format` | 固定为 `tar.gz` |
| `package_archive_name` | `networkcore-linux-${version}-${target}.tar.gz` |
| `package_top_level_dir` | `networkcore-linux-${version}-${target}` |
| `package_dist_dir` | runner workspace 下相对路径，例如 `dist/linux/${target}` |
| `package_install_model` | 固定为 `manual-extract` |
| `package_system_mutation_policy` | 固定为 `none` |

这些字段必须与 [Linux Package Archive Staging Contract](linux-package-archive-staging-contract.md)
中的 staging/output/top-level directory、archive path 和文件来源字段一致，也必须与
[Linux Package Artifact Manifest Design](linux-package-artifact-manifest.md) 中的 manifest
`runner`、`rust_toolchain`、`target_triple`、`artifact_name`、`package_format`、
`install_model` 和 `system_mutation_policy` 一致。

## Rejection Rules

真实 packaging gate 必须拒绝以下情况：

- `package-linux` 未声明 runner、toolchain、target triple、crate、binary 或 archive name。
- runner 不是 `ubuntu-latest`，且本文档没有先批准替代 runner。
- Rust toolchain 不是 `stable`，或 profile 不是 `minimal`。
- target triple 不是 `x86_64-unknown-linux-gnu`，且没有先更新多目标矩阵设计。
- archive 文件名、顶层目录或 manifest target 与 `rust_target_triple` 不一致。
- job 试图从本地构建产物、runner cache、Cargo target 目录或手动上传文件发布 artifact。
- job 在 license/NOTICE `confirmed`、release CI success source、checksum、manifest、signing/attestation 和 rollback gates 完成前上传 artifact。

拒绝时 release workflow 必须失败，并且不得上传 workflow artifact 或 GitHub Release asset。

## Placeholder 行为

当前 release workflow 只能：

- 检查本文档存在和标题。
- 在 `linux-artifact-readiness`、`release-placeholder` 和 release summary 中输出平台输入合同。
- 标记 `linux-package-platform-input-contract=present`。
- 标记 `package-linux=not-defined` 或等价 blocked 状态。
- 继续不定义 `package-linux`。

该 placeholder 只证明平台输入合同已被记录，不证明当前 release 已经可以发布 Linux artifact。

## Artifact Manifest 映射

真实 manifest 必须映射：

- `runner` 等于 `package_runner`。
- `rust_toolchain` 等于本文定义的 `rust_toolchain`。
- `target_triple` 等于 `rust_target_triple`。
- `artifact_name` 等于 `package_archive_name`。
- `package_format` 等于 `package_format`。
- `install_model` 等于 `package_install_model`。
- `system_mutation_policy` 等于 `package_system_mutation_policy`。

manifest 不得写入 runner 本地绝对路径、Cargo cache path、token、GitHub API response 原文、
私钥、配置文件内容或维护者私有信息。

## 验收条件

- 本文档保持在 README、ROADMAP、Release Strategy、Linux artifact 设计、Linux package
  manifest 设计、Linux package artifact job preflight validation contract、Linux package artifact build
  command validation contract、Linux package archive staging contract、Linux package checksum manifest contract、Linux package publish/upload boundary
  contract、Linux package signing/attestation policy binding contract、Linux package release notes/rollback
  policy binding contract、Linux package publish eligibility aggregate contract、Linux package license/NOTICE
  transition validation contract、Linux CLI artifact 安装/回滚设计、Release CI success source contract 和
  CI policy 中可发现。
- `.github/workflows/ci.yml` governance 检查本文档存在和标题。
- `.github/workflows/release.yml` 的 `linux-artifact-readiness` 检查本文档存在、标题和
  release placeholder/summary 输出字段。
- release placeholder 和 release summary 输出 runner/toolchain/target/crate/binary/archive
  naming 合同字段。
- release placeholder 和 release summary 输出的 archive staging 字段必须复用本文档定义的
  `package_archive_name`、`package_top_level_dir` 和 `package_dist_dir`。
- 不生成 artifact、不定义 `package-linux`、不上传 release asset、不在本机执行测试、
  构建、打包或发布。

## 后续工作

- 在 license/NOTICE 人工确认完成前，继续保持 pending marker 并阻止 Linux artifact。
- Linux package archive staging contract、checksum manifest contract、publish/upload boundary contract、
  signing/attestation policy binding contract、release notes/rollback policy binding contract、
  publish eligibility aggregate contract、license/NOTICE transition validation contract、release CI gate
  activation validation contract、artifact job preflight validation contract 和 artifact build command
  validation contract 已定义；下一步可以补充
  Linux package artifact staging file validation contract，仍不生成 artifact。
