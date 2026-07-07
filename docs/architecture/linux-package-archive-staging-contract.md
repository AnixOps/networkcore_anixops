# Linux Package Archive Staging Contract

本文定义首个真实 `package-linux` job 加入 `.github/workflows/release.yml` 前必须遵守的
archive staging、文件来源和顶层目录组装合同。checksum 文件命名、sha256 计算顺序和
manifest 交叉校验边界由 [Linux Package Checksum Manifest Contract](linux-package-checksum-manifest-contract.md)
定义，上传边界由 [Linux Package Publish Upload Boundary Contract](linux-package-publish-upload-boundary-contract.md)
定义，签名/证明边界由 [Linux Package Signing Attestation Policy Binding Contract](linux-package-signing-attestation-policy-binding-contract.md)
定义，release notes/rollback 边界由 [Linux Package Release Notes Rollback Policy Binding Contract](linux-package-release-notes-rollback-policy-binding-contract.md)
定义。当前仍为 placeholder 合同，不定义 `package-linux` job、不构建、不打包、不上传 artifact。

评估时间：2026-07-07。

## 目标

- 固定首个 Linux CLI 压缩包的 staging 目录、输出目录、archive 路径和顶层目录。
- 明确 future `package-linux` job 允许放入压缩包的文件来源和 archive 内路径。
- 确保 manifest `included_files` 能追溯到同一组 staging 输入字段。
- 在 license/NOTICE 人工确认、同 commit CI success gate、checksum/manifest checksum、签名/证明、回滚和 upload gate 完成前继续阻止真实 artifact。

## 非目标

- 不实现 `package-linux` job。
- 不运行 cargo build、不复制二进制、不创建 staging 目录、不创建 archive。
- 不新增 `LICENSE`、`NOTICE`、install script、systemd unit、`.deb`、`.rpm`、AppImage 或 container image。
- 不把 runner 本地绝对路径、Cargo cache、target 目录、测试日志、secret、token、用户配置或环境变量原文写入 manifest。

## Source Of Truth

首个真实 Linux archive staging 输入必须来自本文档、
[Linux Package Artifact Build Command Validation Contract](linux-package-artifact-build-command-validation-contract.md)、
[Linux Package Runner Toolchain Target Contract](linux-package-runner-toolchain-target-contract.md)、
[Linux Package License Notice Transition Validation Contract](linux-package-license-notice-transition-validation-contract.md)
和 release workflow 中的显式常量。不得由 maintainer 在 `workflow_dispatch` 中手动输入
staging 目录、archive 路径或文件来源来绕过门禁。

当前首个 Linux archive staging 固定为：

| 字段 | 值 |
| --- | --- |
| `package_dist_dir` | `dist/linux/${target}` |
| `package_archive_staging_root` | `dist/linux/${target}/staging` |
| `package_top_level_dir` | `networkcore-linux-${version}-${target}` |
| `package_archive_staging_dir` | `dist/linux/${target}/staging/networkcore-linux-${version}-${target}` |
| `package_archive_output_dir` | `dist/linux/${target}/artifacts` |
| `package_archive_name` | `networkcore-linux-${version}-${target}.tar.gz` |
| `package_archive_path` | `dist/linux/${target}/artifacts/networkcore-linux-${version}-${target}.tar.gz` |
| `package_binary_source_path` | `target/${target}/release/networkcore-linux` |
| `package_binary_archive_path` | `bin/networkcore-linux` |
| `package_install_doc_archive_path` | `INSTALL.md` |
| `package_license_source` | `license-notice-confirmed` |
| `package_changelog_source` | `CHANGELOG.md` |

`version` 必须来自 release policy 认可的 release version，`target` 必须等于
`x86_64-unknown-linux-gnu`，除非先更新 runner/toolchain/target contract 和本文档。

## Required Archive Contents

真实 `package-linux` job 必须只把以下文件放入 staging 顶层目录：

| archive path | kind | source | 要求 |
| --- | --- | --- | --- |
| `bin/networkcore-linux` | `binary` | `target/${target}/release/networkcore-linux` | 必须由同一 GitHub Actions release run 构建，且来自 `apps/linux-cli` |
| `INSTALL.md` | `documentation` | repo docs 或 packaging 生成文档 | 必须描述手动解压、运行、卸载和回滚边界 |
| `LICENSE` | `license` | `docs/manual-intervention.md` confirmed 字段指向的 license source | 仅在 license/NOTICE confirmed 后允许进入 archive |
| `NOTICE` | `notice` | confirmed 字段指向的 NOTICE source 或省略 | `notice-source=not-required` 时不得生成伪 NOTICE |
| `CHANGELOG.md` | `changelog` | `CHANGELOG.md` | 必须来自当前 release commit |

archive 内所有路径必须位于单一顶层目录
`networkcore-linux-${version}-${target}/` 下。manifest `included_files` 中的 `path`
必须使用去掉顶层目录后的相对路径，例如 `bin/networkcore-linux`。

## 禁止文件

首个 archive 不得包含：

- 默认配置、用户配置、订阅 URL、token、密码、私钥或证书私钥。
- `target/`、Cargo cache、runner cache、测试日志、coverage 输出或临时目录。
- `docs/` 全量副本、源码树、`.git`、GitHub token response 或 runner 绝对路径。
- systemd unit、shell installer、postinstall script、setcap helper、包管理器 hook。
- 修改 DNS、路由、防火墙、证书信任、service manager 或 capability 的脚本。

如果后续需要加入额外文件，必须先更新本文档、manifest 设计和安装/回滚设计。

## Assembly Order

真实 `package-linux` job 后续必须按以下顺序组装 archive：

1. 确认 license/NOTICE 状态为 `confirmed`，且 `artifact-files` 字段完整。
2. 确认 release CI success source、runner/toolchain/target 和本 staging 合同均已通过。
3. 在 GitHub Actions runner workspace 内创建干净的 `package_dist_dir`。
4. 创建 `package_archive_staging_root`、`package_archive_staging_dir` 和 `package_archive_output_dir`。
5. 从同一 job 的 Rust build output 复制 `package_binary_source_path` 到 `package_binary_archive_path`。
6. 生成或复制 `INSTALL.md`，内容必须承接 Linux CLI artifact installation/rollback design。
7. 复制 confirmed license/NOTICE 文件和 `CHANGELOG.md`。
8. 校验 staging 目录只包含 Required Archive Contents 中允许的路径。
9. 从 `package_archive_staging_root` 的父级创建 `.tar.gz`，确保 archive 只有一个顶层目录。
10. 在 archive 外生成 checksum、sidecar manifest、manifest checksum、signing/attestation 和 rollback 输出。

archive checksum、manifest 和 manifest checksum 都不得放入 archive 内部。

## Rejection Rules

真实 packaging gate 必须拒绝以下情况：

- staging、输出目录、archive 名称或顶层目录缺失。
- archive 没有单一顶层目录，或顶层目录不等于 `package_top_level_dir`。
- `bin/networkcore-linux` 不是当前 GitHub Actions release run 的 build output。
- `LICENSE`/`NOTICE` 来源没有经过 `docs/manual-intervention.md` 的 confirmed 字段确认。
- staging 目录包含禁止文件、额外目录、runner 本地绝对路径、secret 或用户配置。
- archive 路径不在 `package_archive_output_dir` 下。
- manifest `included_files` 与 staging 实际内容不一致。
- job 在 license/NOTICE confirmed、release CI success source、checksum、manifest、signing/attestation 和 rollback gates 完成前上传 artifact。

拒绝时 release workflow 必须失败，并且不得上传 workflow artifact 或 GitHub Release asset。

## Placeholder 行为

当前 release workflow 只能：

- 检查本文档存在和标题。
- 在 `linux-artifact-readiness`、`release-placeholder` 和 release summary 中输出 archive staging 合同。
- 标记 `linux-package-archive-staging-contract=present`。
- 标记 `package-linux=not-defined` 或等价 blocked 状态。
- 继续不定义 `package-linux`。

该 placeholder 只证明 archive staging 合同已被记录，不证明当前 release 已经可以发布 Linux artifact。

## Manifest 映射

真实 manifest 必须映射：

- `archive.relative_path` 等于 `package_archive_path`。
- `artifact_name` 等于 `package_archive_name`。
- `included_files[].path` 必须来自 Required Archive Contents 的 archive path。
- `included_files[].source` 必须来自本文定义的 source 字段或 confirmed license/NOTICE 字段。
- `system_mutation_policy` 必须保持 `none`，除非安装/回滚设计先更新。

manifest 不得写入 runner 本地绝对路径、Cargo cache path、token、GitHub API response 原文、
私钥、配置文件内容或维护者私有信息。

## 验收条件

- 本文档保持在 README、ROADMAP、Release Strategy、Linux artifact 设计、Linux package
  manifest 设计、Linux package checksum manifest contract、Linux package publish/upload boundary
  contract、Linux package signing/attestation policy binding contract、Linux package release notes/rollback
  policy binding contract、Linux package publish eligibility aggregate contract、Linux package artifact job
  preflight validation contract、Linux package artifact build command validation contract、Linux package
  artifact staging file validation contract、Linux CLI artifact 安装/回滚设计、Release CI success source contract、
  Linux package runner/toolchain/target contract、Linux artifact license/NOTICE confirmation source contract
  和 CI policy 中可发现。
- `.github/workflows/ci.yml` governance 检查本文档存在和标题。
- `.github/workflows/release.yml` 的 `linux-artifact-readiness` 检查本文档存在、标题和
  release placeholder/summary 输出字段。
- release placeholder 和 release summary 输出 staging/output/top-level directory、archive
  path、binary source、binary archive path、documentation source、license source 和 changelog source
  合同字段。
- 不生成 artifact、不定义 `package-linux`、不上传 release asset、不在本机执行测试、
  构建、打包或发布。

## 后续工作

- 在 license/NOTICE 人工确认完成前，继续保持 pending marker 并阻止 Linux artifact。
- Linux package checksum manifest contract、publish/upload boundary contract、signing/attestation
  policy binding contract、release notes/rollback policy binding contract、publish eligibility
  aggregate contract、license/NOTICE transition validation contract 和 release CI gate activation validation
  contract 已定义；Linux package artifact job preflight validation contract、Linux package artifact build
  command validation contract、Linux package artifact staging file validation contract、Linux package artifact
  archive creation validation contract 和 Linux package artifact checksum execution validation contract 已定义；
  Linux package artifact manifest generation validation contract、Linux package artifact manifest checksum validation contract 和 Linux package workflow artifact bundle upload validation contract 已定义；下一步可以补充 Linux package artifact attestation execution validation contract，仍不发布 release asset。
