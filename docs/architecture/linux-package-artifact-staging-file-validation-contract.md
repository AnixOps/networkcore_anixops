# Linux Package Artifact Staging File Validation Contract

本文定义首个 Linux `package-linux` job 在未来真实 copy 文件进入 staging 目录前必须满足的
staging file 验证合同。当前仍是 placeholder；本文只固定 build output、INSTALL、
LICENSE/NOTICE 和 CHANGELOG 的复制来源、目标路径、权限校验、失败条件和继续不创建
archive 的边界，不定义 `package-linux` job、不构建、不复制文件、不创建 staging 目录、
不打包、不上传 artifact。

评估时间：2026-07-07。

## 目标

- 固定首个 Linux CLI artifact 进入 staging 目录的文件清单和复制顺序。
- 明确 binary、INSTALL、LICENSE/NOTICE 和 CHANGELOG 的 source/destination/permission
  校验边界。
- 防止 maintainer 从本地文件、旧 workflow artifact、runner cache、临时目录或手写 summary
  绕过 build command、license/NOTICE、archive staging 和 manifest gates。
- 在 staging file gate 未激活时继续阻止 archive、checksum、manifest、workflow artifact 和
  GitHub Release asset。

## 非目标

- 不实现 `package-linux`、`publish-github-release`、`attest-linux`、`sign-linux`、
  `post-release-summary` 或等价 job。
- 不运行 `cargo build`、不复制二进制、不生成 `INSTALL.md`、不复制 `LICENSE`/`NOTICE`、
  不创建 staging 目录、不创建 archive、checksum、manifest、attestation、release notes
  或 upload step。
- 不完成 license/NOTICE 人工确认。
- 不启用 release CI gate 的 GitHub API 读取。
- 不把 runner 本地绝对路径、Cargo cache、target 目录、临时路径、secret、token、
  用户配置、环境变量原文、GitHub API response 原文或未公开安全公告细节写入 manifest、
  release notes 或 Step Summary。

## Source Of Truth

首个 Linux package artifact staging file 输入必须来自本文档、
[Linux Package Artifact Job Preflight Validation Contract](linux-package-artifact-job-preflight-validation-contract.md)、
[Linux Package Artifact Build Command Validation Contract](linux-package-artifact-build-command-validation-contract.md)、
[Linux Package Archive Staging Contract](linux-package-archive-staging-contract.md)、
[Linux Package License Notice Transition Validation Contract](linux-package-license-notice-transition-validation-contract.md)、
[Linux CLI Artifact Installation And Rollback Design](linux-cli-artifact-installation-rollback.md)、
[Linux Package Artifact Manifest Design](linux-package-artifact-manifest.md)、
`CHANGELOG.md`、`docs/manual-intervention.md` 和 release workflow 中的显式常量。

当前 placeholder 固定为：

| 字段 | 值 |
| --- | --- |
| `package_artifact_staging_file_contract` | `present` |
| `package_artifact_staging_file_status` | `blocked-placeholder` |
| `package_artifact_staging_file_source` | `linux-artifact-readiness` |
| `package_artifact_staging_file_current_mode` | `contract-only-no-staging-copy` |
| `package_artifact_staging_file_required_job` | `package-linux` |
| `package_artifact_staging_file_job_status` | `not-defined` |
| `package_artifact_staging_file_preflight_status` | `blocked-placeholder` |
| `package_artifact_staging_file_build_command_status` | `blocked-placeholder` |
| `package_artifact_staging_file_staging_root` | `dist/linux/${target}/staging` |
| `package_artifact_staging_file_staging_dir` | `dist/linux/${target}/staging/networkcore-linux-${version}-${target}` |
| `package_artifact_staging_file_binary_source` | `target/${target}/release/networkcore-linux` |
| `package_artifact_staging_file_binary_destination` | `bin/networkcore-linux` |
| `package_artifact_staging_file_binary_permission` | `0755` |
| `package_artifact_staging_file_install_doc_source` | `generated-from-linux-cli-artifact-installation-rollback` |
| `package_artifact_staging_file_install_doc_destination` | `INSTALL.md` |
| `package_artifact_staging_file_license_source` | `license-notice-confirmed` |
| `package_artifact_staging_file_license_destination` | `LICENSE` |
| `package_artifact_staging_file_notice_source` | `confirmed-notice-or-not-required` |
| `package_artifact_staging_file_changelog_source` | `CHANGELOG.md` |
| `package_artifact_staging_file_changelog_destination` | `CHANGELOG.md` |
| `package_artifact_staging_file_archive_creation` | `blocked` |
| `package_artifact_staging_file_upload` | `blocked` |
| `package_artifact_staging_file_next_action` | `license-notice-ci-build-before-staging` |

`blocked-placeholder` 表示 release workflow 已记录未来 staging file 的验证要求，但当前
release 仍不得创建 job、复制文件、创建 staging 目录或生成 archive。

## Future Staging File Copy

未来真实 `package-linux` job 必须在 preflight active、build command complete、binary path
check passed 后，按以下顺序处理 staging files：

```bash
mkdir -p "dist/linux/${target}/staging/networkcore-linux-${version}-${target}/bin"
install -m 0755 "target/${target}/release/networkcore-linux" \
  "dist/linux/${target}/staging/networkcore-linux-${version}-${target}/bin/networkcore-linux"
install -m 0644 "${generated_install_doc}" \
  "dist/linux/${target}/staging/networkcore-linux-${version}-${target}/INSTALL.md"
install -m 0644 "${confirmed_license_source}" \
  "dist/linux/${target}/staging/networkcore-linux-${version}-${target}/LICENSE"
install -m 0644 "CHANGELOG.md" \
  "dist/linux/${target}/staging/networkcore-linux-${version}-${target}/CHANGELOG.md"
```

如果 `notice_source` 为 confirmed repo file，必须额外复制到
`dist/linux/${target}/staging/networkcore-linux-${version}-${target}/NOTICE`，权限为 `0644`。
如果 `notice_source=not-required`，不得生成伪 NOTICE 文件。

字段规则：

| 字段 | 要求 |
| --- | --- |
| staging root/dir | 必须与 archive staging contract 完全一致，且在 copy 前保持干净 |
| binary source | 必须来自同一 `package-linux` job 的 build output，不能来自 cache 或旧 run artifact |
| binary destination | 必须为 `bin/networkcore-linux`，权限 `0755`，不是目录或 symlink 到 staging 外部 |
| INSTALL.md | 必须由 repo design 生成或复制，描述 manual-extract、uninstall 和 rollback 边界 |
| LICENSE | 必须来自 license/NOTICE confirmed 字段指向的 repo 文件，权限 `0644` |
| NOTICE | 仅在 confirmed source 存在时复制；not-required 时不得创建 placeholder |
| CHANGELOG.md | 必须来自当前 release checkout 的 `CHANGELOG.md`，权限 `0644` |
| archive creation | staging file gate 不得直接创建 `.tar.gz` |
| upload | staging file gate 不得上传 workflow artifact 或 release asset |

## Failure Boundary

真实 staging file gate 必须在以下情况失败，并且不得执行 archive、checksum、manifest、
workflow artifact upload 或 release asset upload：

- preflight status 不是 `active`，或 build command status 不是 `complete`。
- license/NOTICE 仍为 pending，或 release CI gate 仍为 placeholder。
- staging root、staging dir、top-level dir、binary source 或 archive path 与 archive staging
  contract 不一致。
- binary source 不存在、不可执行、不是普通文件、是 workspace 外 symlink，或不是当前 release
  run build step 生成。
- binary destination 不是 `bin/networkcore-linux`，权限不是 `0755`，或路径逃逸顶层目录。
- INSTALL、LICENSE、NOTICE 或 CHANGELOG 的来源缺失、未确认、权限错误、路径逃逸或来自
  runner/local 临时文件。
- staging 目录包含 Required Archive Contents 之外的文件、`target/`、Cargo cache、`.git`、
  secret、token、用户配置、测试日志、runner 绝对路径或源码树全量副本。
- staging file copy 后直接创建 archive、checksum、manifest 或 upload，绕过后续 archive
  creation、checksum/manifest、signing/attestation、release notes/rollback 和 publish
  eligibility gates。

失败时 release workflow 必须失败在 `package-linux` 内或之前，不得创建 publish job 可消费的 artifact。

## Release Workflow 边界

当前 placeholder release 只能：

- 检查本文档存在和标题。
- 检查本文档包含 current placeholder fields、future staging file copy、binary permission、
  failure boundary 和 archive creation blocked 边界。
- 检查 `CHANGELOG.md`、Linux CLI artifact installation/rollback design、archive staging
  contract 和 license/NOTICE transition contract 可发现。
- 在 `linux-artifact-readiness`、release placeholder 和 release summary 中输出 staging file
  validation contract。
- 标记 `linux-package-artifact-staging-file-contract=present`。
- 标记 `linux-package-artifact-staging-file-status=blocked-placeholder`。
- 标记 `linux-package-artifact-staging-file-required-job=package-linux`。
- 标记 `linux-package-artifact-staging-file-preflight=blocked-placeholder`。
- 标记 `linux-package-artifact-staging-file-build-command=blocked-placeholder`。
- 标记 `linux-package-artifact-staging-file-binary-source=target/${target}/release/networkcore-linux`。
- 标记 `linux-package-artifact-staging-file-binary-destination=bin/networkcore-linux`。
- 标记 `linux-package-artifact-staging-file-binary-permission=0755`。
- 标记 `linux-package-artifact-staging-file-install-doc=INSTALL.md`。
- 标记 `linux-package-artifact-staging-file-license-source=license-notice-confirmed`。
- 标记 `linux-package-artifact-staging-file-changelog-source=CHANGELOG.md`。
- 标记 `linux-package-artifact-staging-file-archive-creation=blocked`。
- 标记 `linux-package-artifact-staging-file-upload=blocked`。
- 标记 `linux-package-artifact-staging-file-next-action=license-notice-ci-build-before-staging`。
- 继续不定义 `package-linux`、`publish-github-release`、`attest-linux`、`sign-linux` 或
  `post-release-summary`。

## Manifest Binding

真实 manifest 的 `included_files` 必须能追溯到 staging file copy 输出：

```json
{
  "staging_files": {
    "contract": "docs/architecture/linux-package-artifact-staging-file-validation-contract.md",
    "staging_root": "dist/linux/x86_64-unknown-linux-gnu/staging",
    "staging_dir": "dist/linux/x86_64-unknown-linux-gnu/staging/networkcore-linux-v0.1.0-x86_64-unknown-linux-gnu",
    "files": [
      {
        "path": "bin/networkcore-linux",
        "source": "target/x86_64-unknown-linux-gnu/release/networkcore-linux",
        "mode": "0755"
      },
      {
        "path": "INSTALL.md",
        "source": "generated-from-linux-cli-artifact-installation-rollback",
        "mode": "0644"
      },
      {
        "path": "LICENSE",
        "source": "license-notice-confirmed",
        "mode": "0644"
      },
      {
        "path": "CHANGELOG.md",
        "source": "CHANGELOG.md",
        "mode": "0644"
      }
    ]
  }
}
```

manifest 不得写入 runner 本地绝对路径、Cargo cache path、token、secret、GitHub API
response 原文、私钥、用户配置、维护者私有身份或未公开安全公告细节。

## 验收条件

- 本文档保持在 README、ROADMAP、Release Strategy、Linux package artifact job preflight
  validation contract、Linux package artifact build command validation contract、Linux package
  archive staging contract、Linux package manifest 设计、Linux CLI artifact 安装/回滚设计和
  CI policy 中可发现。
- `.github/workflows/ci.yml` governance 检查本文档存在、标题和 release workflow placeholder 输出字段。
- `.github/workflows/release.yml` 的 `linux-artifact-readiness` 检查本文档存在、标题、placeholder
  fields、future staging file copy、binary permission、failure boundary 和 `package-linux`
  未定义状态。
- release placeholder 和 release summary 输出 staging file status、required job、preflight blocked、
  build command blocked、binary source/destination/permission、INSTALL、LICENSE、CHANGELOG、
  archive creation blocked、upload blocked 和 next action。
- 当前不生成 artifact、不定义 `package-linux`、不定义 `publish-github-release`、不创建
  staging 目录、不创建 archive、不上传 workflow artifact、不上传 release asset、不在本机
  执行测试、构建、打包或发布。

## 后续工作

- 在 license/NOTICE 人工确认、release CI gate activation、artifact job preflight 和 build
  command 激活前，继续保持 `package-linux` 未定义。
- Linux package artifact archive creation validation contract 和 Linux package artifact checksum execution validation contract 已定义；Linux package artifact manifest generation validation contract、Linux package artifact manifest checksum validation contract、Linux package workflow artifact bundle upload validation contract、Linux package artifact attestation execution validation contract、Linux package release notes/rollback execution validation contract 和 Linux package publish eligibility execution validation contract 已定义；release CI gate execution validation contract 已定义；下一步可以补充 release CI gate API implementation plan，仍不发布 release asset。
