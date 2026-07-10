# Linux Package Artifact Manifest Design

> Current activation note: Linux artifact release path is now `linux-artifact-release-state=confirmed-release-path`. `package-linux`, attestation, publish eligibility, and GitHub Release upload are owned by GitHub Actions; any older blocked, not-defined, or current-placeholder wording below describes the historical pre-activation boundary unless a section explicitly states the post-activation state.


本文定义首个 Linux `package-linux` job 在真实生成 artifact 前必须遵守的
artifact manifest 和 metadata 输出合同。它承接
[Linux Artifact Pre-Release Design](linux-artifact-pre-release-design.md)、
[Linux CLI Artifact Installation And Rollback Design](linux-cli-artifact-installation-rollback.md)、
[Linux Artifact License Notice Confirmation Design](linux-artifact-license-notice-confirmation.md)、
[Linux Package License Notice Transition Validation Contract](linux-package-license-notice-transition-validation-contract.md)、
[Release CI Success Source Contract](release-ci-success-source-contract.md)、
[Linux Package Release CI Gate Activation Validation Contract](linux-package-release-ci-gate-activation-validation-contract.md)、[Release CI Gate Execution Validation Contract](release-ci-gate-execution-validation-contract.md)、[Release CI Gate API Implementation Plan](release-ci-gate-api-implementation-plan.md)、
[Linux Package Runner Toolchain Target Contract](linux-package-runner-toolchain-target-contract.md)、
[Linux Package Archive Staging Contract](linux-package-archive-staging-contract.md)、
[Linux Package Checksum Manifest Contract](linux-package-checksum-manifest-contract.md)、
[Linux Package Publish Upload Boundary Contract](linux-package-publish-upload-boundary-contract.md)、
[Linux Package Signing Attestation Policy Binding Contract](linux-package-signing-attestation-policy-binding-contract.md)、
[Linux Package Release Notes Rollback Policy Binding Contract](linux-package-release-notes-rollback-policy-binding-contract.md)、
[Linux Package Release Notes Rollback Execution Validation Contract](linux-package-release-notes-rollback-execution-validation-contract.md)、
[Linux Package Publish Eligibility Aggregate Contract](linux-package-publish-eligibility-aggregate-contract.md)、
[Linux Package Publish Eligibility Execution Validation Contract](linux-package-publish-eligibility-execution-validation-contract.md) 和
[Release Strategy](../release-strategy.md)。当前仓库的 Linux artifact release path 已激活；
本文件定义当前和后续 `package-linux` job 必须持续输出、校验和发布的 manifest 字段。

评估时间：2026-07-07。

## 目标

- 为首个 `networkcore-linux` Linux 压缩包定义 sidecar manifest 文件边界。
- 让 release summary、checksum、签名/证明和回滚字段有一个稳定、机器可读的来源。
- 避免 `package-linux` 只上传二进制或压缩包而缺少可审计 metadata。
- 在 license/NOTICE marker 缺失、非法或回退到 pending 时阻止真实 `package-linux` job。

## 非目标

- 不允许在本机实现、构建、打包、签名、证明或上传 artifact；这些步骤只能由 GitHub Actions release workflow 执行。
- 不定义 `.deb`、`.rpm`、AppImage、container image 或发行版仓库 metadata。
- 不把 runner 本地绝对路径、secret、token、证书私钥、配置文件内容或用户环境信息写入 manifest。

## Manifest 形态

首个 Linux package manifest 必须是 UTF-8 JSON sidecar 文件，不放入压缩包内部：

`networkcore-linux-${version}-${target}.manifest.json`

manifest 必须在 archive 和 archive checksum sidecar 生成之后创建，原因是 manifest 要记录
archive 文件名、checksum 文件名和 checksum 值。archive checksum、manifest 文件名、
manifest checksum 文件名、sha256 计算顺序和交叉校验字段遵守
[Linux Package Checksum Manifest Contract](linux-package-checksum-manifest-contract.md)。
manifest 自身必须另外生成 sha256，输出为：

`networkcore-linux-${version}-${target}.manifest.json.sha256`

`package-linux` 后续至少输出以下字段：

| 输出字段 | 含义 |
| --- | --- |
| `artifact_name` | Linux archive 文件名 |
| `artifact_path` | runner 上待上传 archive 路径 |
| `checksum_algorithm` | 固定为 `sha256` |
| `checksum_file` | archive checksum 文件路径 |
| `checksum_value` | archive sha256 值 |
| `artifact_manifest_name` | manifest 文件名 |
| `artifact_manifest_path` | runner 上待上传 manifest 路径 |
| `artifact_manifest_checksum_file` | manifest checksum 文件路径 |
| `artifact_manifest_checksum_value` | manifest sha256 值 |

这些字段必须进入 release summary。没有 manifest 输出时不得上传 Linux artifact。

## JSON 字段

manifest 顶层字段必须稳定、显式、可由自动化读取：

| 字段 | 要求 |
| --- | --- |
| `schema_version` | 固定为 `1`，后续破坏性变更必须递增 |
| `artifact_kind` | 固定为 `linux-cli-tarball` |
| `package_format` | 固定为 `tar.gz`，除非先更新设计 |
| `artifact_name` | 与 job output `artifact_name` 完全一致 |
| `target_triple` | Rust target triple，首个 artifact 必须来自 package runner/toolchain/target contract |
| `version` | release 版本，例如 `v0.1.0`、`v0.1.0-alpha.1` 或 `v0.1.0-rc.1` |
| `commit_sha` | release run 的 Git commit SHA |
| `source_ref` | release run 的 Git ref |
| `ci_run_url` | 同 commit 的成功 CI run URL，必须来自 release CI success source contract |
| `release_run_url` | 当前 release run URL |
| `runner` | runner 标签，首个 artifact 固定来自 package runner/toolchain/target contract 的 `ubuntu-latest` |
| `rust_toolchain` | packaging job 使用的 Rust toolchain，首个 artifact 固定为 `stable` |
| `archive` | archive 文件名、相对路径和 size bytes |
| `checksum` | archive checksum 算法、文件名和值 |
| `included_files` | 压缩包内文件清单和来源，必须来自 archive staging contract |
| `install_model` | 固定为 `manual-extract`，除非安装设计先更新 |
| `system_mutation_policy` | 固定为 `none`，首个 artifact 不修改系统状态 |
| `license_notice_status` | license/NOTICE 确认状态；未确认时不得生成 artifact |
| `signing` | signing/attestation/provenance 状态 |
| `release_notes` | release notes 和 withdrawal/replacement policy 字段 |
| `rollback` | release rollback 字段 |
| `publish_eligibility` | publish 前所有 gate 的 aggregate status 和 per-gate 状态 |

推荐最小 JSON 形态：

```json
{
  "schema_version": 1,
  "artifact_kind": "linux-cli-tarball",
  "package_format": "tar.gz",
  "artifact_name": "networkcore-linux-v0.1.0-x86_64-unknown-linux-gnu.tar.gz",
  "target_triple": "x86_64-unknown-linux-gnu",
  "version": "v0.1.0",
  "commit_sha": "<release-commit-sha>",
  "source_ref": "refs/tags/v0.1.0",
  "ci_run_url": "<successful-ci-run-url>",
  "release_run_url": "<release-run-url>",
  "runner": "ubuntu-latest",
  "rust_toolchain": "stable",
  "archive": {
    "file_name": "networkcore-linux-v0.1.0-x86_64-unknown-linux-gnu.tar.gz",
    "relative_path": "dist/linux/x86_64-unknown-linux-gnu/artifacts/networkcore-linux-v0.1.0-x86_64-unknown-linux-gnu.tar.gz",
    "size_bytes": 0
  },
  "checksum": {
    "algorithm": "sha256",
    "file_name": "networkcore-linux-v0.1.0-x86_64-unknown-linux-gnu.tar.gz.sha256",
    "value": "<archive-sha256>"
  },
  "included_files": [
    {
      "path": "bin/networkcore-linux",
      "kind": "binary",
      "required": true,
      "source": "apps/linux-cli"
    },
    {
      "path": "libexec/anixops-runner.js",
      "kind": "script-runner",
      "required": true,
      "source": "third_party/mitm_anixops"
    },
    {
      "path": "INSTALL.md",
      "kind": "documentation",
      "required": true,
      "source": "generated-from-repo-docs"
    },
    {
      "path": "LICENSE",
      "kind": "license",
      "required": true,
      "source": "license-notice-confirmed"
    },
    {
      "path": "CHANGELOG.md",
      "kind": "changelog",
      "required": true,
      "source": "CHANGELOG.md"
    }
  ],
  "install_model": "manual-extract",
  "system_mutation_policy": "none",
  "license_notice_status": "confirmed",
  "signing": {
    "signing_policy": "unsigned-no-detached-signature",
    "signing_status": "not-signed-by-policy",
    "attestation_policy": "github-artifact-attestation-required",
    "attestation_status": "attested",
    "provenance_policy": "github-build-provenance-required",
    "provenance_file": "github-artifact-attestation"
  },
  "release_notes": {
    "release_notes_policy": "required-before-publish",
    "release_notes_status": "published",
    "release_notes_source": "CHANGELOG.md-and-release-summary",
    "withdrawal_policy": "withdrawal-not-overwrite",
    "replacement_policy": "new-version-tag-required"
  },
  "rollback": {
    "rollback_policy": "manual-extract-version-switch",
    "rollback_status": "summarized",
    "rollback_scope": "linux-cli-artifact",
    "rollback_trigger": "checksum-install-runtime-security-or-provenance-defect",
    "rollback_steps": "withdraw-release-asset-and-publish-replacement-version",
    "replacement_version": "next-version-required",
    "rollback_owner": "maintainer"
  },
  "publish_eligibility": {
    "status": "eligible",
    "license_notice": "confirmed",
    "ci": "success",
    "runner_toolchain": "matched",
    "archive_staging": "matched",
    "checksum_manifest": "verified",
    "artifact_manifest": "verified",
    "publish_upload": "ready",
    "signing_attestation": "attested",
    "release_notes_rollback": "published-and-summarized"
  }
}
```

示例中的 `size_bytes` 和 placeholder 值不是当前 artifact 事实；真实 job 必须写入
实际值。

## 生成顺序

真实 `package-linux` job 后续必须按以下顺序生成 metadata：

1. 按 [Linux Package License Notice Transition Validation Contract](linux-package-license-notice-transition-validation-contract.md) 确认 `docs/manual-intervention.md` 中的 license/NOTICE 状态为 `confirmed`。
2. 确认 `release-ci-gate` 已按 [Release CI Success Source Contract](release-ci-success-source-contract.md)、[Linux Package Release CI Gate Activation Validation Contract](linux-package-release-ci-gate-activation-validation-contract.md)、[Release CI Gate Execution Validation Contract](release-ci-gate-execution-validation-contract.md) 和 [Release CI Gate API Implementation Plan](release-ci-gate-api-implementation-plan.md) 读取同 commit 成功 CI run 字段。
3. 确认 `package-linux` 已按 [Linux Package Runner Toolchain Target Contract](linux-package-runner-toolchain-target-contract.md) 声明 runner、Rust toolchain、target triple、crate、binary 和 archive naming 输入。
4. 确认 `package-linux` 已按 [Linux Package Archive Staging Contract](linux-package-archive-staging-contract.md) 声明 staging/output/top-level directory、archive path 和允许文件来源。
5. 确认 `package-linux` 已按 [Linux Package Checksum Manifest Contract](linux-package-checksum-manifest-contract.md) 声明 archive checksum、manifest 和 manifest checksum sidecar 文件命名、路径、record format 和交叉校验字段。
6. 在 GitHub Actions runner 中构建 `networkcore-linux`。
7. 按 archive staging contract 组装只含允许文件的顶层目录。
8. 创建 `.tar.gz` archive。
9. 计算 archive sha256，并在 archive 外写入 archive checksum sidecar。
10. 创建 manifest JSON，写入 `archive.file_name`、`archive.relative_path`、`checksum.algorithm`、`checksum.file_name` 和 `checksum.value`。
11. 交叉校验 manifest archive checksum 字段与 archive checksum sidecar 完全一致。
12. 计算最终 manifest sha256，并在 archive 外写入 manifest checksum sidecar。
13. 输出 archive、archive checksum、manifest 和 manifest checksum 字段。
14. 按 [Linux Package Signing Attestation Policy Binding Contract](linux-package-signing-attestation-policy-binding-contract.md) 输出 signing/attestation/provenance 状态。
15. 按 [Linux Package Release Notes Rollback Policy Binding Contract](linux-package-release-notes-rollback-policy-binding-contract.md) 和 [Linux Package Release Notes Rollback Execution Validation Contract](linux-package-release-notes-rollback-execution-validation-contract.md) 输出 release notes/rollback/withdrawal/replacement 状态。
16. 按 [Linux Package Publish Eligibility Aggregate Contract](linux-package-publish-eligibility-aggregate-contract.md) 输出 publish eligibility aggregate 状态。
17. 按 [Linux Package Publish Eligibility Execution Validation Contract](linux-package-publish-eligibility-execution-validation-contract.md) 校验 `package_publish_eligibility_status=eligible` 前 required gates、required fields 和 blocked/missing/unknown gate 边界。
18. release summary 展示字段；后续 publish job 必须按 [Linux Package Publish Upload Boundary Contract](linux-package-publish-upload-boundary-contract.md) 校验 workflow artifact bundle、release asset set、signing/attestation 状态、release notes/rollback 状态、publish eligibility aggregate 状态和 publish eligibility execution 状态后才能上传。

manifest 不得反向参与 archive checksum。这样用户可以独立校验 archive 和
manifest，release summary 也能引用两个 checksum。

## 文件清单边界

首个 manifest 的 `included_files` 必须至少覆盖以下路径，并与
[Linux Package Archive Staging Contract](linux-package-archive-staging-contract.md) 中的
Required Archive Contents 保持一致：

| path | kind | required | source |
| --- | --- | --- | --- |
| `bin/networkcore-linux` | `binary` | `true` | `apps/linux-cli` |
| `INSTALL.md` | `documentation` | `true` | repo docs 或 packaging 生成文档 |
| `LICENSE` | `license` | `true` | 人工确认后的 license/NOTICE 来源 |
| `CHANGELOG.md` | `changelog` | `true` | `CHANGELOG.md` |

首个 archive 不得包含：

- 用户配置、默认配置、订阅 URL、token、密码或私钥。
- systemd unit、shell installer、postinstall script、setcap helper 或 package-manager hook。
- 证书私钥、MITM CA 私钥、trust store mutation script。
- runner cache、Cargo target 目录、测试日志或临时目录。

## Release Summary 门禁

真实 artifact 发布前，release summary 必须输出：

- archive 文件名和 sha256。
- manifest 文件名和 sha256。
- target triple、version、commit SHA、CI run URL 和 release run URL。
- install model 和 system mutation policy。
- signing/attestation/provenance 状态。
- release notes/withdrawal/replacement policy 状态。
- rollback 字段。
- publish eligibility aggregate 状态。
- publish eligibility execution 状态、required gates、required fields 和 eligible status field。
- license/NOTICE 确认状态。

缺少任一字段时，release workflow 必须失败，不得上传 Linux artifact。

历史 placeholder release 不生成 manifest 文件，但必须在 `release-placeholder` 和
`release-summary` 中提前列出 manifest output contract，让后续真实 `package-linux`
无法绕过 `artifact_manifest_name`、`artifact_manifest_path`、
`artifact_manifest_checksum_file` 和 `artifact_manifest_checksum_value` 字段。

## 验收条件

- 本文档保持在 README、ROADMAP、Release Strategy、Linux artifact 设计、Linux CLI artifact 安装/回滚设计、
  [Linux Package Artifact Manifest Checksum Validation Contract](linux-package-artifact-manifest-checksum-validation-contract.md)
  和 CI policy 中可发现。
- `.github/workflows/ci.yml` governance 检查本文档存在和标题。
- `.github/workflows/release.yml` 的 `linux-artifact-readiness` 检查本文档存在、标题、release CI success source contract、release CI gate activation validation contract、release CI gate execution validation contract、release CI gate API implementation plan、artifact job preflight validation contract、artifact build command validation contract、artifact staging file validation contract、package runner/toolchain/target contract、archive staging contract、checksum/manifest checksum contract、publish/upload boundary contract、signing/attestation policy binding contract、release notes/rollback policy binding contract、release notes/rollback execution validation contract、publish eligibility aggregate contract、publish eligibility execution validation contract、license/NOTICE transition validation contract、license/NOTICE source contract、release placeholder manifest output summary 和 license/NOTICE source contract summary，但继续拒绝定义 `package-linux` job。
- release CI gate、release placeholder 和 release summary 输出 CI success source contract、release CI gate activation validation contract、release CI gate execution validation contract、release CI gate API implementation plan、artifact job preflight validation contract、artifact build command validation contract、artifact staging file validation contract、package runner/toolchain/target contract、archive staging contract、checksum/manifest checksum contract、artifact manifest checksum validation contract、publish/upload boundary contract、signing/attestation policy binding contract、release notes/rollback policy binding contract、release notes/rollback execution validation contract、publish eligibility aggregate contract、publish eligibility execution validation contract、license/NOTICE transition validation contract、manifest output contract 字段清单与 license/NOTICE source contract pending 状态。
- TODO 指向下一步最小 release workflow 或 release governance 增量。
- 不生成 artifact、不上传 release asset、不在本机执行测试、构建、打包或发布。

## 后续工作

- 在 license/NOTICE 人工确认完成前，继续不实现 `package-linux`。
- Linux package checksum manifest contract、publish/upload boundary contract、signing/attestation policy binding contract、release notes/rollback policy binding contract、publish eligibility aggregate contract、license/NOTICE transition validation contract 和 release CI gate activation validation contract 和 release CI gate execution validation contract 已定义；Linux package artifact job preflight validation contract、Linux package artifact build command validation contract、Linux package artifact staging file validation contract、Linux package artifact archive creation validation contract 和 Linux package artifact checksum execution validation contract 已定义；Linux package artifact manifest generation validation contract、Linux package artifact manifest checksum validation contract、Linux package workflow artifact bundle upload validation contract、Linux package artifact attestation execution validation contract、Linux package release notes/rollback execution validation contract 和 Linux package publish eligibility execution validation contract 已定义；release CI gate execution validation contract 和 release CI gate API implementation 已激活；当前 license/NOTICE 和 artifact gates 已进入 confirmed release path；后续 tag release 继续通过 release workflow、同 commit CI、checksum、manifest、attestation、release notes、rollback 和 publish eligibility gates 生成和发布 Linux assets。
