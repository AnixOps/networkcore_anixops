# Linux Package Artifact Manifest Design

本文定义首个 Linux `package-linux` job 在真实生成 artifact 前必须遵守的
artifact manifest 和 metadata 输出合同。它承接
[Linux Artifact Pre-Release Design](linux-artifact-pre-release-design.md)、
[Linux CLI Artifact Installation And Rollback Design](linux-cli-artifact-installation-rollback.md)
和 [Release Strategy](../release-strategy.md)。当前仓库仍不生成 Linux artifact；
本文件只定义后续 packaging job 的可检查字段。

评估时间：2026-07-07。

## 目标

- 为首个 `networkcore-linux` Linux 压缩包定义 sidecar manifest 文件边界。
- 让 release summary、checksum、签名/证明和回滚字段有一个稳定、机器可读的来源。
- 避免 `package-linux` 只上传二进制或压缩包而缺少可审计 metadata。
- 在 license/NOTICE 人工确认完成前继续阻止真实 `package-linux` job。

## 非目标

- 不实现 `package-linux` job。
- 不构建、打包、签名、证明或上传 artifact。
- 不定义 `.deb`、`.rpm`、AppImage、container image 或发行版仓库 metadata。
- 不把 runner 本地绝对路径、secret、token、证书私钥、配置文件内容或用户环境信息写入 manifest。

## Manifest 形态

首个 Linux package manifest 必须是 UTF-8 JSON sidecar 文件，不放入压缩包内部：

`networkcore-linux-${version}-${target}.manifest.json`

manifest 必须在 archive 和 checksum 生成之后创建，原因是 manifest 要记录
archive 文件名、checksum 文件名和 checksum 值。manifest 自身必须另外生成
sha256，输出为：

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
| `target_triple` | Rust target triple，例如 `x86_64-unknown-linux-gnu` |
| `version` | release 版本，例如 `v0.1.0` 或 `v0.1.0-rc.1` |
| `commit_sha` | release run 的 Git commit SHA |
| `source_ref` | release run 的 Git ref |
| `ci_run_url` | 同 commit 的成功 CI run URL，真实 packaging 前必须存在 |
| `release_run_url` | 当前 release run URL |
| `runner` | runner 标签，例如 `ubuntu-latest` |
| `rust_toolchain` | packaging job 使用的 Rust toolchain |
| `archive` | archive 文件名、相对路径和 size bytes |
| `checksum` | archive checksum 算法、文件名和值 |
| `included_files` | 压缩包内文件清单和来源 |
| `install_model` | 固定为 `manual-extract`，除非安装设计先更新 |
| `system_mutation_policy` | 固定为 `none`，首个 artifact 不修改系统状态 |
| `license_notice_status` | license/NOTICE 确认状态；未确认时不得生成 artifact |
| `signing` | signing/attestation/provenance 状态 |
| `rollback` | release rollback 字段 |

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
    "relative_path": "dist/networkcore-linux-v0.1.0-x86_64-unknown-linux-gnu.tar.gz",
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
      "path": "README.md",
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
    "signing_policy": "unsigned-placeholder",
    "signing_status": "not-signed",
    "attestation_status": "not-enabled",
    "provenance_file": "not-enabled"
  },
  "rollback": {
    "rollback_scope": "linux-cli-artifact",
    "rollback_trigger": "checksum, install, runtime, or security defect",
    "rollback_steps": "withdraw release asset and publish replacement version",
    "replacement_version": "next-version",
    "rollback_owner": "maintainer"
  }
}
```

示例中的 `size_bytes` 和 placeholder 值不是当前 artifact 事实；真实 job 必须写入
实际值。

## 生成顺序

真实 `package-linux` job 后续必须按以下顺序生成 metadata：

1. 确认 license/NOTICE 人工事项已完成。
2. 确认同 commit 的 CI run 成功。
3. 在 GitHub Actions runner 中构建 `networkcore-linux`。
4. 组装只含允许文件的顶层目录。
5. 创建 `.tar.gz` archive。
6. 计算 archive sha256。
7. 创建 manifest JSON。
8. 计算 manifest sha256。
9. 输出 archive、archive checksum、manifest 和 manifest checksum 字段。
10. release summary 展示字段；后续 publish job 才能上传。

manifest 不得反向参与 archive checksum。这样用户可以独立校验 archive 和
manifest，release summary 也能引用两个 checksum。

## 文件清单边界

首个 manifest 的 `included_files` 必须至少覆盖：

| path | kind | required | source |
| --- | --- | --- | --- |
| `bin/networkcore-linux` | `binary` | `true` | `apps/linux-cli` |
| `README.md` 或 `INSTALL.md` | `documentation` | `true` | repo docs 或 packaging 生成文档 |
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
- rollback 字段。
- license/NOTICE 确认状态。

缺少任一字段时，release workflow 必须失败，不得上传 Linux artifact。

## 验收条件

- 本文档保持在 README、ROADMAP、Release Strategy、Linux artifact 设计、Linux CLI artifact 安装/回滚设计和 CI policy 中可发现。
- `.github/workflows/ci.yml` governance 检查本文档存在和标题。
- `.github/workflows/release.yml` 的 `linux-artifact-readiness` 检查本文档存在和标题，但继续拒绝定义 `package-linux` job。
- TODO 指向下一步最小 release workflow 增量。
- 不生成 artifact、不上传 release asset、不在本机执行测试、构建、打包或发布。

## 后续工作

- 在 license/NOTICE 人工确认完成前，继续不实现 `package-linux`。
- 下一步可以在 release placeholder 中补充 manifest output contract summary，仍不生成 artifact。
