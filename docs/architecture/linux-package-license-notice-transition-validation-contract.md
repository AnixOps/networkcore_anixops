# Linux Package License Notice Transition Validation Contract

本文定义首个 Linux `package-linux` artifact 的 license/NOTICE 状态从 `pending`
切换为 `confirmed` 时必须满足的验证合同。当前 transition 已完成，本文继续固定
confirmed 字段、文件存在性检查、release workflow 阻断规则和防回退规则；它不重新确认
license 文本，也不允许跳过 CI、checksum、manifest、attestation、release notes、rollback 或
publish eligibility gates。

当前状态：

```text
linux-artifact-release-state=confirmed-release-path
linux-artifact-license-notice-status=confirmed
linux-artifact-publish-scope=tag-release-after-all-gates
```

评估时间：2026-07-07。

## 目标

- 把 license/NOTICE 从 pending 切换到 confirmed 的最小字段和验证规则文档化。
- 要求 confirmed 状态必须来自一次独立人工确认提交，不能夹带 packaging 或 publish job。
- 明确 `LICENSE`、可选 `NOTICE` 和 artifact 内 license/NOTICE 文件清单的存在性检查。
- 在 confirmed marker 未出现或字段不完整时继续阻止 `package-linux` 和 release assets。
- 防止 maintainer 通过 workflow input、聊天记录、本地文件或 Step Summary 手写 eligible 状态绕过
  `docs/manual-intervention.md`。

## 非目标

- 不重新执行或扩大 license/NOTICE 人工确认。
- 不新增、修改或解释项目 license、NOTICE 或第三方许可文本。
- 不在本文档中生成 archive、checksum、manifest、attestation、release notes、workflow artifact 或 release asset。
- 不把人工确认人的邮箱、私有身份信息、法律意见全文、私有合同、token、外部账号、
  runner 本地绝对路径或未公开安全公告细节写入仓库、manifest 或 Step Summary。

## Source Of Truth

首个 Linux license/NOTICE transition validation 输入必须来自本文档、
[Linux Artifact License Notice Confirmation Design](linux-artifact-license-notice-confirmation.md)、
[Linux Package Artifact Manifest Design](linux-package-artifact-manifest.md)、
[Linux Package Archive Staging Contract](linux-package-archive-staging-contract.md)、
[Linux Package Publish Eligibility Aggregate Contract](linux-package-publish-eligibility-aggregate-contract.md)、
`docs/manual-intervention.md` 和 release workflow 中的显式常量。

当前 confirmed release path 固定为：

| 字段 | 值 |
| --- | --- |
| `package_license_notice_transition_validation_contract` | `present` |
| `package_license_notice_transition_status` | `confirmed` |
| `package_license_notice_transition_source` | `docs/manual-intervention.md` |
| `package_license_notice_transition_required_commit` | `independent-manual-confirmation-commit` |
| `package_license_notice_transition_pending_marker` | `absent` |
| `package_license_notice_transition_confirmed_marker` | `present` |
| `package_license_notice_transition_license_source` | `LICENSE` |
| `package_license_notice_transition_license_file_check` | `present` |
| `package_license_notice_transition_notice_source` | `not-required` |
| `package_license_notice_transition_notice_file_check` | `not-required` |
| `package_license_notice_transition_artifact_files` | `LICENSE` |
| `package_license_notice_transition_package_linux` | `eligible-after-ci-and-release-gates` |
| `package_license_notice_transition_release_assets` | `eligible-after-package-signing-checksum-and-rollback-gates` |
| `package_license_notice_transition_next_action` | `continue-release-gates` |

当前 `confirmed` 表示 release workflow 已验证 transition 字段、`LICENSE`、`NOTICE=not-required`
和 artifact files，且 pending marker 不存在。该状态只解除 license/NOTICE 人工阻断；
packaging、attestation、publish eligibility 和 GitHub Release asset 上传仍必须继续通过各自 gate。

## Confirmed Transition 字段

人工确认完成后，必须用一次独立提交只更新确认状态和必要 license/NOTICE 文件。该提交不得
同时修改 `.github/workflows/release.yml` 中的 `package-linux`、`publish-github-release`、
`attest-linux`、`sign-linux`、`post-release-summary` 或任何上传 artifact 的 job；当前仓库已保留
该独立 transition marker。

confirmed 状态下，`docs/manual-intervention.md` 至少必须包含：

```text
linux-artifact-license-notice-status=confirmed
linux-artifact-license-notice-source-contract=docs/architecture/linux-artifact-license-notice-confirmation.md
linux-artifact-license-notice-transition-contract=docs/architecture/linux-package-license-notice-transition-validation-contract.md
linux-artifact-license-notice-transition-commit=independent-manual-confirmation-commit
linux-artifact-license-notice-confirmed-at=YYYY-MM-DD
linux-artifact-license-notice-confirmed-by=maintainer
linux-artifact-license-notice-scope=networkcore-linux
linux-artifact-license-notice-license-source=LICENSE
linux-artifact-license-notice-notice-source=not-required
linux-artifact-license-notice-artifact-files=LICENSE
linux-artifact-license-notice-package-linux=eligible-after-ci-and-release-gates
linux-artifact-license-notice-release-assets=eligible-after-package-signing-checksum-and-rollback-gates
```

字段规则：

| 字段 | 要求 |
| --- | --- |
| `status` | 只允许 `pending` 或 `confirmed`；confirmed 时不得保留 pending 状态行 |
| `transition-contract` | 必须指向本文档 |
| `transition-commit` | 必须为 `independent-manual-confirmation-commit` |
| `confirmed-at` | ISO 日期，格式为 `YYYY-MM-DD` |
| `confirmed-by` | 固定角色或公开 GitHub handle；不得写邮箱或私有身份 |
| `scope` | 首个 Linux artifact 固定为 `networkcore-linux` |
| `license-source` | 仓库相对路径，首个 Linux artifact 固定为 `LICENSE`，confirmed 时文件必须存在 |
| `notice-source` | 仓库相对路径或 `not-required`；不是 `not-required` 时文件必须存在 |
| `artifact-files` | artifact 内必须包含的 license/NOTICE 文件清单，首个 Linux artifact 至少包含 `LICENSE` |
| `package-linux` | confirmed 后只能表示可进入后续 CI/release gates，不表示可立即打包 |
| `release-assets` | confirmed 后只能表示可进入后续 checksum/signing/rollback gates，不表示可立即上传 |

## 文件存在性检查

release workflow 后续读取 confirmed marker 时必须执行以下检查：

1. `linux-artifact-license-notice-status=confirmed` 存在，且 `pending` 状态行不存在。
2. `linux-artifact-license-notice-transition-contract` 指向本文档。
3. `linux-artifact-license-notice-transition-commit=independent-manual-confirmation-commit` 存在。
4. `linux-artifact-license-notice-license-source` 是仓库相对路径，且对应文件存在。
5. `linux-artifact-license-notice-notice-source` 为 `not-required`，或对应仓库相对路径存在。
6. `linux-artifact-license-notice-artifact-files` 至少包含 `LICENSE`，且不得包含 runner 本地绝对路径。
7. `linux-artifact-license-notice-package-linux` 只能是
   `eligible-after-ci-and-release-gates`。
8. `linux-artifact-license-notice-release-assets` 只能是
   `eligible-after-package-signing-checksum-and-rollback-gates`。

如果 status 为 `pending`、同时存在 pending/confirmed、或字段缺失，release workflow 必须失败，
不得继续构建、上传 workflow artifact 或发布 GitHub Release asset。

## Release Workflow 边界

当前 release workflow 必须：

- 检查本文档存在和标题。
- 检查 `docs/manual-intervention.md` 当前处于 confirmed 状态，且 pending 行不存在。
- 验证 transition 字段、`LICENSE`、`NOTICE=not-required` 和 artifact files。
- 在 `linux-artifact-readiness` 和 release summary 中输出 transition validation 结果。
- 标记 `linux-package-license-notice-transition-contract=present`。
- 标记 `linux-package-license-notice-transition-status=confirmed`。
- 标记 `linux-package-license-notice-transition-required-commit=independent-manual-confirmation-commit`。
- 标记 `linux-package-license-notice-transition-confirmed-marker=present`。
- 标记 `linux-package-license-notice-transition-license-file-check=present`。
- 标记 `linux-package-license-notice-transition-package-linux=eligible-after-ci-and-release-gates`。
- 标记 `linux-package-license-notice-transition-next-action=continue-release-gates`。

confirmed transition 合同完成后，仍必须继续通过同 commit CI、runner/toolchain、archive staging、
checksum/manifest、artifact manifest、publish/upload、signing/attestation、release notes/rollback
和 publish eligibility aggregate gates。license/NOTICE confirmed 只是解除一个人工阻断。

## Rejection Rules

release workflow 必须拒绝以下情况：

- 在 `docs/manual-intervention.md` 仍为 pending 时定义 `package-linux` 或上传 release asset。
- confirmed 状态没有使用独立人工确认提交字段。
- confirmed 状态缺少 `transition-contract`、`transition-commit`、`confirmed-at`、`confirmed-by`、
  `scope`、`license-source`、`notice-source`、`artifact-files`、`package-linux` 或 `release-assets` 字段。
- `license-source` 或 `notice-source` 指向 runner 本地绝对路径、外部 URL、secret 路径或不存在的仓库文件。
- `artifact-files` 不包含 `LICENSE`，或包含 runner 本地绝对路径。
- confirmed 状态与 [Linux Package Archive Staging Contract](linux-package-archive-staging-contract.md) 的
  required archive contents 不一致。
- license/NOTICE confirmed 后立即把 aggregate status 改为 `eligible`，但 CI、checksum、manifest、
  signing/attestation、release notes/rollback 或 publish/upload gates 仍未完成。
- Step Summary、manifest 或 release notes 输出人工邮箱、私有身份、法律意见全文、私有合同、
  token、证书私钥、runner 本地绝对路径或未公开安全公告细节。

拒绝时不得上传 workflow artifact 或 GitHub Release asset。

## 验收条件

- 本文档保持在 README、ROADMAP、Release Strategy、Linux artifact 设计、Linux artifact
  license/NOTICE confirmation source contract、Linux package manifest 设计、Linux package archive
  staging contract、Linux package artifact job preflight validation contract、Linux package publish
  eligibility aggregate contract、Linux CLI artifact 安装/回滚设计和 CI policy 中可发现。
- `.github/workflows/ci.yml` governance 检查本文档存在、标题、
  `linux-artifact-release-state=confirmed-release-path` 和 confirmed marker。
- `.github/workflows/release.yml` 的 `linux-artifact-readiness` 检查本文档存在、标题、confirmed marker、
  pending marker absence、transition 字段、license/NOTICE 文件存在性检查和 release-state consistency marker。
- release summary 输出 Linux readiness、package、attestation、publish eligibility、artifact、
  checksum、manifest 和 GitHub Release 状态。
- 当前只允许 GitHub Actions 生成 archive、checksum、manifest、attestation、workflow artifact
  和 tag release asset；本机不得执行测试、构建、打包或发布。

## 后续工作

- 保持 `linux-artifact-license-notice-status=confirmed` 与 release strategy、release workflow、
  README、ROADMAP、TODO 和 CHANGELOG 一致。
- Linux package release CI gate activation validation contract、Linux package artifact job preflight
  validation contract、Linux package artifact build command validation contract、Linux package artifact
  staging file validation contract 和 Linux package artifact archive creation validation contract 已定义；
  Linux package artifact manifest generation validation contract、Linux package artifact manifest checksum validation contract、Linux package workflow artifact bundle upload validation contract、Linux package artifact attestation execution validation contract、Linux package release notes/rollback execution validation contract 和 Linux package publish eligibility execution validation contract 已定义；release CI gate execution validation contract 和 release CI gate API implementation 已激活；下一步是继续补强 Linux managed lifecycle、安装器/服务设计或其他平台产物前置设计。
