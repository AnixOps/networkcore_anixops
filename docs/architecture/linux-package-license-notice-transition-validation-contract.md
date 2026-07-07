# Linux Package License Notice Transition Validation Contract

本文定义首个 Linux `package-linux` artifact 的 license/NOTICE 状态从 `pending`
切换为 `confirmed` 时必须满足的验证合同。当前仍是 pending placeholder；本文只固定
未来人工确认提交、字段、文件存在性检查和 release workflow 阻断规则，不完成人工确认、
不添加 license 文本、不定义 `package-linux` job、不上传 artifact。

评估时间：2026-07-07。

## 目标

- 把 license/NOTICE 从 pending 切换到 confirmed 的最小字段和验证规则文档化。
- 要求 confirmed 状态必须来自一次独立人工确认提交，不能夹带 packaging 或 publish job。
- 明确 `LICENSE`、可选 `NOTICE` 和 artifact 内 license/NOTICE 文件清单的存在性检查。
- 在 confirmed marker 未出现或字段不完整时继续阻止 `package-linux` 和 release assets。
- 防止 maintainer 通过 workflow input、聊天记录、本地文件或 Step Summary 手写 eligible 状态绕过
  `docs/manual-intervention.md`。

## 非目标

- 不完成 license/NOTICE 人工确认。
- 不新增、修改或解释项目 license、NOTICE 或第三方许可文本。
- 不实现 `package-linux`、`publish-github-release`、`attest-linux`、`sign-linux`、
  `post-release-summary` 或等价 job。
- 不生成 archive、checksum、manifest、attestation、release notes、workflow artifact 或 release asset。
- 不把人工确认人的邮箱、私有身份信息、法律意见全文、私有合同、token、外部账号、
  runner 本地绝对路径或未公开安全公告细节写入仓库、manifest 或 Step Summary。

## Source Of Truth

首个 Linux license/NOTICE transition validation 输入必须来自本文档、
[Linux Artifact License Notice Confirmation Design](linux-artifact-license-notice-confirmation.md)、
[Linux Package Artifact Manifest Design](linux-package-artifact-manifest.md)、
[Linux Package Archive Staging Contract](linux-package-archive-staging-contract.md)、
[Linux Package Publish Eligibility Aggregate Contract](linux-package-publish-eligibility-aggregate-contract.md)、
`docs/manual-intervention.md` 和 release workflow 中的显式常量。

当前 placeholder 固定为：

| 字段 | 值 |
| --- | --- |
| `package_license_notice_transition_validation_contract` | `present` |
| `package_license_notice_transition_status` | `blocked-pending` |
| `package_license_notice_transition_source` | `docs/manual-intervention.md` |
| `package_license_notice_transition_required_commit` | `independent-manual-confirmation-commit` |
| `package_license_notice_transition_pending_marker` | `present` |
| `package_license_notice_transition_confirmed_marker` | `blocked-not-present` |
| `package_license_notice_transition_license_source` | `LICENSE` |
| `package_license_notice_transition_license_file_check` | `blocked-until-confirmed` |
| `package_license_notice_transition_notice_source` | `not-required` |
| `package_license_notice_transition_notice_file_check` | `not-required-until-confirmed` |
| `package_license_notice_transition_artifact_files` | `LICENSE` |
| `package_license_notice_transition_package_linux` | `not-defined` |
| `package_license_notice_transition_release_assets` | `blocked` |
| `package_license_notice_transition_next_action` | `manual-license-notice-confirmation` |

当前 `blocked-pending` 表示 release workflow 已知道如何验证 future confirmed transition，
但 `docs/manual-intervention.md` 仍保持 pending marker，因此不得进入 packaging。

## Confirmed Transition 字段

未来人工确认完成后，必须用一次独立提交只更新确认状态和必要 license/NOTICE 文件。该提交不得
同时修改 `.github/workflows/release.yml` 中的 `package-linux`、`publish-github-release`、
`attest-linux`、`sign-linux`、`post-release-summary` 或任何上传 artifact 的 job。

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

如果 status 仍为 `pending`，release workflow 当前只能输出 blocked 状态，不得尝试查找或生成
artifact license 文件。

## Release Workflow 边界

当前 placeholder release 只能：

- 检查本文档存在和标题。
- 检查 `docs/manual-intervention.md` 当前仍处于 pending 状态；如果 future confirmed marker 出现，
  则先要求 pending 行不存在，并验证 transition 字段、`LICENSE` 和可选 `NOTICE` 文件存在性。
- 在 `linux-artifact-readiness`、release placeholder 和 release summary 中输出 transition
  validation contract。
- 标记 `linux-package-license-notice-transition-contract=present`。
- 标记 `linux-package-license-notice-transition-status=blocked-pending`。
- 标记 `linux-package-license-notice-transition-required-commit=independent-manual-confirmation-commit`。
- 标记 `linux-package-license-notice-transition-confirmed-marker=blocked-not-present`。
- 标记 `linux-package-license-notice-transition-license-file-check=blocked-until-confirmed`。
- 标记 `linux-package-license-notice-transition-package-linux=not-defined`。
- 标记 `linux-package-license-notice-transition-next-action=manual-license-notice-confirmation`。
- 继续不定义 `package-linux`、`publish-github-release`、`attest-linux`、`sign-linux` 或
  `post-release-summary`。

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
- `.github/workflows/ci.yml` governance 检查本文档存在、标题和 release workflow placeholder 输出字段。
- `.github/workflows/release.yml` 的 `linux-artifact-readiness` 检查本文档存在、标题、当前 pending marker、
  future confirmed marker transition 字段、license/NOTICE 文件存在性检查、transition blocked marker 和
  `package-linux` 未定义状态。
- release placeholder 和 release summary 输出 transition source、blocked status、required independent
  commit、future confirmed marker、license/NOTICE file check、`package-linux` not-defined 和 next action。
- 当前不生成 artifact、不定义 `package-linux`、不定义 `publish-github-release`、不上传 workflow artifact、
  不上传 release asset、不在本机执行测试、构建、打包或发布。

## 后续工作

- 在人工确认完成前，继续保持 `linux-artifact-license-notice-status=pending`。
- Linux package release CI gate activation validation contract、Linux package artifact job preflight
  validation contract、Linux package artifact build command validation contract 和 Linux package artifact
  staging file validation contract 已定义；下一步可以补充 Linux package artifact archive creation
  validation contract，仍不生成 artifact。
