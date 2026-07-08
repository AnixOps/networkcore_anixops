# Linux Package Release CI Gate Activation Validation Contract

> Current activation note: Linux artifact release path is now `linux-artifact-release-state=confirmed-release-path`. `package-linux`, attestation, publish eligibility, and GitHub Release upload are owned by GitHub Actions; any older blocked, not-defined, or current-placeholder wording below describes the historical pre-activation boundary unless a section explicitly states the post-activation state.


本文定义首个 Linux `package-linux` artifact 在启用真实 packaging 前，`release-ci-gate`
从 placeholder 字段合同切换到自动读取同 commit 成功 CI run 时必须满足的验证合同。当前
`release-ci-gate` API read 已激活；本文继续固定权限、API 读取字段、失败条件和继续不生成 artifact 的边界，
不定义 `package-linux` job、不上传 artifact。

评估时间：2026-07-07。

## 目标

- 明确 `release-ci-gate` 从 placeholder 切换到自动 CI run 读取前需要的 GitHub Actions 权限。
- 固定读取同 repository、同 commit、`main` 分支、`CI` workflow 成功 run 的 API 字段。
- 定义找不到成功 CI、CI 未完成、workflow 不匹配或 commit 不匹配时的失败边界。
- 在 CI gate 仍未激活时继续阻止 `package-linux`、workflow artifact 和 GitHub Release asset。
- 防止 maintainer 通过 workflow input、Step Summary、手写 URL、本地命令或聊天记录声明 CI 已通过。

## 非目标

- 不实现 `package-linux`、`publish-github-release`、`attest-linux`、`sign-linux`、
  `post-release-summary` 或等价 job。
- 不生成 archive、checksum、manifest、attestation、release notes、workflow artifact 或 release asset。
- 不把 GitHub token、API response 原文、runner 本地绝对路径、维护者私有身份或未公开安全公告细节写入
  manifest、release notes 或 Step Summary。

## Source Of Truth

首个 Linux release CI gate activation validation 输入必须来自本文档、
[Release CI Success Source Contract](release-ci-success-source-contract.md)、
[Release CI Gate Execution Validation Contract](release-ci-gate-execution-validation-contract.md)、
[Release CI Gate API Implementation Plan](release-ci-gate-api-implementation-plan.md)、
[Linux Package Publish Eligibility Aggregate Contract](linux-package-publish-eligibility-aggregate-contract.md)、
[Linux Package Artifact Manifest Design](linux-package-artifact-manifest.md)、
[Linux Package Artifact Job Preflight Validation Contract](linux-package-artifact-job-preflight-validation-contract.md)、
[Linux Package Publish Upload Boundary Contract](linux-package-publish-upload-boundary-contract.md)、
[Linux Package License Notice Transition Validation Contract](linux-package-license-notice-transition-validation-contract.md)
和 release workflow 中的显式常量。

当前 active activation 固定为：

| 字段 | 值 |
| --- | --- |
| `package_release_ci_gate_activation_contract` | `present` |
| `package_release_ci_gate_activation_status` | `active` |
| `package_release_ci_gate_activation_source` | `release-ci-gate` |
| `package_release_ci_gate_activation_current_mode` | `api-read-active` |
| `package_release_ci_gate_activation_required_permission` | `actions-read` |
| `package_release_ci_gate_activation_permission_status` | `enabled` |
| `package_release_ci_gate_activation_api_source` | `github-actions-runs-api` |
| `package_release_ci_gate_activation_api_status` | `queried` |
| `package_release_ci_gate_activation_required_workflow` | `CI` |
| `package_release_ci_gate_activation_required_workflow_file` | `.github/workflows/ci.yml` |
| `package_release_ci_gate_activation_required_branch` | `main` |
| `package_release_ci_gate_activation_required_status` | `completed` |
| `package_release_ci_gate_activation_required_conclusion` | `success` |
| `package_release_ci_gate_activation_required_head_sha` | `same-release-sha` |
| `package_release_ci_gate_activation_allowed_events` | `push,workflow_dispatch` |
| `package_release_ci_gate_activation_failure_mode` | `fail-before-package-linux` |
| `package_release_ci_gate_activation_package_linux` | `not-defined` |
| `package_release_ci_gate_activation_artifacts` | `blocked` |
| `package_release_ci_gate_activation_next_action` | `license-notice-and-package-linux-preflight-after-ci-gate` |

`active` 表示 release workflow 已自动读取并校验同 repository、同 commit、`main` 分支的成功 CI run 和
`CI summary` job；artifact 仍不能进入 packaging，因为 license/NOTICE confirmation 与后续 artifact gates
尚未完成。

## Activation 字段

启用真实 CI gate 后，`release-ci-gate` 必须在同一 job 中自动产生以下字段，并由后续
`package-linux`、manifest、release notes 和 release summary 读取：

```text
release-ci-gate=active
release-ci-gate-activation-contract=docs/architecture/linux-package-release-ci-gate-activation-validation-contract.md
release-ci-gate-activation-permission=actions-read
release-ci-gate-activation-api-source=github-actions-runs-api
release-ci-gate-activation-api-query=workflow=CI,branch=main,head_sha=${release_sha},status=completed
ci_workflow_name=CI
ci_workflow_file=.github/workflows/ci.yml
ci_run_id=<actions-run-id>
ci_run_attempt=<actions-run-attempt>
ci_run_url=<actions-run-url>
ci_run_status=completed
ci_run_conclusion=success
ci_head_sha=${release_sha}
ci_head_branch=main
ci_event=<push-or-controlled-workflow_dispatch>
ci_repository=${release_repository}
ci_checked_at=<UTC timestamp>
```

字段规则：

| 字段 | 要求 |
| --- | --- |
| `release-ci-gate` | 只能从 `placeholder` 切换为 `active`；不能使用 `manual`、`skipped` 或 `assumed` |
| `activation-contract` | 必须指向本文档 |
| `activation-permission` | 必须对应 workflow `permissions: actions: read` |
| `activation-api-source` | 固定为 GitHub Actions workflow runs API 或等价 GitHub 官方 run 查询 |
| `activation-api-query` | 必须包含 workflow、branch、head SHA 和 completed status 约束 |
| `ci_workflow_name` | 固定为 `CI` |
| `ci_workflow_file` | 固定为 `.github/workflows/ci.yml` |
| `ci_run_status` | 必须为 `completed` |
| `ci_run_conclusion` | 必须为 `success` |
| `ci_head_sha` | 必须等于 release run 的 `${{ github.sha }}` |
| `ci_head_branch` | 必须为 `main` |
| `ci_event` | 必须为 `push` 或受控 `workflow_dispatch`；`workflow_dispatch` 只能在同 commit、同 branch 且 CI summary 成功时接受 |
| `ci_repository` | 必须等于 release run repository |
| `ci_checked_at` | UTC 时间戳，只记录检查时间，不记录 API response 原文 |

## API 读取边界

activation 必须满足以下顺序：

1. `release-policy` 先确认 release version、event 和 ref 合法。
2. `release-ci-gate` 使用 `actions: read` 权限读取当前 repository 的 `CI` workflow runs。
3. 查询必须限制为 `.github/workflows/ci.yml`、`main` branch、release SHA、`completed` status。
4. 从返回结果中选择 `conclusion=success`、`head_sha` 等于 release SHA、`head_branch=main`、
   `repository` 等于当前 repository 的 run。
5. 检查 CI summary job 已成功，且 CI run 没有因为 concurrency 被取消或被 superseded 后仍被误用。
6. 输出 required CI source fields；后续 job 只能读取这些字段，不得接受 maintainer 手写 run id。
7. 如果任何检查失败，release workflow 必须在 `package-linux` 前失败。

当前 workflow 执行以上 API 读取并输出 active 状态，但仍不定义 `package-linux`。

## Rejection Rules

真实 activation 必须拒绝以下情况：

- workflow 未授予 `actions: read` 却尝试读取 CI run。
- 找不到同 repository、同 commit、`main` 分支、`CI` workflow 的成功 completed run。
- 找到的 run 仍为 `queued`、`in_progress`、`waiting`、`requested`、`cancelled`、`timed_out` 或
  conclusion 不是 `success`。
- run 来自 pull request ref、fork、不同 branch、不同 workflow、不同 SHA 或不同 repository。
- run 缺少 CI summary job 成功结论，或关键 policy/workspace/Rust/security gate 被移除。
- release workflow 使用 input 传入的 URL、run id、chat log、本地命令输出或 Step Summary 文本替代 API 查询。
- `package-linux` 在 CI activation 不是 `active` 时被定义或执行。
- API response 原文、token、Authorization header、runner 本地路径或维护者私有身份被写入 manifest、release notes
  或 Step Summary。

拒绝时不得执行 `package-linux`，不得上传 workflow artifact 或 GitHub Release asset。

## Release Workflow 边界

当前 release workflow 只能：

- 检查本文档存在和标题。
- 检查 `release-ci-gate` 已启用 `actions: read`，确保 `permission-status=enabled` 与实际权限一致。
- 在 `release-ci-gate`、`linux-artifact-readiness`、release placeholder 和 release summary 中输出 activation
  validation contract active 字段。
- 标记 `linux-package-release-ci-gate-activation-contract=present`。
- 标记 `linux-package-release-ci-gate-activation-status=active`。
- 标记 `linux-package-release-ci-gate-activation-required-permission=actions-read`。
- 标记 `linux-package-release-ci-gate-activation-permission-status=enabled`。
- 标记 `linux-package-release-ci-gate-activation-api-status=queried`。
- 标记 `linux-package-release-ci-gate-activation-required-head-sha=same-release-sha`。
- 标记 `linux-package-release-ci-gate-activation-package-linux=not-defined`。
- 标记 `linux-package-release-ci-gate-activation-artifacts=blocked`。
- 标记 `linux-package-release-ci-gate-activation-next-action=license-notice-and-package-linux-preflight-after-ci-gate`。
- 继续不定义 `package-linux`、`publish-github-release`、`attest-linux`、`sign-linux` 或
  `post-release-summary`。

## Manifest Binding

真实 `package-linux` manifest 必须把 activation 后的 CI fields 写入 release metadata：

```json
{
  "ci": {
    "workflow_name": "CI",
    "workflow_file": ".github/workflows/ci.yml",
    "run_id": "<actions-run-id>",
    "run_attempt": "<actions-run-attempt>",
    "run_url": "<actions-run-url>",
    "status": "completed",
    "conclusion": "success",
    "head_sha": "<release-sha>",
    "head_branch": "main",
    "event": "<push-or-controlled-workflow_dispatch>",
    "repository": "<owner/repo>",
    "checked_at": "<utc-timestamp>"
  }
}
```

manifest 不得写入 API response 原文、GitHub token、secret、runner 本地绝对路径或维护者私有身份。

## 验收条件

- 本文档保持在 README、ROADMAP、Release Strategy、Release CI success source contract、Linux package
  manifest 设计、Release CI gate execution validation contract、Release CI gate API implementation plan、Linux package artifact job preflight validation contract、
  Linux package publish eligibility aggregate contract、Linux package publish/upload boundary contract、Linux CLI artifact 安装/回滚设计和
  CI policy 中可发现。
- `.github/workflows/ci.yml` governance 检查本文档存在、标题和 release workflow placeholder 输出字段。
- `.github/workflows/release.yml` 的 `release-ci-gate` 检查本文档存在、标题，并输出 activation active 字段。
- `linux-artifact-readiness`、release placeholder 和 release summary 输出 activation active status、required permission、
  queried API status、same release SHA requirement、`package-linux` not-defined 和 artifact blocked 状态。
- 当前不生成 artifact、不定义 `package-linux`、不定义 `publish-github-release`、不上传 workflow artifact、
  不上传 release asset、不在本机执行测试、构建、打包或发布。

## 后续工作

- CI activation 已实现；下一步在 artifact 路径上必须先完成 license/NOTICE 人工确认，再定义
  `package-linux` preflight，仍不发布 release asset。
