# Release CI Gate Execution Validation Contract

> Current activation note: Linux artifact release path is now `linux-artifact-release-state=confirmed-release-path`. `package-linux`, attestation, publish eligibility, and GitHub Release upload are owned by GitHub Actions; any older blocked, not-defined, or current-placeholder wording below describes the historical pre-activation boundary unless a section explicitly states the post-activation state.


本文定义 release workflow 真正执行 `release-ci-gate` 时，如何自动读取同 repository、同
commit、`main` 分支成功 CI run，并在 `package-linux` 或任何 release asset 前失败阻断。当前
`release-ci-gate` API read 已激活；本文固定 API 字段、权限、失败边界和 release workflow 输出，
继续不定义 `package-linux` job、不上传 artifact 或 release asset。

评估时间：2026-07-07。

## 目标

- 明确 `release-ci-gate` 的真实执行必须由 workflow 自动查询 GitHub Actions runs API。
- 固定同 repository、同 commit、`main` 分支、`CI` workflow、`completed`/`success` run 的选择规则。
- 定义 required API 字段、`actions: read` 权限、CI summary 成功校验和失败边界。
- 阻止 maintainer 用 workflow input、手写 run URL、Step Summary、本地命令或聊天记录替代自动校验。
- 在当前 placeholder 阶段继续阻止 `package-linux`、workflow artifact、GitHub Release 和 release asset。

## 非目标

- 不定义 `package-linux`、`attest-linux`、`publish-eligibility-gate`、`publish-github-release`、
  `post-release-summary` 或等价 publish job。
- 不生成 archive、checksum、manifest、workflow artifact、attestation、release notes、GitHub Release
  或 release asset。
- 不把 GitHub token、API response 原文、runner 本地绝对路径、secret、维护者私有身份或未公开安全公告细节写入
  manifest、release notes、release summary 或 Step Summary。

## Source Of Truth

首个 release CI gate execution 输入必须来自本文档、
[Release CI Success Source Contract](release-ci-success-source-contract.md)、
[Linux Package Release CI Gate Activation Validation Contract](linux-package-release-ci-gate-activation-validation-contract.md)、
[Release CI Gate API Implementation Plan](release-ci-gate-api-implementation-plan.md)、
[Linux Package Publish Eligibility Execution Validation Contract](linux-package-publish-eligibility-execution-validation-contract.md)、
[Linux Package Publish Eligibility Aggregate Contract](linux-package-publish-eligibility-aggregate-contract.md)、
[Linux Package Artifact Job Preflight Validation Contract](linux-package-artifact-job-preflight-validation-contract.md)、
[Linux Package Artifact Manifest Design](linux-package-artifact-manifest.md)、
[Linux Package Publish Upload Boundary Contract](linux-package-publish-upload-boundary-contract.md)、
[Linux Package License Notice Transition Validation Contract](linux-package-license-notice-transition-validation-contract.md)、
CI workflow、release workflow 和 `docs/manual-intervention.md` 中的显式机器字段。

当前 active execution 固定为：

| 字段 | 值 |
| --- | --- |
| `release_ci_gate_execution_contract` | `present` |
| `release_ci_gate_execution_status` | `active` |
| `release_ci_gate_execution_source` | `release-ci-gate` |
| `release_ci_gate_execution_current_mode` | `api-read-active` |
| `release_ci_gate_execution_required_job` | `release-ci-gate` |
| `release_ci_gate_execution_job_status` | `active` |
| `release_ci_gate_execution_required_permission` | `actions-read` |
| `release_ci_gate_execution_permission_status` | `enabled` |
| `release_ci_gate_execution_api_source` | `github-actions-runs-api` |
| `release_ci_gate_execution_api_status` | `queried` |
| `release_ci_gate_execution_query_workflow` | `CI` |
| `release_ci_gate_execution_query_workflow_file` | `.github/workflows/ci.yml` |
| `release_ci_gate_execution_query_branch` | `main` |
| `release_ci_gate_execution_query_head_sha` | `same-release-sha` |
| `release_ci_gate_execution_query_status` | `completed` |
| `release_ci_gate_execution_required_conclusion` | `success` |
| `release_ci_gate_execution_allowed_events` | `push,workflow_dispatch` |
| `release_ci_gate_execution_required_fields` | `ci_workflow_name,ci_workflow_file,ci_run_id,ci_run_attempt,ci_run_url,ci_run_status,ci_run_conclusion,ci_head_sha,ci_head_branch,ci_event,ci_repository,ci_checked_at` |
| `release_ci_gate_execution_ci_summary` | `success` |
| `release_ci_gate_execution_manual_input` | `blocked` |
| `release_ci_gate_execution_package_linux` | `not-defined` |
| `release_ci_gate_execution_workflow_artifact` | `blocked` |
| `release_ci_gate_execution_release_asset` | `blocked` |
| `release_ci_gate_execution_next_action` | `license-notice-and-package-linux-preflight-after-ci-gate` |

`active` 表示 release workflow 已读取 GitHub API 并校验同 commit successful CI run；Linux artifact 仍不能进入
packaging，因为 license/NOTICE confirmation 和后续 artifact gates 尚未完成。

## Active Gate Execution

真实 `release-ci-gate` 必须在 `release-policy` 后、`package-linux` 或任何 artifact job 前运行。
实现可以使用 `gh api` 或 GitHub 官方 REST API，但必须使用 workflow 的 `GITHUB_TOKEN` 和
`actions: read` 权限读取当前 repository 的 workflow runs。

执行边界：

```yaml
release-ci-gate:
  permissions:
    contents: read
    actions: read
  steps:
    - name: Validate same-commit CI success
      run: |
        # Query workflow runs for CI on main with head_sha=${{ github.sha }} and status=completed.
        # Select a success run from the same repository and require CI summary success.
```

字段规则：

| 字段组 | 要求 |
| --- | --- |
| workflow | 固定为 `CI`，workflow file 固定为 `.github/workflows/ci.yml` |
| repository | 必须等于 release run repository，不能接受 fork、mirror 或外部 repository |
| branch | 必须为 `main` |
| head SHA | 必须等于 release run 的 `${{ github.sha }}` |
| status | 必须为 `completed` |
| conclusion | 必须为 `success` |
| event | 只允许 `push` 或受控 `workflow_dispatch` |
| run id/attempt/url | 必须来自 API response 中被选中的成功 run |
| CI summary | 必须确认同一 CI run 的 summary job 成功，且 policy/workspace/Rust/security gate 未被移除 |
| checked at | 使用 UTC 检查时间，只记录结果字段，不记录 API response 原文 |

真实执行成功后，后续 `package-linux`、manifest、release notes 和 release summary 只能消费这些自动化字段，
不得接受 maintainer 手动输入的 run id、run URL、eligible 状态或 artifact path。

## Failure Boundary

真实 `release-ci-gate` 必须在以下情况失败，并且失败必须发生在 `package-linux`、workflow artifact upload、
GitHub Release creation 或 release asset upload 之前：

- workflow 未启用 `actions: read` 却尝试读取 CI run，或启用权限后未执行 API 查询。
- 找不到同 repository、同 commit、`main` 分支、`CI` workflow、`completed`/`success` 的 run。
- 选中的 run 仍为 `queued`、`in_progress`、`waiting`、`requested`、`cancelled`、`timed_out`，或
  conclusion 不是 `success`。
- run 来自 pull request ref、fork、不同 branch、不同 workflow、不同 SHA、不同 repository 或旧 release run。
- run 缺少 CI summary job 成功结论，或关键 policy/workspace/Rust/security gate 被移除。
- release workflow 使用 input、手写 URL、run id、Step Summary 文本、本地命令输出或聊天记录替代 API 查询。
- API response 原文、token、Authorization header、runner 本地绝对路径、secret 或维护者私有身份被写入
  manifest、release notes、release summary 或 Step Summary。
- `package-linux`、`publish-github-release` 或 release asset upload 在 execution status 不是
  `active` 时被定义或执行。

## Release Workflow 边界

当前 release workflow 只能：

- 检查本文档存在和标题。
- 检查 `release-ci-gate` 已启用 `actions: read`，确保 `permission-status=enabled` 与实际权限一致。
- 在 `release-ci-gate`、`linux-artifact-readiness`、release placeholder 和 release summary 中输出 execution
  validation contract active 字段。
- 标记 `release-ci-gate-execution-contract=present`。
- 标记 `release-ci-gate-execution-status=active`。
- 标记 `release-ci-gate-execution-required-permission=actions-read`。
- 标记 `release-ci-gate-execution-permission-status=enabled`。
- 标记 `release-ci-gate-execution-api-status=queried`。
- 标记 `release-ci-gate-execution-query-head-sha=same-release-sha`。
- 标记 `release-ci-gate-execution-required-fields=ci_workflow_name,ci_workflow_file,ci_run_id,ci_run_attempt,ci_run_url,ci_run_status,ci_run_conclusion,ci_head_sha,ci_head_branch,ci_event,ci_repository,ci_checked_at`。
- 标记 `release-ci-gate-execution-ci-summary=success`。
- 标记 `release-ci-gate-execution-package-linux=not-defined`。
- 标记 `release-ci-gate-execution-release-asset=blocked`。
- 标记 `release-ci-gate-execution-next-action=license-notice-and-package-linux-preflight-after-ci-gate`。
- 继续不定义 `package-linux`、`attest-linux`、`publish-eligibility-gate`、`publish-github-release`、
  `post-release-summary` 或等价 publish job。
- 继续不调用 GitHub Actions runs API、GitHub Releases API、`gh release create`、release action、
  upload-release-asset API 或 `actions/upload-artifact`。

## Manifest Binding

真实 `package-linux` manifest 必须把 execution 后的 CI fields 写入 release metadata：

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

manifest 不得写入 API response 原文、GitHub token、secret、runner 本地绝对路径、维护者私有身份或
未公开安全公告细节。

## 验收条件

- 本文档保持在 README、ROADMAP、Release Strategy、CI policy、Release CI success source contract、
  Linux package release CI gate activation validation contract、Linux package publish eligibility execution
  validation contract、Linux package publish eligibility aggregate contract、Linux package artifact job preflight
  validation contract、release CI gate API implementation plan、Linux package artifact manifest design、
  Linux artifact pre-release design 和 Linux CLI artifact 安装/回滚设计中可发现。
- `.github/workflows/ci.yml` governance 检查本文档存在、标题、status、required permission、API status、
  required fields、CI summary、failure boundary 和 release workflow placeholder 输出字段。
- `.github/workflows/release.yml` 的 `release-ci-gate` 检查本文档存在、标题，并输出 execution active 字段。
- `linux-artifact-readiness`、release placeholder 和 release summary 输出 execution active status、required permission、
  queried API status、same release SHA requirement、required fields、CI summary success、manual input blocked、`package-linux`
  not-defined、workflow artifact blocked 和 release asset blocked 状态。
- 当前不生成 artifact、不定义 `package-linux`、不定义 `attest-linux`、不定义
  `publish-eligibility-gate`、不定义 `publish-github-release`、不定义 `post-release-summary`、不创建
  GitHub Release、不上传 workflow artifact、不上传 release asset、不在本机执行测试、构建、打包或发布。

## 后续工作

- Release CI gate API implementation 已激活；下一步在 artifact 路径上必须先完成 license/NOTICE 人工确认，再定义
  `package-linux` preflight，同时继续阻止 GitHub Release asset。
