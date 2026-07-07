# Release CI Gate API Implementation Plan

本文定义 `release-ci-gate` 从 placeholder 进入真实 GitHub Actions API 读取前的最小实现计划。当前仍不启用
`actions: read`，不调用 GitHub API，不定义 `package-linux`，不生成 workflow artifact 或 release asset。

评估时间：2026-07-07。

## 目标

- 固定 release workflow 未来读取 CI run 的最小 API 调用顺序。
- 明确启用 `actions: read` 前必须满足的权限、查询、选择、CI summary 校验和输出字段。
- 让 implementation PR 可以逐项替换 `blocked-placeholder`，而不是一次性加入 packaging 和发布。
- 继续阻止任何人工输入 run id、run URL、Step Summary 文本或本地命令输出绕过 CI gate。

## 非目标

- 不在本增量中启用 `actions: read`。
- 不在本增量中执行 `gh api`、REST API 查询或 GraphQL 查询。
- 不定义 `package-linux`、`attest-linux`、`post-release-summary`、`publish-eligibility-gate`、
  `publish-github-release` 或等价 publish job。
- 不生成 archive、checksum、manifest、workflow artifact、attestation、release notes、GitHub Release
  或 release asset。
- 不把 API response 原文、token、Authorization header、runner 本地绝对路径、secret 或维护者私有身份写入
  manifest、release notes、release summary 或 Step Summary。

## Source Of Truth

本计划依赖以下合同和 workflow：

- [Release CI Success Source Contract](release-ci-success-source-contract.md)
- [Linux Package Release CI Gate Activation Validation Contract](linux-package-release-ci-gate-activation-validation-contract.md)
- [Release CI Gate Execution Validation Contract](release-ci-gate-execution-validation-contract.md)
- [Linux Package Artifact Job Preflight Validation Contract](linux-package-artifact-job-preflight-validation-contract.md)
- [Linux Package Publish Eligibility Execution Validation Contract](linux-package-publish-eligibility-execution-validation-contract.md)
- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`

当前计划固定为：

| 字段 | 值 |
| --- | --- |
| `release_ci_gate_api_plan_contract` | `present` |
| `release_ci_gate_api_plan_status` | `blocked-design-only` |
| `release_ci_gate_api_plan_required_permission` | `actions-read` |
| `release_ci_gate_api_plan_permission_activation` | `separate-implementation-pr` |
| `release_ci_gate_api_plan_workflow_endpoint` | `actions/workflows/ci.yml/runs` |
| `release_ci_gate_api_plan_jobs_endpoint` | `actions/runs/{run_id}/jobs` |
| `release_ci_gate_api_plan_query_filters` | `branch=main,head_sha=same-release-sha,status=completed,exclude_pull_requests=true` |
| `release_ci_gate_api_plan_required_conclusion` | `success` |
| `release_ci_gate_api_plan_allowed_events` | `push,workflow_dispatch` |
| `release_ci_gate_api_plan_ci_summary` | `required-success` |
| `release_ci_gate_api_plan_selection` | `newest-success-same-repository-same-sha-ci-summary-success` |
| `release_ci_gate_api_plan_output_mode` | `sanitized-fields-only` |
| `release_ci_gate_api_plan_rollback` | `revert-to-blocked-placeholder-before-package-linux` |
| `release_ci_gate_api_plan_package_linux` | `not-defined` |
| `release_ci_gate_api_plan_release_asset` | `blocked` |
| `release_ci_gate_api_plan_next_action` | `implement-release-ci-gate-api-read-before-package-linux` |

## API Implementation Steps

The future implementation PR must change only the CI gate first:

1. Give `release-ci-gate` job-level `permissions: contents: read, actions: read`.
2. Use the workflow-runs endpoint for `.github/workflows/ci.yml` with `branch=main`, `head_sha=${{ github.sha }}`,
   `status=completed`, `exclude_pull_requests=true`, and bounded pagination.
3. Filter returned runs to the current repository, `name == "CI"`, `path == ".github/workflows/ci.yml"`,
   `head_branch == "main"`, `head_sha == ${{ github.sha }}`, `conclusion == "success"`, and event in
   `push,workflow_dispatch`.
4. Select the newest matching run by `run_attempt` and `updated_at`; if more than one remains with equivalent
   freshness, fail closed instead of guessing.
5. Use the workflow-jobs endpoint for the selected `run_id` and require `CI summary` to be `completed/success`.
6. Require the selected run to still expose the policy, workspace, Rust build/test, and Rust audit jobs that
   `docs/ci-cd-policy.md` treats as gating for this repository.
7. Write only sanitized fields to `$GITHUB_OUTPUT` and Step Summary:
   `ci_workflow_name`, `ci_workflow_file`, `ci_run_id`, `ci_run_attempt`, `ci_run_url`, `ci_run_status`,
   `ci_run_conclusion`, `ci_head_sha`, `ci_head_branch`, `ci_event`, `ci_repository`, and `ci_checked_at`.
8. Keep `package-linux`, workflow artifact upload, GitHub Release creation, and release asset upload undefined until
   this gate is active and the remaining artifact gates are separately complete.

## Failure Boundary

The future implementation must fail before any artifact job if:

- `actions: read` is absent, or the API query did not run.
- The workflow-runs endpoint returns no same repository, same SHA, `main`, `CI`, `completed/success` run.
- The selected run is from a pull request ref, fork, different workflow file, different branch, different SHA or
  different repository.
- The selected run is still queued or in progress, or its conclusion is not `success`.
- The selected run lacks a successful `CI summary` job or the required policy/workspace/Rust/security jobs.
- The implementation accepts manual run id, run URL, release input, Step Summary text, local command output or chat
  transcript as gate evidence.
- API response JSON, token, Authorization header, runner local absolute path, secret or private maintainer identity is
  written to manifest, release notes, release summary or Step Summary.
- `package-linux`, workflow artifact upload, GitHub Release creation or release asset upload becomes reachable while
  `release_ci_gate_api_plan_status=blocked-design-only` or `release-ci-gate-execution-status=blocked-placeholder`.

## Rollback Plan

If the first implementation PR fails in GitHub Actions:

- Revert the `actions: read` permission change first.
- Restore `release-ci-gate-execution-status=blocked-placeholder`.
- Keep all artifact and publish jobs undefined.
- Keep the selected CI run fields out of manifest/release notes until a later successful implementation PR.
- Record any GitHub API shape change in this plan before retrying.

## Current Placeholder Requirements

This plan only requires the repository to:

- Keep this document discoverable from README, ROADMAP, release strategy, CI policy, release CI success source contract
  and release CI gate execution validation contract.
- Have CI governance check this document title, status, required permission, workflow endpoint, jobs endpoint,
  query filters, CI summary, selection rule, rollback rule, `package-linux` blocked state and release asset blocked
  state.
- Continue not defining `package-linux`, `attest-linux`, `post-release-summary`, `publish-eligibility-gate`,
  `publish-github-release` or release asset upload.

## References

- GitHub REST API workflow runs: `https://docs.github.com/en/rest/actions/workflow-runs`
- GitHub REST API workflow jobs: `https://docs.github.com/en/rest/actions/workflow-jobs`

## 后续工作

- 在单独增量中实现 `release-ci-gate` API read，并让 GitHub Actions 证明 selected CI run 与 CI summary job
  校验能通过。
- 在 release CI gate API read 通过前继续保持 `package-linux` 不存在、workflow artifact blocked、release asset
  blocked。
