# Release CI Gate API Implementation Plan

本文定义并记录 `release-ci-gate` 从 placeholder 进入真实 GitHub Actions API 读取的最小实现。当前 release
workflow 已在 `release-ci-gate` job 级启用 `actions: read`，调用 GitHub Actions workflow runs API 与 workflow
jobs API，自动校验同 repository、同 commit、`main` 分支的成功 `CI` run 和 `CI summary` job；但仍不定义
`package-linux`，不上传 workflow artifact 或 release asset。

评估时间：2026-07-07。

## 目标

- 明确 `release-ci-gate` 的第一步实现只读取同 repository、同 commit、`main` 分支的 `CI` workflow run。
- 固定 GitHub Actions workflow runs API 和 workflow jobs API 的最小使用方式。
- 定义成功 run 的选择规则、CI summary job 成功校验和 machine-readable 输出字段。
- 保持实现顺序可回滚：API read 激活早于 `package-linux`、workflow artifact upload、attestation 和 GitHub Release asset。
- 防止 maintainer 用手写 run id、run URL、Step Summary 文本、聊天记录或本地命令绕过自动校验。

## 非目标

- 不定义 `package-linux`、`attest-linux`、`publish-eligibility-gate`、`publish-github-release`、
  `post-release-summary` 或等价 publish job。
- 不生成 archive、checksum、manifest、workflow artifact、attestation、release notes、GitHub Release
  或 release asset。
- 不把 GitHub token、Authorization header、API response 原文、runner 本地绝对路径、secret、维护者私有身份或
  未公开安全公告细节写入 manifest、release notes、release summary 或 Step Summary。

## Source Of Truth

首个 release CI gate API implementation 输入必须来自本文档、
[Release CI Success Source Contract](release-ci-success-source-contract.md)、
[Linux Package Release CI Gate Activation Validation Contract](linux-package-release-ci-gate-activation-validation-contract.md)、
[Release CI Gate Execution Validation Contract](release-ci-gate-execution-validation-contract.md)、
[Linux Package Artifact Job Preflight Validation Contract](linux-package-artifact-job-preflight-validation-contract.md)、
[Linux Package Publish Eligibility Execution Validation Contract](linux-package-publish-eligibility-execution-validation-contract.md)、
[Linux Package Publish Eligibility Aggregate Contract](linux-package-publish-eligibility-aggregate-contract.md)、
release workflow、CI workflow 和 `docs/manual-intervention.md` 中的显式机器字段。

当前 active API read 固定为：

| 字段 | 值 |
| --- | --- |
| `release_ci_gate_api_implementation_plan` | `docs/architecture/release-ci-gate-api-implementation-plan.md` |
| `release_ci_gate_api_implementation_status` | `active` |
| `release_ci_gate_api_implementation_source` | `release-ci-gate` |
| `release_ci_gate_api_implementation_current_mode` | `api-read-active` |
| `release_ci_gate_api_implementation_required_permission` | `actions-read` |
| `release_ci_gate_api_implementation_permission_status` | `enabled` |
| `release_ci_gate_api_implementation_runs_endpoint` | `GET /repos/{owner}/{repo}/actions/workflows/ci.yml/runs` |
| `release_ci_gate_api_implementation_jobs_endpoint` | `GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs` |
| `release_ci_gate_api_implementation_query_filters` | `branch=main,status=completed,head_sha=same-release-sha` |
| `release_ci_gate_api_implementation_selection_rule` | `latest-successful-same-sha-main-ci` |
| `release_ci_gate_api_implementation_summary_job` | `CI summary` |
| `release_ci_gate_api_implementation_summary_status` | `success` |
| `release_ci_gate_api_implementation_output_fields` | `ci_workflow_name,ci_workflow_file,ci_run_id,ci_run_attempt,ci_run_url,ci_run_status,ci_run_conclusion,ci_head_sha,ci_head_branch,ci_event,ci_repository,ci_checked_at` |
| `release_ci_gate_api_implementation_manual_input` | `blocked` |
| `release_ci_gate_api_implementation_package_linux` | `not-defined` |
| `release_ci_gate_api_implementation_workflow_artifact` | `blocked` |
| `release_ci_gate_api_implementation_release_asset` | `blocked` |
| `release_ci_gate_api_implementation_next_action` | `license-notice-and-package-linux-preflight-after-ci-gate` |

`active` 表示 release workflow 已自动读取并校验同 commit CI 成功结果；Linux artifact 仍不能进入 packaging，
因为 license/NOTICE confirmation、`package-linux` preflight、checksum/manifest、workflow artifact bundle、attestation、
release notes/rollback 和 publish eligibility gates 尚未完成。

## Active API Query

第一版真实实现只在 `release-ci-gate` job 内加入 API read，并保持 `package-linux` 未定义。该 job 必须在
`release-policy` 成功后运行，并在任何 artifact job、workflow artifact upload 或 release asset upload 前失败阻断。

最小 workflow 权限形态：

```yaml
permissions:
  contents: read
  actions: read
```

实现查询顺序：

1. 使用 `GITHUB_TOKEN` 调用 workflow runs API：
   `GET /repos/{owner}/{repo}/actions/workflows/ci.yml/runs?branch=main&status=completed&head_sha=${release_sha}&per_page=20`。
2. 从 `workflow_runs` 中筛选 `name=CI`、`path=.github/workflows/ci.yml`、`head_branch=main`、
   `head_sha=${release_sha}`、`status=completed`、`conclusion=success`、`repository.full_name=${release_repository}`。
3. `event` 只接受 `push` 或受控 `workflow_dispatch`；不得接受 `pull_request`、fork、mirror、旧 branch 或旧 commit run。
4. 如存在多个符合条件的 run，选择 `run_attempt`/`created_at` 最新的成功 run，并记录该选择规则。
5. 使用选中 run 的 `id` 调用 workflow jobs API：
   `GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs?filter=latest&per_page=100`。
6. 在 jobs response 中要求 `name=CI summary` 的 job 存在且 `status=completed`、`conclusion=success`。
7. 输出 required CI source fields，并通过 `release-ci-gate` job outputs 供后续 `package-linux`、manifest、release notes 和 release summary 消费。
8. 只记录整理后的字段，不记录 API response 原文。

## Active Output Fields

API read 成功后，`release-ci-gate` 输出 active 字段：

```text
release-ci-gate=active
release-ci-gate-api-implementation-plan=docs/architecture/release-ci-gate-api-implementation-plan.md
release-ci-gate-api-implementation-status=active
release-ci-gate-api-implementation-permission=actions-read
release-ci-gate-api-implementation-runs-endpoint=GET /repos/{owner}/{repo}/actions/workflows/ci.yml/runs
release-ci-gate-api-implementation-jobs-endpoint=GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs
release-ci-gate-api-implementation-query-filters=branch=main,status=completed,head_sha=${release_sha}
release-ci-gate-api-implementation-selection-rule=latest-successful-same-sha-main-ci
release-ci-gate-api-implementation-summary-job=CI summary
release-ci-gate-api-implementation-summary-status=success
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
| `release-ci-gate` | 只能从 `placeholder` 切换为 `active`；不能使用 `manual`、`assumed`、`skipped` |
| `status` | API implementation 成功后必须为 `active` |
| `permission` | 必须对应 workflow 中显式 `actions: read` |
| `runs-endpoint` | 固定为 workflow file `ci.yml` 的 workflow runs endpoint |
| `jobs-endpoint` | 固定为选中 run 的 workflow jobs endpoint |
| `query-filters` | 必须包含 `branch=main`、`status=completed` 和 release SHA |
| `selection-rule` | 必须选择 same SHA、same branch、same repository 的成功 CI run |
| `summary-job` | 固定检查 `CI summary` job |
| `ci_run_url` | 必须来自选中 run 的 `html_url` |
| `ci_checked_at` | UTC 时间戳，只记录检查时间 |

## Failure And Rollback Boundary

真实 API implementation 必须在以下情况失败，并且失败必须发生在 `package-linux`、workflow artifact upload、
GitHub Release creation 或 release asset upload 之前：

- workflow 未启用 `actions: read` 却尝试查询 API，或启用后没有执行 API 查询。
- workflow runs API 返回空结果、非 2xx、分页结果不完整且未继续查询，或 rate limit/authorization 失败。
- 选中 run 不是同 repository、同 commit、`main`、`.github/workflows/ci.yml`、`CI` workflow。
- 选中 run 的 `status` 不是 `completed`，或 `conclusion` 不是 `success`。
- 选中 run 的 `event` 不是 `push` 或受控 `workflow_dispatch`。
- 选中 run 缺少 `CI summary` job，或该 job 不是 `completed`/`success`。
- workflow 使用输入参数、手写 URL、手写 run id、Step Summary 文本、本地命令输出或聊天记录替代 API 查询。
- API response 原文、GitHub token、Authorization header、secret、runner 本地绝对路径、维护者私有身份或未公开安全公告细节被写入输出。
- `package-linux`、workflow artifact upload、GitHub Release creation 或 release asset upload 在 API implementation status
  不是 `active` 时被定义或执行。

回滚边界：

- 如果 API read 实现导致 release workflow 失败，回滚只需恢复 `release-ci-gate` 为 plan-only/placeholder 字段，并移除
  `actions: read` 权限。
- 回滚不得引入 `package-linux` 或 release asset。
- 回滚后 `release-ci-gate-api-implementation-status` 必须回到 `planned-blocked`。

## Release Workflow 边界

当前 release workflow API read 只能：

- 检查本文档存在和标题。
- 检查 release workflow 已为 `release-ci-gate` 启用 `actions: read`，确保 `permission-status=enabled` 与实际权限一致。
- 在 `release-ci-gate` 中查询 GitHub Actions workflow runs API 与 workflow jobs API。
- 在 `release-ci-gate`、`linux-artifact-readiness`、release placeholder 和 release summary 中输出 API implementation active 字段。
- 标记 `release-ci-gate-api-implementation-plan=docs/architecture/release-ci-gate-api-implementation-plan.md`。
- 标记 `release-ci-gate-api-implementation-status=active`。
- 标记 `release-ci-gate-api-implementation-current-mode=api-read-active`。
- 标记 `release-ci-gate-api-implementation-required-permission=actions-read`。
- 标记 `release-ci-gate-api-implementation-permission-status=enabled`。
- 标记 `release-ci-gate-api-implementation-runs-endpoint=GET /repos/{owner}/{repo}/actions/workflows/ci.yml/runs`。
- 标记 `release-ci-gate-api-implementation-jobs-endpoint=GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs`。
- 标记 `release-ci-gate-api-implementation-query-filters=branch=main,status=completed,head_sha=same-release-sha`。
- 标记 `release-ci-gate-api-implementation-summary-job=CI summary`。
- 标记 `release-ci-gate-api-implementation-summary-status=success`。
- 标记 `release-ci-gate-api-implementation-package-linux=not-defined`。
- 标记 `release-ci-gate-api-implementation-release-asset=blocked`。
- 标记 `release-ci-gate-api-implementation-next-action=license-notice-and-package-linux-preflight-after-ci-gate`。
- 继续不调用 GitHub Releases API、`gh release create`、release action、upload-release-asset API 或
  `actions/upload-artifact`。

## 验收条件

- 本文档保持在 README、ROADMAP、Release Strategy、CI policy、Release CI success source contract、
  Linux package release CI gate activation validation contract、Release CI gate execution validation contract、
  Linux package artifact job preflight validation contract、Linux package publish eligibility execution validation contract
  和 TODO 中可发现。
- `.github/workflows/ci.yml` governance 检查本文档存在、标题、status、runs endpoint、jobs endpoint、query filters、
  summary job、failure and rollback boundary 和 release workflow placeholder 输出字段。
- `.github/workflows/release.yml` 的 `release-ci-gate` 检查本文档存在、标题，启用 `actions: read`，调用 API，
  校验同 commit successful CI run 和 `CI summary` job，并输出 API implementation active 字段与 required CI source fields。
- `linux-artifact-readiness`、release placeholder 和 release summary 输出 API implementation plan status、required
  permission、runs endpoint、jobs endpoint、query filters、summary job、manual input blocked、`package-linux` not-defined、
  workflow artifact blocked 和 release asset blocked 状态。
- 当前不生成 artifact、不定义 `package-linux`、不定义 `attest-linux`、不定义
  `publish-eligibility-gate`、不定义 `publish-github-release`、不定义 `post-release-summary`、不创建
  GitHub Release、不上传 workflow artifact、不上传 release asset、不在本机执行测试、构建、打包或发布。

## 后续工作

- `release-ci-gate` API read 已激活；下一步在 artifact 路径上必须先完成 license/NOTICE confirmed marker，然后才能定义
  `package-linux` preflight。
- 即使 API read 激活，Linux artifact 发布仍必须等待 license/NOTICE confirmed marker、`package-linux` preflight、
  checksum/manifest、workflow artifact bundle、attestation、release notes/rollback 和 publish eligibility gates。
