# Release CI Success Source Contract

本文定义真实 `package-linux` 或其他平台 artifact job 加入前，release workflow
如何证明当前 release commit 已经在 `main` 上通过 CI。当前 `release-ci-gate` 已通过
GitHub Actions API 自动读取同 repository、同 commit、`main` 分支成功 CI run；但仍不构建、不打包、不发布 artifact。

评估时间：2026-07-07。

## 目标

- 为真实 artifact packaging 前的同 commit CI 成功门禁定义稳定 source contract。
- 明确后续 release workflow 必须从 GitHub Actions 读取的 run/source 字段。
- 避免 `package-linux` 只依赖人工判断、聊天记录、本地命令或不相关 CI run。
- 保持当前 placeholder release 不生成 artifact。

## 非目标

- 不实现真实 `package-linux` job。
- 不在 placeholder 阶段调用 GitHub API 强制查询 CI run。
- 不在本机构建、测试、打包或发布。
- 不接受本地测试输出、未完成 run、PR-only run、失败 run、不同 commit run 或不同分支 run
  作为 packaging 依据。

## Source Of Truth

未来真实 artifact packaging 前，release workflow 必须从 GitHub Actions 当前仓库读取
CI run。允许来源：

- workflow 文件：`.github/workflows/ci.yml`
- workflow 名称：`CI`
- repository：当前 release run 所在仓库
- branch：`main`
- commit：当前 release run 的 `${{ github.sha }}`
- conclusion：`success`
- status：`completed`

当前阶段已由 `release-ci-gate` 自动读取和失败门禁实现该合同。真实 packaging 前，后续 `package-linux`
只能消费这些自动化字段，不能接受人工输入的 CI URL 或 run id。

## Required Fields

真实 gate 必须读取并在 release summary、artifact manifest 或 release notes 中暴露以下字段：

| 字段 | 要求 |
| --- | --- |
| `ci_workflow_name` | 固定为 `CI` |
| `ci_workflow_file` | 固定为 `.github/workflows/ci.yml` |
| `ci_run_id` | 成功 CI run 的 GitHub Actions run id |
| `ci_run_attempt` | 成功 run attempt |
| `ci_run_url` | 成功 CI run URL |
| `ci_run_status` | 必须为 `completed` |
| `ci_run_conclusion` | 必须为 `success` |
| `ci_head_sha` | 必须等于 release run 的 commit SHA |
| `ci_head_branch` | 必须为 `main` |
| `ci_event` | `push` 或受控 `workflow_dispatch` |
| `ci_repository` | 必须等于 release run repository |
| `ci_checked_at` | release workflow 完成检查的 UTC 时间 |

真实 `package-linux` job 只能依赖这些字段的自动化结果，不得由 maintainer 手动输入
CI URL 或 run id 后绕过校验。

## Rejection Rules

真实 gate 必须拒绝以下情况：

- 找不到同 repository、同 commit、`main` 分支上的成功 CI run。
- CI run 仍在 `queued`、`in_progress` 或 `waiting`。
- CI run conclusion 不是 `success`。
- CI run 来自 pull request ref、fork、不同 commit、不同 branch 或不同 workflow。
- run 成功但关键 job 被移除，导致 CI summary 不再门禁 policy、workspace、build/test、
  lint 或 security audit。
- release run commit 与 artifact manifest 中记录的 `commit_sha` 不一致。

拒绝时 release workflow 必须失败，并且不得执行 `package-linux`、上传 workflow artifact
或发布 release asset。

## Active Gate 行为

当前 `release-ci-gate` 必须：

- 输出当前 release commit、ref、event 和 required future gate。
- 输出本文档路径和 required CI source 字段清单。
- 标记 `release-ci-gate=active`。
- 标记 `release-ci-success-source-contract=present`。
- 查询 workflow runs API 和 workflow jobs API。
- 输出 `ci_workflow_name`、`ci_workflow_file`、`ci_run_id`、`ci_run_attempt`、`ci_run_url`、`ci_run_status`、
  `ci_run_conclusion`、`ci_head_sha`、`ci_head_branch`、`ci_event`、`ci_repository` 和 `ci_checked_at`。
- 为 `package-linux`、attestation、publish eligibility 和 GitHub Release upload 提供同 commit CI gate。

该 active gate 证明同 commit CI 已通过；artifact 是否发布仍由 checksum、manifest、attestation、release notes、
rollback 和 publish eligibility gates 共同决定。

## Artifact Manifest 映射

真实 `package-linux` manifest 必须映射：

- `ci_run_url` 来自成功 CI run URL。
- `commit_sha` 等于 `ci_head_sha` 和 release SHA。
- `source_ref` 等于 release ref。
- `release_run_url` 等于当前 release run URL。

manifest 不得写入 GitHub token、API response 原文、runner 本地路径或维护者私有信息。

## 验收条件

- 本文档保持在 README、ROADMAP、Release Strategy、Linux artifact 设计、Linux package
  manifest 设计、Linux package checksum manifest contract、Linux package publish/upload boundary
  contract、Linux package signing/attestation policy binding contract、Linux package release notes/rollback
  policy binding contract、Linux package publish eligibility aggregate contract、Linux package license/NOTICE
  transition validation contract、Linux package release CI gate activation validation contract、Linux package
  release CI gate execution validation contract、release CI gate API implementation plan、Linux package
  artifact job preflight validation contract、Linux CLI artifact 安装/回滚设计、Linux package
  runner/toolchain/target contract、Linux package archive staging contract 和 CI policy 中可发现。
- `.github/workflows/ci.yml` governance 检查本文档存在和标题。
- `.github/workflows/release.yml` 的 `release-ci-gate` 检查本文档和
  [Linux Package Release CI Gate Activation Validation Contract](linux-package-release-ci-gate-activation-validation-contract.md)
  以及 [Release CI Gate Execution Validation Contract](release-ci-gate-execution-validation-contract.md)
  和 [Release CI Gate API Implementation Plan](release-ci-gate-api-implementation-plan.md)
  存在和标题，并输出 `release-ci-success-source-contract=present`、activation active 字段、execution
  active 字段与 API implementation active 字段。
- release summary 输出 release CI source contract、activation validation contract、execution validation contract、
  API implementation plan 与 required fields。
- `package-linux`、attestation 和 publish jobs 只能在 GitHub Actions 中运行；本机仍不得执行测试、
  构建、打包或发布。

## 后续工作

- 当前 artifact 路径已进入 confirmed release path；release workflow 继续输出 source contract 和 active CI 字段。
- Linux package runner/toolchain/target contract、Linux package archive staging contract、Linux
  package checksum manifest contract、Linux package publish/upload boundary contract、Linux package
  signing/attestation policy binding contract、Linux package release notes/rollback policy binding
  contract、Linux package publish eligibility aggregate contract 和 Linux package license/NOTICE transition
  validation contract、Linux package release CI gate activation validation contract 已在 release placeholder
  中输出；Linux package artifact job preflight validation contract、Linux package artifact build command validation contract、Linux package artifact staging file validation contract、Linux package artifact archive creation validation contract 和 Linux package artifact checksum execution validation contract 已定义；Linux package artifact manifest generation validation contract、Linux package artifact manifest checksum validation contract、Linux package workflow artifact bundle upload validation contract、Linux package artifact attestation execution validation contract、Linux package release notes/rollback execution validation contract 和 Linux package publish eligibility execution validation contract 已定义；release CI gate execution validation contract 和 release CI gate API implementation 已激活；当前 artifact 路径已进入 confirmed release path；后续 tag release 继续通过 release workflow、同 commit CI、checksum、manifest、attestation、release notes、rollback 和 publish eligibility gates 生成和发布 Linux assets。
