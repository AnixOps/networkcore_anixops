# Alpha Windows Smoke Test

本文定义 alpha 启动阶段的 Windows 手工 smoke 测试记录方式。它是
`docs/manual-intervention.md` 的人工介入补充，不替代 GitHub Actions
`windows-latest` CI 矩阵，也不允许从人工 Windows 机器上传或发布 release artifact。

## Current Candidate

| Field | Value |
| --- | --- |
| Alpha version | `v0.1.0-alpha.1` |
| Commit | `67e86a84388023df77e53537f3f209b5a05c1682` |
| CI run | `28901464670` |
| Release run | `28901692913` |
| Release mode | tag push placeholder |
| Windows CI evidence | `Workspace smoke (windows-latest)` and `Rust build and test (windows-latest)` success |
| Release artifact status | `not-produced-placeholder` |
| Manual Windows environment | Windows 11 24H2 x64 |
| Manual local build/test | `not-run` |
| Manual result | `passed` |

当前 alpha 只证明 release workflow 的 placeholder gate 已启动并通过；它不生成
Linux、Windows、iOS 或其他平台 release asset。Windows installer、Windows service、
code signing、store upload 和 artifact install/run smoke 当前均为 not applicable。

## Manual Scope

用户侧 Windows smoke 可以记录以下事实：

1. Windows 环境信息：Windows 版本、架构、终端、权限模式。
2. 当前 alpha candidate：版本、commit、CI run、release run 是否与上表一致。
3. GitHub Actions Windows 证据：`windows-latest` workspace smoke 和 Rust build/test job
   是否为 success。
4. 如用户进行了额外 Windows 侧探索性运行，必须记录来源、命令、输出摘要和结果；
   该结果只能作为 manual smoke evidence，不能替代 GitHub Actions build/test/package/release
   verification。
5. 若发现失败，记录失败版本、Windows 环境、复现步骤、日志摘要和下一步修复动作。

## Marker Update Contract

测试完成后，用独立提交更新 `docs/manual-intervention.md` 中的
`Alpha Windows Manual Smoke Test` 字段。通过时至少更新：

```text
alpha-release-windows-manual-test-status=confirmed
alpha-release-windows-manual-test-version=v0.1.0-alpha.1
alpha-release-windows-manual-test-commit=<release run head SHA>
alpha-release-windows-manual-test-ci-run=<same-commit CI run id>
alpha-release-windows-manual-test-release-run=<release run id>
alpha-release-windows-manual-test-result=passed
alpha-release-windows-manual-test-confirmed-at=<UTC timestamp>
alpha-release-windows-manual-test-confirmed-by=<GitHub username or operator>
alpha-release-windows-manual-test-next-action=rerun-ci-release-workflows-after-marker-update
```

失败时必须使用 `status=failed` 和 `result=failed`，并新增可审计的失败摘要；
不得把失败或未完成的手工 smoke 记录为 alpha Windows verified。

## Next Automation

marker 更新提交后，必须重新推送并等待 GitHub Actions CI 通过，再按 release policy
从 `main` 重新触发 release workflow。任何真实 Windows artifact 进入 release workflow 前，
还必须先补齐 Windows artifact、service、installer、signing 和 rollback 相关设计与门禁。
