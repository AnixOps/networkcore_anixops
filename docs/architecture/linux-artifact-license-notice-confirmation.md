# Linux Artifact License Notice Confirmation Design

本文定义首个 Linux `package-linux` artifact 发布前，license/NOTICE 人工确认记录
如何进入仓库、如何被 release readiness 读取，以及在未确认时如何继续阻止真实
Linux release asset。当前状态仍为未确认，不生成 artifact。

评估时间：2026-07-07。

## 目标

- 为 Linux artifact 的 license/NOTICE 人工确认提供稳定、机器可读的来源。
- 明确 pending 与 confirmed 状态的字段，不让 `package-linux` 依赖口头确认。
- 保持人工确认完成前 release workflow 只能处于 placeholder/readiness gate 状态。
- 避免把法律意见、私有授权材料、账号信息或外部平台凭据写入仓库。

## 非目标

- 不完成 license/NOTICE 人工确认。
- 不添加、修改或解释项目 license 文本。
- 不实现 `package-linux` job。
- 不构建、打包、签名、证明或上传 Linux artifact。
- 不把人工姓名、邮箱、法律意见全文、私有合同、token 或外部账号信息写入
  release manifest。

## Source Of Truth

`docs/manual-intervention.md` 是 license/NOTICE 确认状态的仓库内 source of
truth。release workflow 后续只能读取该文件中的机器字段，不应依赖 issue、聊天记录、
本地文件、runner 环境变量或口头确认。

当前未确认状态必须保留以下字段：

```text
linux-artifact-license-notice-status=pending
linux-artifact-license-notice-source-contract=docs/architecture/linux-artifact-license-notice-confirmation.md
linux-artifact-license-notice-package-linux=blocked
linux-artifact-license-notice-release-assets=blocked
```

只要 `linux-artifact-license-notice-status=pending` 存在，`package-linux` 不得定义，
release workflow 不得上传 Linux artifact。

## Confirmed 状态字段

未来人工确认完成后，必须在 `docs/manual-intervention.md` 中用一次独立提交把
pending 字段替换为 confirmed 字段。最小字段如下：

```text
linux-artifact-license-notice-status=confirmed
linux-artifact-license-notice-source-contract=docs/architecture/linux-artifact-license-notice-confirmation.md
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
| `status` | 只允许 `pending` 或 `confirmed` |
| `confirmed-at` | ISO 日期，人工确认完成日期 |
| `confirmed-by` | 固定角色或公开 GitHub handle；不得写邮箱或私有身份信息 |
| `scope` | 首个 Linux artifact 固定为 `networkcore-linux` |
| `license-source` | 仓库内 license 文件路径；真实 packaging 前必须存在 |
| `notice-source` | 仓库内 NOTICE 文件路径，或 `not-required` |
| `artifact-files` | artifact 内必须包含的 license/NOTICE 文件清单 |
| `package-linux` | confirmed 后也只能表示具备进入后续 CI/release gates 的资格 |
| `release-assets` | confirmed 后也只能表示具备进入后续 checksum/signing/rollback gates 的资格 |

确认完成不等于 artifact 可发布。真实发布仍必须满足 CI、checksum、manifest、
signing/attestation、rollback 和安装边界门禁。

## Release Readiness 行为

placeholder 阶段的 `linux-artifact-readiness` 必须：

- 检查本文档存在和标题。
- 检查 `docs/manual-intervention.md` 包含 pending 或未来 confirmed 的机器字段。
- 在 pending 状态下继续输出 `manual-confirmation-required`。
- 在 pending 状态下继续拒绝定义 `package-linux`。
- 在 release placeholder 和 release summary 中输出 license/NOTICE source contract 与当前状态。

未来添加 `package-linux` 前，release workflow 必须先把 pending 检查替换为 confirmed
检查；如果字段缺失、状态非法、license 文件不存在、NOTICE 状态不明确或 artifact
文件清单缺失，workflow 必须失败。

## Manifest 映射

真实 `package-linux` job 生成 manifest 时：

- `license_notice_status` 必须来自 `docs/manual-intervention.md` 的 confirmed 状态。
- `included_files` 中的 license/NOTICE entries 必须来自 `artifact-files`。
- `license-source` 和 `notice-source` 不得指向 runner 本地绝对路径。
- manifest 不得写入人工确认人的邮箱、私有合同或外部凭据。

## 验收条件

- 本文档保持在 README、ROADMAP、Release Strategy、Linux artifact 设计、Linux
  package artifact manifest 设计、Linux package checksum manifest contract、Linux package
  publish/upload boundary contract、Linux package signing/attestation policy binding contract、
  Linux package release notes/rollback policy binding contract、Linux package publish eligibility
  aggregate contract、Linux package license/NOTICE transition validation contract、Linux CLI artifact 安装/回滚设计、
  Release CI success source contract、Linux package
  runner/toolchain/target contract、Linux package archive staging contract 和 CI policy 中可发现。
- `.github/workflows/ci.yml` governance 检查本文档存在和标题。
- `.github/workflows/release.yml` 的 `linux-artifact-readiness` 检查本文档存在、标题和
  `docs/manual-intervention.md` 的 pending marker。
- release placeholder 和 release summary 输出 license/NOTICE source contract 与 pending 状态。
- 不生成 artifact、不定义 `package-linux`、不上传 release asset、不在本机执行测试、
  构建、打包或发布。

## 后续工作

- 在人工确认完成前，继续保持 pending marker 并阻止 Linux artifact。
- Release CI success source contract、Linux package runner/toolchain/target contract、Linux
  package archive staging contract、Linux package checksum manifest contract、Linux package
  publish/upload boundary contract、Linux package signing/attestation policy binding contract、
  Linux package release notes/rollback policy binding contract 和 Linux package publish eligibility
  aggregate contract、Linux package license/NOTICE transition validation contract、Linux package release
  CI gate activation validation contract、Linux package artifact job preflight validation contract、
  Linux package artifact build command validation contract、Linux package artifact staging file validation
  contract、Linux package artifact archive creation validation contract 和 Linux package artifact checksum
  execution validation contract 已定义；Linux package artifact manifest generation validation contract、Linux package artifact manifest checksum validation contract、Linux package workflow artifact bundle upload validation contract、Linux package artifact attestation execution validation contract、Linux package release notes/rollback execution validation contract 和 Linux package publish eligibility execution validation contract 已定义；release CI gate execution validation contract 和 release CI gate API implementation plan 已定义；下一步可以实现 `release-ci-gate` API read，仍不发布 release asset。
