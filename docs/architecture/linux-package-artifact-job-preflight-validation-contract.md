# Linux Package Artifact Job Preflight Validation Contract

本文定义首个 Linux `package-linux` job 在未来真实加入 release workflow 前必须满足的
preflight 验证合同。当前仍是 placeholder；本文只固定未来 job 的依赖、checkout、
toolchain、build、staging 前置顺序、失败条件和继续不上传 artifact 的边界，不定义
`package-linux` job、不构建、不打包、不上传 artifact。

评估时间：2026-07-07。

## 目标

- 明确 `package-linux` 在 license/NOTICE 与 release CI gate 未解除前仍不得定义。
- 固定未来真实 `package-linux` job 的最小 `needs`、preflight 输入和执行顺序。
- 定义 checkout、toolchain setup、build、archive staging 之前必须验证的阻断条件。
- 防止 maintainer 用 workflow input、手写 Step Summary、本地构建产物或旧 run artifact 绕过 release gates。
- 在 preflight 未激活时继续阻止 workflow artifact 和 GitHub Release asset。

## 非目标

- 不实现 `package-linux`、`publish-github-release`、`attest-linux`、`sign-linux`、
  `post-release-summary` 或等价 job。
- 不运行 `cargo build`、不安装 Rust target、不创建 staging 目录、不生成 archive、
  checksum、manifest、attestation、release notes、workflow artifact 或 release asset。
- 不完成 license/NOTICE 人工确认。
- 不启用 release CI gate 的 GitHub API 读取。
- 不把 GitHub token、API response 原文、runner 本地绝对路径、Cargo cache、target 目录、
  secret、证书私钥、用户配置、维护者私有身份或未公开安全公告细节写入 manifest、
  release notes 或 Step Summary。

## Source Of Truth

首个 Linux package artifact job preflight 输入必须来自本文档、
[Linux Package License Notice Transition Validation Contract](linux-package-license-notice-transition-validation-contract.md)、
[Linux Package Release CI Gate Activation Validation Contract](linux-package-release-ci-gate-activation-validation-contract.md)、
[Release CI Gate Execution Validation Contract](release-ci-gate-execution-validation-contract.md)、
[Release CI Success Source Contract](release-ci-success-source-contract.md)、
[Linux Package Artifact Build Command Validation Contract](linux-package-artifact-build-command-validation-contract.md)、
[Linux Package Runner Toolchain Target Contract](linux-package-runner-toolchain-target-contract.md)、
[Linux Package Archive Staging Contract](linux-package-archive-staging-contract.md)、
[Linux Package Checksum Manifest Contract](linux-package-checksum-manifest-contract.md)、
[Linux Package Artifact Manifest Design](linux-package-artifact-manifest.md)、
[Linux Package Publish Upload Boundary Contract](linux-package-publish-upload-boundary-contract.md)、
[Linux Package Publish Eligibility Aggregate Contract](linux-package-publish-eligibility-aggregate-contract.md)、
`docs/manual-intervention.md` 和 release workflow 中的显式常量。

当前 placeholder 固定为：

| 字段 | 值 |
| --- | --- |
| `package_artifact_job_preflight_contract` | `present` |
| `package_artifact_job_preflight_status` | `blocked-placeholder` |
| `package_artifact_job_preflight_source` | `linux-artifact-readiness` |
| `package_artifact_job_preflight_current_mode` | `contract-only-no-package-linux` |
| `package_artifact_job_preflight_required_job` | `package-linux` |
| `package_artifact_job_preflight_job_status` | `not-defined` |
| `package_artifact_job_preflight_required_needs` | `release-policy,release-ci-gate,linux-artifact-readiness` |
| `package_artifact_job_preflight_license_notice_status` | `blocked-pending` |
| `package_artifact_job_preflight_release_ci_gate_status` | `blocked-placeholder` |
| `package_artifact_job_preflight_checkout_status` | `blocked-before-gates` |
| `package_artifact_job_preflight_toolchain_status` | `blocked-before-gates` |
| `package_artifact_job_preflight_build_status` | `blocked-before-gates` |
| `package_artifact_job_preflight_staging_status` | `blocked-before-gates` |
| `package_artifact_job_preflight_upload_status` | `blocked` |
| `package_artifact_job_preflight_workflow_artifact` | `blocked` |
| `package_artifact_job_preflight_release_asset` | `blocked` |
| `package_artifact_job_preflight_failure_mode` | `fail-before-checkout-toolchain-build-staging` |
| `package_artifact_job_preflight_next_action` | `license-notice-and-ci-gate-before-package-linux` |

`blocked-placeholder` 表示 release workflow 已记录未来 `package-linux` job 的 preflight
要求，但当前 release 仍不得创建 job 或执行任何 packaging step。

## Future `package-linux` Job Shape

未来真实 `package-linux` job 必须至少满足以下结构：

```text
package-linux:
  needs:
    - release-policy
    - release-ci-gate
    - linux-artifact-readiness
  runs-on: ubuntu-latest
```

job 内必须按以下顺序处理：

1. 在 checkout 前读取 `needs.*.result`，确认 `release-policy`、`release-ci-gate` 和
   `linux-artifact-readiness` 都为 `success`。
2. 验证 `release-ci-gate` 已输出 active CI gate 字段，且 `ci_head_sha` 等于 release SHA。
3. 验证 license/NOTICE 状态已按 transition contract 从 `pending` 切到 `confirmed`。
4. 执行 `actions/checkout`，且 checkout commit 必须等于 release SHA。
5. 检查本文档、runner/toolchain、archive staging、checksum/manifest、manifest、publish/upload
   和 publish eligibility 合同仍存在并与 release workflow 常量一致。
6. 设置 Rust `stable`/`minimal` toolchain，并确认 target 为 `x86_64-unknown-linux-gnu`。
7. 按 [Linux Package Artifact Build Command Validation Contract](linux-package-artifact-build-command-validation-contract.md)
   构建 `apps/linux-cli` 的 `networkcore-linux` release binary。
8. 验证 build output 只作为本 job staging 输入，不从本地开发机、旧 run artifact 或 runner cache 读取。
9. 创建干净的 staging/output 目录。
10. 按 archive staging contract 复制 binary、INSTALL、LICENSE/NOTICE 和 CHANGELOG。
11. 在任何 staging 校验失败时立即失败，不生成 archive、checksum、manifest 或 upload artifact。
12. 只有后续 checksum、manifest、signing/attestation、release notes/rollback 和 publish eligibility
    gates 全部完成后，才允许进入 workflow artifact upload。

当前 placeholder 不执行以上步骤。

## Preflight Fields

真实 `package-linux` job 激活时必须输出以下字段供后续 job、manifest 和 release summary 使用：

```text
package-linux-preflight=active
package-linux-preflight-contract=docs/architecture/linux-package-artifact-job-preflight-validation-contract.md
package-linux-preflight-needs=release-policy,release-ci-gate,linux-artifact-readiness
package-linux-preflight-license-notice=confirmed
package-linux-preflight-ci-gate=active
package-linux-preflight-release-sha=${release_sha}
package-linux-preflight-checkout-sha=${release_sha}
package-linux-preflight-runner=ubuntu-latest
package-linux-preflight-rust-toolchain=stable
package-linux-preflight-rust-profile=minimal
package-linux-preflight-target=x86_64-unknown-linux-gnu
package-linux-preflight-crate=apps/linux-cli
package-linux-preflight-binary=networkcore-linux
package-linux-preflight-build-output=target/${target}/release/networkcore-linux
package-linux-preflight-staging-root=dist/linux/${target}/staging
package-linux-preflight-output-dir=dist/linux/${target}/artifacts
package-linux-preflight-upload=blocked-until-checksum-manifest-attestation-rollback-eligibility
```

字段规则：

| 字段 | 要求 |
| --- | --- |
| `package-linux-preflight` | 只能从 placeholder 进入 `active`；不能使用 `manual`、`assumed` 或 `skipped` |
| `preflight-contract` | 必须指向本文档 |
| `needs` | 必须包含 release policy、release CI gate 和 Linux artifact readiness |
| `license-notice` | 必须为 `confirmed`；当前 pending 时不得定义 `package-linux` |
| `ci-gate` | 必须为 `active`，并绑定同 commit 成功 CI run |
| `release-sha` | 必须等于 release run 的 `${{ github.sha }}` |
| `checkout-sha` | checkout 后必须等于 release SHA |
| `runner` | 首个 artifact 固定为 `ubuntu-latest` |
| `rust-toolchain` | 固定为 `stable` |
| `rust-profile` | 固定为 `minimal` |
| `target` | 固定为 `x86_64-unknown-linux-gnu` |
| `crate` | 固定为 `apps/linux-cli` |
| `binary` | 固定为 `networkcore-linux` |
| `build-output` | 必须来自同一 release run 的 build step |
| `staging-root` / `output-dir` | 必须与 archive staging contract 一致 |
| `upload` | preflight 只允许进入后续 checksum/manifest gates，不得直接上传 |

## Failure Boundary

真实 preflight 必须在以下情况失败，并且不得执行后续 build、staging、archive、checksum、
manifest、workflow artifact upload 或 release asset upload：

- `release-policy`、`release-ci-gate` 或 `linux-artifact-readiness` 不是 `success`。
- release CI gate 仍为 `placeholder`、`blocked-placeholder`、`not-called`、manual 或 assumed。
- `ci_head_sha`、checkout SHA 或 release SHA 不一致。
- `docs/manual-intervention.md` 仍包含 `linux-artifact-license-notice-status=pending`。
- license/NOTICE confirmed 字段缺失、不一致或指向不存在的 repo 文件。
- runner、toolchain、target、crate、binary、archive naming 或 staging path 与合同不一致。
- job 试图读取本地开发机产物、旧 workflow artifact、cache 中的 binary 或手动上传文件。
- checkout、toolchain、build、staging 任一步缺少 Step Summary 和 machine-readable output 字段。
- staging 目录包含禁止文件、runner 绝对路径、secret、用户配置或非合同允许文件。
- preflight 之后直接上传 workflow artifact 或 GitHub Release asset，绕过 checksum、manifest、
  signing/attestation、release notes/rollback 或 publish eligibility gates。

失败时 release workflow 必须失败在 `package-linux` 内或之前，不得创建 publish job 可消费的 artifact。

## Release Workflow 边界

当前 placeholder release 只能：

- 检查本文档存在和标题。
- 检查本文档包含 current placeholder fields、future preflight fields 和 failure boundary。
- 在 `linux-artifact-readiness`、release placeholder 和 release summary 中输出 artifact job
  preflight validation contract。
- 标记 `linux-package-artifact-job-preflight-contract=present`。
- 标记 `linux-package-artifact-job-preflight-source=linux-artifact-readiness`。
- 标记 `linux-package-artifact-job-preflight-status=blocked-placeholder`。
- 标记 `linux-package-artifact-job-preflight-current-mode=contract-only-no-package-linux`。
- 标记 `linux-package-artifact-job-preflight-required-job=package-linux`。
- 标记 `linux-package-artifact-job-preflight-job-status=not-defined`。
- 标记 `linux-package-artifact-job-preflight-required-needs=release-policy,release-ci-gate,linux-artifact-readiness`。
- 标记 `linux-package-artifact-job-preflight-license-notice=blocked-pending`。
- 标记 `linux-package-artifact-job-preflight-ci-gate=blocked-placeholder`。
- 标记 `linux-package-artifact-job-preflight-checkout=blocked-before-gates`。
- 标记 `linux-package-artifact-job-preflight-toolchain=blocked-before-gates`。
- 标记 `linux-package-artifact-job-preflight-build=blocked-before-gates`。
- 标记 `linux-package-artifact-job-preflight-staging=blocked-before-gates`。
- 标记 `linux-package-artifact-job-preflight-upload=blocked`。
- 标记 `linux-package-artifact-job-preflight-workflow-artifact=blocked`。
- 标记 `linux-package-artifact-job-preflight-release-asset=blocked`。
- 标记 `linux-package-artifact-job-preflight-failure-mode=fail-before-checkout-toolchain-build-staging`。
- 标记 `linux-package-artifact-job-preflight-next-action=license-notice-and-ci-gate-before-package-linux`。
- 继续不定义 `package-linux`、`publish-github-release`、`attest-linux`、`sign-linux` 或
  `post-release-summary`。

## Manifest Binding

真实 manifest 必须能追溯到 preflight 输出：

```json
{
  "package_preflight": {
    "contract": "docs/architecture/linux-package-artifact-job-preflight-validation-contract.md",
    "needs": [
      "release-policy",
      "release-ci-gate",
      "linux-artifact-readiness"
    ],
    "license_notice": "confirmed",
    "ci_gate": "active",
    "release_sha": "<release-sha>",
    "checkout_sha": "<release-sha>",
    "runner": "ubuntu-latest",
    "rust_toolchain": "stable",
    "rust_profile": "minimal",
    "target": "x86_64-unknown-linux-gnu",
    "crate": "apps/linux-cli",
    "binary": "networkcore-linux",
    "build_output": "target/x86_64-unknown-linux-gnu/release/networkcore-linux",
    "staging_root": "dist/linux/x86_64-unknown-linux-gnu/staging",
    "output_dir": "dist/linux/x86_64-unknown-linux-gnu/artifacts"
  }
}
```

manifest 不得写入 runner 本地绝对路径、Cargo cache path、token、secret、GitHub API response
原文、私钥、用户配置、维护者私有身份或未公开安全公告细节。

## 验收条件

- 本文档保持在 README、ROADMAP、Release Strategy、Linux package manifest 设计、Linux CLI
  artifact 安装/回滚设计、Linux package publish eligibility aggregate contract、Linux package
  runner/toolchain/target contract、Linux package archive staging contract、Linux package checksum
  manifest contract、Linux package publish/upload boundary contract、Linux package license/NOTICE
  transition validation contract、release CI success source contract、Linux package release CI gate activation
  validation contract、release CI gate execution validation contract、Linux package artifact build command validation contract、Linux package artifact
  staging file validation contract 和 CI policy 中可发现。
- `.github/workflows/ci.yml` governance 检查本文档存在、标题和 release workflow placeholder 输出字段。
- `.github/workflows/release.yml` 的 `linux-artifact-readiness` 检查本文档存在、标题、placeholder
  fields、future preflight fields、failure boundary 和 `package-linux` 未定义状态。
- release placeholder 和 release summary 输出 preflight status、required job、required needs、
  license/NOTICE blocked、CI gate blocked、checkout/toolchain/build/staging blocked、upload blocked
  和 next action。
- 当前不生成 artifact、不定义 `package-linux`、不定义 `publish-github-release`、不上传 workflow
  artifact、不上传 release asset、不在本机执行测试、构建、打包或发布。

## 后续工作

- 在 license/NOTICE 人工确认完成和 release CI gate activation 实现前，继续保持
  `package-linux` 未定义。
- Linux package artifact build command validation contract、Linux package artifact staging file validation
  contract、Linux package artifact archive creation validation contract 和 Linux package artifact checksum
  execution validation contract 已定义；Linux package artifact manifest generation validation contract
  和 Linux package artifact manifest checksum validation contract 已定义；下一步可以补充 Linux
  package workflow artifact bundle upload validation contract，明确真实 manifest checksum sidecar 生成后
  校验 release bundle 文件集、上传同一 release run workflow artifact 和仍不发布 release asset 的边界。
