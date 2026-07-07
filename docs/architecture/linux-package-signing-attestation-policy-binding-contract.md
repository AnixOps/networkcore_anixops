# Linux Package Signing Attestation Policy Binding Contract

本文定义首个真实 Linux `package-linux` artifact 在进入 publish/upload 前必须遵守的
签名、attestation、provenance 字段和未启用时的阻断策略。当前仍为 placeholder 合同，
不定义 `package-linux` job、不定义 `attest-linux` job、不签名、不生成 provenance、不上传
workflow artifact 或 GitHub Release asset。

评估时间：2026-07-07。

## 目标

- 明确首个 Linux CLI tarball 的签名策略、attestation 策略和 provenance 来源。
- 固定 release summary、manifest 和 publish gate 必须读取的 signing/attestation 字段。
- 说明当前未启用 signing/attestation 时的 blocked 状态，避免把未证明产物误认为可发布。
- 在 license/NOTICE、同 commit CI success、checksum/manifest checksum、publish/upload 和
  rollback gates 完成前继续阻止真实 artifact。

## 非目标

- 不实现 `package-linux` job。
- 不实现 `attest-linux`、`sign-linux` 或等价 signing job。
- 不生成 detached signature、GitHub artifact attestation、provenance bundle 或 release asset。
- 不引入本地 signing key、GPG key、cosign key、证书私钥或 GitHub Secrets。
- 不定义 macOS notarization、Windows Authenticode、iOS App Store attestation 或商店签名策略。
- 不把 GitHub token、API response 原文、runner 本地绝对路径、secret、证书私钥或用户配置写入
  manifest、release notes 或 Step Summary。

## Source Of Truth

首个真实 Linux signing/attestation 输入必须来自本文档、
[Linux Package Artifact Manifest Design](linux-package-artifact-manifest.md)、
[Linux Package Checksum Manifest Contract](linux-package-checksum-manifest-contract.md)、
[Linux Package Publish Upload Boundary Contract](linux-package-publish-upload-boundary-contract.md)、
[Linux Package Artifact Attestation Execution Validation Contract](linux-package-artifact-attestation-execution-validation-contract.md)、
[Linux Package Release Notes Rollback Policy Binding Contract](linux-package-release-notes-rollback-policy-binding-contract.md)、
[Linux Package Publish Eligibility Aggregate Contract](linux-package-publish-eligibility-aggregate-contract.md)、
[Linux Package License Notice Transition Validation Contract](linux-package-license-notice-transition-validation-contract.md)、
[Release CI Success Source Contract](release-ci-success-source-contract.md) 和 release workflow 中的
显式常量。不得由 maintainer 在 `workflow_dispatch` 中手动输入 signing status、attestation
status、provenance reference 或 release asset eligibility 来绕过门禁。

当前首个 Linux signing/attestation policy 固定为：

| 字段 | 值 |
| --- | --- |
| `package_signing_attestation_policy_contract` | `present` |
| `package_signing_policy` | `unsigned-no-detached-signature` |
| `package_signing_status` | `blocked-not-signed` |
| `package_detached_signature_required` | `false` |
| `package_signature_asset` | `not-included` |
| `package_signing_job_name` | `not-defined-until-detached-signature-policy` |
| `package_attestation_policy` | `github-artifact-attestation-required` |
| `package_attestation_status` | `blocked-not-attested` |
| `package_attestation_job_name` | `attest-linux` |
| `package_attestation_download_source` | `same-run-workflow-artifact` |
| `package_attestation_subjects` | `archive,archive_sha256,manifest,manifest_sha256` |
| `package_provenance_policy` | `github-build-provenance-required` |
| `package_provenance_file` | `github-artifact-attestation` |
| `package_provenance_status` | `blocked-not-generated` |
| `package_publish_requires_attestation` | `true` |
| `package_publish_without_attestation` | `blocked` |

首个 Linux tarball 不使用 detached signature。它必须在公开 GitHub Release asset 前具备同一
release run 内生成的 GitHub artifact attestation/provenance 记录；如果后续选择 GPG、
cosign keyless bundle、Sigstore bundle 或其他 detached signature 文件，必须先更新本文档、
manifest 设计和 publish/upload boundary。

## Manifest Binding

真实 `package-linux` manifest 的 `signing` object 必须与本文档和 release workflow outputs
完全一致。首个 Linux artifact 的最小发布前状态为：

```json
{
  "signing_policy": "unsigned-no-detached-signature",
  "signing_status": "not-signed-by-policy",
  "attestation_policy": "github-artifact-attestation-required",
  "attestation_status": "attested",
  "provenance_policy": "github-build-provenance-required",
  "provenance_file": "github-artifact-attestation"
}
```

当前 placeholder 不生成 manifest，只能输出 blocked 状态：

```json
{
  "signing_policy": "unsigned-no-detached-signature",
  "signing_status": "blocked-not-signed",
  "attestation_policy": "github-artifact-attestation-required",
  "attestation_status": "blocked-not-attested",
  "provenance_policy": "github-build-provenance-required",
  "provenance_file": "github-artifact-attestation",
  "provenance_status": "blocked-not-generated"
}
```

`provenance_file=github-artifact-attestation` 表示 provenance 来源是 GitHub artifact attestation
记录，而不是当前仓库内的静态文件。真实 release summary 必须输出可验证的 attestation/provenance
引用；当前 placeholder 只能输出 blocked 状态。

## Job Boundary

真实 release workflow 后续必须按以下顺序处理 Linux signing/attestation：

1. `package-linux` 生成 archive、archive checksum、manifest 和 manifest checksum。
2. `package-linux` 上传同一 release run 的 workflow artifact bundle。
3. `attest-linux` 从 `same-run-workflow-artifact` 下载 bundle。
4. `attest-linux` 对 archive、archive checksum、manifest 和 manifest checksum 生成 GitHub
   artifact attestation/provenance。
5. `attest-linux` 输出 signing/attestation/provenance 字段到 job outputs 和 Step Summary。
6. `publish-github-release` 下载同一 run 的 workflow artifact bundle。
7. `publish-github-release` 重新校验 checksum、manifest checksum、CI source、license/NOTICE、
   rollback 字段和 attestation/provenance 状态。
8. 只有 `package_attestation_status=attested` 且 provenance 引用可验证时，才允许上传
   GitHub Release assets。

当前 placeholder release 不执行第 1 步及之后的任何真实 signing、attestation、provenance 或
upload 步骤。

## Rejection Rules

真实 signing/attestation gate 必须拒绝以下情况：

- `package-linux`、`attest-linux`、`sign-linux` 或 `publish-github-release` 在本文档和相关
  release gates 完成前被定义。
- signing policy、attestation policy、provenance policy 或 subject file set 与本文档不一致。
- attestation subject 缺少 archive、archive checksum、manifest 或 manifest checksum。
- attestation 从同一 release run workflow artifact 以外的文件、旧 run artifact、不同 commit
  artifact、外部 URL 或人工上传文件生成。
- manifest `signing` object 与 job outputs 或 release summary 字段不一致。
- publish job 在 `package_attestation_status=attested` 和 provenance reference 可验证前上传
  GitHub Release asset。
- release asset set 尝试加入未声明的 signature、bundle 或 provenance sidecar。
- signing/attestation 步骤输出 secret、token、证书私钥、runner 本地绝对路径或 API response 原文。

拒绝时 release workflow 必须失败，并且不得上传 workflow artifact 或 GitHub Release asset。

## Placeholder 行为

当前 release workflow 只能：

- 检查本文档存在和标题。
- 在 `linux-artifact-readiness`、`release-placeholder` 和 release summary 中输出 signing/attestation
  policy binding 合同。
- 标记 `linux-package-signing-attestation-policy-contract=present`。
- 标记 `linux-package-signing-policy=unsigned-no-detached-signature`。
- 标记 `linux-package-signing-status=blocked-not-signed`。
- 标记 `linux-package-attestation-status=blocked-not-attested`。
- 标记 `linux-package-provenance-status=blocked-not-generated`。
- 标记 `linux-package-publish-without-attestation=blocked`。
- 标记 `package-linux=not-defined`、`attest-linux=not-defined`、`sign-linux=not-defined` 和
  `publish-github-release=not-defined` 或等价 blocked 状态。
- 继续不定义 `package-linux`、`attest-linux`、`sign-linux` 或 `publish-github-release`。

该 placeholder 只证明 signing/attestation policy binding 已被记录，不证明当前 release 已经可以
发布 Linux artifact。

## 验收条件

- 本文档保持在 README、ROADMAP、Release Strategy、Linux artifact 设计、Linux package manifest
  设计、Linux package publish/upload boundary contract、Linux package checksum manifest contract、
  Linux package artifact attestation execution validation contract、
  Linux package release notes/rollback policy binding contract、Linux package publish eligibility
  aggregate contract、Linux CLI artifact 安装/回滚设计、
  Release CI success source contract、Linux package
  artifact job preflight validation contract、runner/toolchain/target contract、Linux package archive staging
  contract、Linux artifact license/NOTICE confirmation source contract 和 CI policy 中可发现。
- `.github/workflows/ci.yml` governance 检查本文档存在和标题。
- `.github/workflows/release.yml` 的 `linux-artifact-readiness` 检查本文档存在、标题和
  release placeholder/summary 输出字段。
- release placeholder 和 release summary 输出 signing policy、signing status、attestation policy、
  attestation status、provenance policy、provenance file/status、attestation subjects、attestation
  job name、publish requires attestation 和 blocked status。
- 不生成 artifact、不定义 `package-linux`、不定义 `attest-linux`、不定义 `sign-linux`、不定义
  `publish-github-release`、不上传 workflow artifact、不上传 release asset、不在本机执行测试、
  构建、打包或发布。

## 后续工作

- 在 license/NOTICE 人工确认完成前，继续保持 pending marker 并阻止 Linux artifact。
- Linux package release notes/rollback policy binding contract、publish eligibility aggregate contract、
  license/NOTICE transition validation contract 和 release CI gate activation validation contract 已定义；
  Linux package artifact job preflight validation contract、Linux package artifact build command validation contract、Linux package artifact staging file validation contract、Linux package artifact archive creation validation contract 和 Linux package artifact checksum execution validation contract 已定义；Linux package artifact manifest generation validation contract、Linux package artifact manifest checksum validation contract、Linux package workflow artifact bundle upload validation contract 和 Linux package artifact attestation execution validation contract 已定义；下一步可以补充 Linux package release notes/rollback execution validation contract，仍不发布 release asset。
