# Windows CLI Artifact Source Release Contract

评估时间：2026-07-10。

当前合同状态：

```text
windows-cli-artifact-source-release-contract=present
windows-cli-artifact-release-state=package-path-active
windows-cli-artifact-version-scope=v0.1.1-alpha.2
WINDOWS_CLI_ARTIFACT_GATE=package-windows-active/system-mutation-blocked
windows-cli-artifact-runner=windows-latest
windows-cli-artifact-runner-kind=github-hosted
windows-cli-artifact-rust-toolchain=stable
windows-cli-artifact-rust-profile=minimal
windows-cli-artifact-target-triple=x86_64-pc-windows-gnu
windows-cli-artifact-package-format=zip
windows-cli-artifact-checksum-algorithm=sha256
windows-cli-artifact-manifest-schema-version=1
windows-cli-artifact-install-model=manual-extract
windows-cli-artifact-system-mutation-policy=none
windows-cli-artifact-source-identity=apps/windows-cli
windows-cli-artifact-service=blocked
windows-cli-artifact-driver=blocked
windows-cli-artifact-installer=blocked
windows-cli-artifact-system-proxy-mutation=blocked
windows-cli-artifact-trust-store-mutation=blocked
windows-cli-artifact-script-dispatch=blocked
windows-cli-artifact-authenticode-policy=unsigned-no-authenticode-for-alpha-cli-zip
windows-cli-artifact-attestation-policy=github-artifact-attestation-required
windows-cli-artifact-package-windows=defined
windows-cli-artifact-release-assets=enabled-after-attestation-and-publish-gate
windows-cli-artifact-next-action=subscription-parser-gates-after-windows-artifact
```

## Purpose

本文固定 `v0.1.1-alpha.2` 的 Windows CLI artifact package/publish path。该切片在
`v0.1.1-alpha.1` 的 source/release contract 基础上激活 `apps/windows-cli` source identity、
`package-windows`、Windows zip、checksum、manifest、attestation、release notes/rollback 和 publish
eligibility gate。

`v0.1.1-alpha.2` 生成 Windows CLI zip 并上传 Windows release asset，但不引入 Windows service、
driver、installer、系统代理 mutation、system trust store mutation、JavaScript script dispatch 或 managed
lifecycle。订阅格式扩展继续等待 `v0.1.1-alpha.3` 或后续明确切片。

## Source Identity Boundary

当前仓库同时保留 `apps/linux-cli` 和 `apps/windows-cli` 入口。Windows CLI 的 source identity 是
`apps/windows-cli`，crate 和 binary 名为 `networkcore-windows`，并依赖 `platform-windows`。`platform-windows`
只报告只读 artifact/package 状态和 blocked system mutation 边界。

release workflow 不得把 `networkcore-linux.exe` 或 Windows CI build output 冒充为正式 Windows artifact。
正式 Windows artifact 必须来自 `apps/windows-cli` 的 `networkcore-windows.exe`。

## Active Artifact Contract

真实 Windows artifact job 必须至少定义：

- runner: `windows-latest`。
- source identity: `apps/windows-cli`。
- Rust toolchain: `stable` with `minimal` profile.
- target triple: `x86_64-pc-windows-gnu` 或后续明确批准的 Windows target。
- archive format: `.zip`。
- archive name: `networkcore-windows-${version}-${target}.zip`，除非 source identity contract 另行批准。
- manifest name: `networkcore-windows-${version}-${target}.manifest.json`。
- checksum algorithm: `sha256`，archive 和 manifest 都必须有 sidecar checksum。
- attestation policy: GitHub artifact attestation required。
- signing policy: alpha 阶段允许 unsigned/no detached signature；正式签名、证书和时间戳服务必须单独补
  manual marker 或 release gate。
- rollback policy: withdrawal-not-overwrite and new-version-tag-required。

## Blocked Operations

`v0.1.1-alpha.2` 必须保持以下能力 blocked：

- `install-windows-service`
- `install-driver`
- `run-installer`
- `mutate-system-proxy`
- `mutate-system-trust-store`
- `execute-javascript-dispatch`
- `managed-daemon-lifecycle`

## Release Workflow Boundary

当前 release workflow 必须包含：

- `windows-cli-artifact-readiness`：验证本文档、`apps/windows-cli`、`platform-windows` 和 blocked mutation anchors。
- `package-windows`：在 `windows-latest` 上构建 `networkcore-windows.exe`，生成 zip、zip sha256、
  manifest JSON 和 manifest sha256。
- `attest-windows`：对 Windows 四件套生成 GitHub artifact attestation。
- `windows-release-summary`：校验 release notes 和 rollback 字段。
- `windows-publish-eligibility-gate`：聚合 source identity、同 commit CI、checksum/manifest、attestation、
  release notes/rollback 和 system mutation blocked 状态。
- `publish-github-release`：只有 tag release 且 Linux/Windows publish eligibility 都为 eligible 时，才上传
  Linux 和 Windows release assets。

所有 build、zip、checksum、manifest、attestation 和 GitHub Release asset upload 只能在 GitHub Actions 中运行。

## CI Governance Anchors

Repository policy 必须检查以下锚点：

- `windows-cli-artifact-source-release-contract=present`
- `windows-cli-artifact-release-state=package-path-active`
- `windows-cli-artifact-version-scope=v0.1.1-alpha.2`
- `WINDOWS_CLI_ARTIFACT_GATE=package-windows-active/system-mutation-blocked`
- `windows-cli-artifact-runner=windows-latest`
- `windows-cli-artifact-target-triple=x86_64-pc-windows-gnu`
- `windows-cli-artifact-package-format=zip`
- `windows-cli-artifact-checksum-algorithm=sha256`
- `windows-cli-artifact-source-identity=apps/windows-cli`
- `windows-cli-artifact-attestation-policy=github-artifact-attestation-required`
- `windows-cli-artifact-package-windows=defined`
- `windows-cli-artifact-release-assets=enabled-after-attestation-and-publish-gate`
- `networkcore-linux.exe`
- `networkcore-windows.exe`
- `windows-cli-artifact-readiness`
- `package-windows`
- `attest-windows`
- `windows-publish-eligibility-gate`

这些检查证明 Windows package/publish path 已激活，但不放开 Windows service、driver、installer、system
proxy mutation、system trust store mutation、JavaScript script dispatch 或 managed daemon lifecycle。
