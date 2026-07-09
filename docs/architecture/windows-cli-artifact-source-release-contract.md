# Windows CLI Artifact Source Release Contract

评估时间：2026-07-10。

当前合同状态：

```text
windows-cli-artifact-source-release-contract=present
windows-cli-artifact-release-state=contract-only
windows-cli-artifact-version-scope=v0.1.1-alpha.1
WINDOWS_CLI_ARTIFACT_GATE=source-release-contract-active/package-windows-blocked
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
windows-cli-artifact-source-identity=not-activated
windows-cli-artifact-service=blocked
windows-cli-artifact-driver=blocked
windows-cli-artifact-installer=blocked
windows-cli-artifact-system-proxy-mutation=blocked
windows-cli-artifact-trust-store-mutation=blocked
windows-cli-artifact-script-dispatch=blocked
windows-cli-artifact-authenticode-policy=unsigned-no-authenticode-for-alpha-cli-zip
windows-cli-artifact-attestation-policy=github-artifact-attestation-required
windows-cli-artifact-package-windows=not-defined
windows-cli-artifact-release-assets=blocked
windows-cli-artifact-next-action=package-windows-gate-after-source-contract
```

## Purpose

本文固定 `v0.1.1-alpha.1` 的 Windows CLI artifact source/release contract。该切片只定义 Windows
artifact 进入 release workflow 前必须满足的源码身份、runner、toolchain、archive、checksum、manifest、
attestation、release notes、rollback 和 signing policy 边界。

`v0.1.1-alpha.1` 不生成 Windows zip，不上传 Windows release asset，不引入 Windows service、driver、
installer、系统代理 mutation、system trust store mutation、JavaScript script dispatch 或 managed lifecycle。
真实 `package-windows`、Windows artifact publish eligibility 和 GitHub Release asset 上传必须等待
`v0.1.1-alpha.2` 或后续明确切片。

## Source Identity Boundary

当前仓库只有 `apps/linux-cli` 入口，并且该 crate 名为 `networkcore-linux`、依赖 `platform-linux`。虽然
GitHub Actions 的 CI matrix 已在 `windows-latest` 上验证 Rust workspace，但这不等于已有正式 Windows CLI
artifact source identity。

进入真实 Windows artifact 前，必须先满足以下条件之一：

- 新增独立 `apps/windows-cli` crate，二进制名、README、platform adapter 和命令边界均明确属于 Windows。
- 或者先把现有 CLI 抽象为跨平台 entrypoint，并通过 source contract 说明 Linux/Windows 平台 adapter
  的分发、二进制命名、命令输出差异和回滚边界。

在上述源码身份激活前，release workflow 不得把 `networkcore-linux.exe` 或 Windows CI build output
冒充为正式 Windows artifact。

## Required Future Artifact Contract

后续真实 Windows artifact job 必须至少定义：

- runner: `windows-latest`。
- source identity: `apps/windows-cli` 或经合同批准的跨平台 CLI entrypoint。
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

`v0.1.1-alpha.1` 必须保持以下能力 blocked：

- `package-windows`
- `publish-windows-release-asset`
- `install-windows-service`
- `install-driver`
- `run-installer`
- `mutate-system-proxy`
- `mutate-system-trust-store`
- `execute-javascript-dispatch`
- `managed-daemon-lifecycle`

## Release Workflow Boundary

当前 release workflow 只允许新增 `windows-cli-artifact-readiness` 这类合同检查 job。该 job 可以读取本文档并输出
blocked summary，但不得执行 cargo build、zip、checksum、manifest、attestation、signing、installer 或
GitHub Release asset upload。

`publish-github-release` 在 `v0.1.1-alpha.1` 合同切片中仍只能上传已有 Linux artifact。Windows artifact 出现在
GitHub Release asset 中必须等待真实 `package-windows`、attestation、release notes/rollback 和 publish
eligibility gates 全部激活并在 GitHub Actions 中通过。

## CI Governance Anchors

Repository policy 必须检查以下锚点：

- `windows-cli-artifact-source-release-contract=present`
- `windows-cli-artifact-release-state=contract-only`
- `windows-cli-artifact-version-scope=v0.1.1-alpha.1`
- `WINDOWS_CLI_ARTIFACT_GATE=source-release-contract-active/package-windows-blocked`
- `windows-cli-artifact-runner=windows-latest`
- `windows-cli-artifact-target-triple=x86_64-pc-windows-gnu`
- `windows-cli-artifact-package-format=zip`
- `windows-cli-artifact-checksum-algorithm=sha256`
- `windows-cli-artifact-source-identity=not-activated`
- `windows-cli-artifact-attestation-policy=github-artifact-attestation-required`
- `windows-cli-artifact-package-windows=not-defined`
- `windows-cli-artifact-release-assets=blocked`
- `networkcore-linux.exe`
- `windows-cli-artifact-readiness`

这些检查只证明合同存在和 release workflow 输出 blocked 状态，不证明 Windows artifact 已发布。
