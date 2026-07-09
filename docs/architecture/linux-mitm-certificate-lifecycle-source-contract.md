# Linux MITM Certificate Lifecycle Source Contract

评估时间：2026-07-09。

当前合同状态：

```text
mitm-certificate-lifecycle-source-contract-status=active
MITM_CERTIFICATE_LIFECYCLE_GATE=artifact-lifecycle-active/profile-trust-artifact-active/trust-mutation-blocked
```

本文固定 Linux MITM certificate lifecycle 从 plan-only 进入受控 artifact lifecycle 后必须遵守的源码边界。当前仓库允许 `networkcore-linux mitm certificate apply --confirm --cert-file <path> --key-file <path> [--profile-trust-file <path>] --snapshot <path>` 写入调用方显式提供路径上的 NetworkCore certificate artifact、private key artifact、可选 dedicated profile trust artifact 和 rollback snapshot；允许 `networkcore-linux mitm certificate rollback --snapshot <path>` 读取 NetworkCore snapshot 并删除 snapshot 管理的 artifact。该能力不安装或信任 CA，不修改 system trust store、NSS DB、p11-kit、Firefox trust store 或 profile trust state，不解密 HTTPS，也不应用 HTTP/TLS rewrite。

## Current Boundary

- `networkcore-linux mitm certificate-plan` 继续输出 `mitm_status.certificate_plan`，但计划包含 `write-local-ca-artifact`、`snapshot-ca-artifact`、`write-dedicated-profile-trust-artifact` 和 `rollback-ca-artifact` active steps。
- `networkcore-linux mitm certificate apply --confirm --cert-file <path> --key-file <path> [--profile-trust-file <path>] --snapshot <path>` 通过 `CommandMitmCertificateArtifactStore` 写入 operator-provided certificate/key artifact 路径、可选 dedicated profile trust artifact 路径和 NetworkCore rollback snapshot。
- 缺少 `--confirm` 时返回 `cli.linux.mitm.certificate.authorization_required`，不写文件。
- 缺少 `--cert-file`、`--key-file` 或 `--snapshot` 时返回 `cli.linux.mitm.certificate.apply.config_missing`，不写文件。
- 已存在的 cert/key/profile trust/snapshot 路径必须拒绝覆盖，分别返回 `cli.linux.mitm.certificate.artifact.write_failed` 或 `cli.linux.mitm.certificate.snapshot.write_failed`。
- Snapshot 记录 NetworkCore ownership、artifact path、subject 和内容 fingerprint；rollback 必须在当前文件 fingerprint 仍匹配 snapshot 时才删除 artifact，避免覆盖外部修改。
- `networkcore-linux mitm certificate rollback --snapshot <path>` 读取 snapshot，成功时返回 `cli.linux.mitm.certificate.rollback.ready`；snapshot 缺失、不可读或不是 NetworkCore certificate artifact snapshot 时返回 `cli.linux.mitm.certificate.snapshot.read_failed`。
- Artifact rollback 遇到外部修改时返回 `cli.linux.mitm.certificate.rollback.failed`。
- `certificate_lifecycle` JSON report 输出 action、source contract status、gate、gate status、request、artifact request、trust_plan、apply_report 或 rollback_report。
- `certificate_lifecycle.request.artifact`、`apply_report` 和 `rollback_report` 输出 `profile_trust_file_path`，artifact request 还输出 `profile_trust_content` 和 `profile_trust_fingerprint`。
- `trust_plan` 固定为 `trust-mutation-blocked`，但包含 `prepare-dedicated-profile-trust-artifact` active step；仍列出 `install-ca`、`trust-ca`、`update-ca-certificates`、`mutate-nss-db`、`mutate-p11-kit`、`mutate-firefox-trust-store`、`revoke-ca` 和 `rollback-trust-store` blocked operations。

## Source Anchors

当前源码必须保留或通过 CI governance 显式迁移以下 NetworkCore-owned anchors：

- `LinuxMitmCertificateLifecycleReport`
- `LinuxMitmCertificateLifecycleRequest`
- `LinuxMitmCertificateArtifactRequest`
- `LinuxMitmCertificateArtifactApplyOutcome`
- `LinuxMitmCertificateArtifactRollbackOutcome`
- `LinuxMitmCertificateApplyReport`
- `LinuxMitmCertificateRollbackReport`
- `LinuxMitmCertificateTrustPlan`
- `MitmCertificateAuthorization`
- `MitmCertificateRollbackSnapshot`
- `MitmCertificateArtifactStore`
- `CommandMitmCertificateArtifactStore`
- `UnavailableMitmCertificateArtifactStore`
- `handle_mitm_certificate_apply`
- `handle_mitm_certificate_apply_with_store`
- `handle_mitm_certificate_rollback`
- `handle_mitm_certificate_rollback_with_store`
- `handle_entrypoint_with_certificate_lifecycle_io`
- `certificate_lifecycle`
- `--cert-file`
- `--key-file`
- `--profile-trust-file`
- `--snapshot`
- `profile_trust_file_path`
- `profile_trust_content`
- `profile_trust_fingerprint`
- `cli.linux.mitm.certificate.authorization_required`
- `cli.linux.mitm.certificate.apply.ready`
- `cli.linux.mitm.certificate.apply.config_missing`
- `cli.linux.mitm.certificate.apply.blocked`
- `cli.linux.mitm.certificate.artifact.write_failed`
- `cli.linux.mitm.certificate.snapshot.write_failed`
- `cli.linux.mitm.certificate.snapshot.read_failed`
- `cli.linux.mitm.certificate.rollback.ready`
- `cli.linux.mitm.certificate.rollback.failed`
- `cli.linux.mitm.certificate.rollback.blocked`

## Explicitly Blocked

当前合同明确禁止：

- 执行 `update-ca-certificates`。
- 修改 NSS DB、p11-kit 或 Firefox trust store。
- 写入发行版专用 trust command、system trust store、browser trust store 或 profile trust state。
- 把 artifact 写入等同于可信 CA 安装。
- 生成 live HTTPS decrypt capability 或 HTTP/TLS redirect/header/body/script rewrite。
- 在没有 NetworkCore snapshot 且 fingerprint 匹配的情况下删除或覆盖 cert/key artifact。

## CI Governance

CI 必须静态检查源码中的命令、类型、诊断 code、JSON report 字段、文档 anchor 和 gate 状态。任何后续把 trust mutation 从 blocked 改为 active 的提交，必须先新增单独 source contract，覆盖系统 trust store 检测、安装、撤销、rollback、发行版差异和人工授权边界。
