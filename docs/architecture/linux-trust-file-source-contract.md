# Linux Trust-File Source Contract

评估时间：2026-07-27。

当前源码状态：

```text
linux-trust-file-source-contract=active
linux-trust-file-backend=explicit-ubuntu-style-file
linux-trust-file-refresh=update-ca-certificates
linux-trust-file-default-discovery=blocked
linux-trust-file-other-backends=blocked
```

当前 `main` 允许通过 `networkcore-linux mitm certificate trust-apply` 将调用方提供的公开 CA PEM 写入调用方提供的绝对 trust-file 路径，并在写入精确读回后调用 `update-ca-certificates`。`trust-rollback` 只恢复同一 NetworkCore snapshot 记录的内容；当前文件被外部修改时拒绝回滚。两条命令都要求 `--confirm`，不发现发行版默认路径，不读取或输出私钥，不修改 NSS、p11-kit、Firefox、浏览器 profile、系统代理或 HTTPS 数据面。

## Required Boundaries

- `--cert-file`、`--trust-file` 和 `--snapshot` 必须是绝对、互不相同的路径；符号链接和已有 snapshot 不得被覆盖。
- apply 必须先验证公开 CA PEM、写入 snapshot、原子写入 trust-file、精确读回，再刷新系统信任库。
- apply 的写入或刷新失败必须恢复原文件并删除未完成 snapshot；rollback 的刷新失败必须恢复已应用内容并保留 snapshot。
- rollback 必须比较当前 trust-file 与 snapshot 中的已应用内容，拒绝覆盖外部修改。
- `update-ca-certificates` 是显式 Ubuntu-style adapter 的唯一刷新 runner；其他 trust backend 仍是 blocked capability。

## Source Anchors

- `platform_linux::trust::apply_linux_trust`
- `platform_linux::trust::rollback_linux_trust`
- `CommandLinuxTrustRefreshRunner`
- `LinuxTrustApplyRequest`
- `LinuxTrustRollbackRequest`
- `LinuxCliCommand::MitmCertificateTrustApply`
- `LinuxCliCommand::MitmCertificateTrustRollback`
- `networkcore-linux mitm certificate trust-apply`
- `networkcore-linux mitm certificate trust-rollback`
- `trust_cli_handlers_reject_missing_paths_without_mutation`
- `trust_apply_refreshes_and_rollback_restores_snapshot`
- `trust_rollback_rejects_external_changes`

