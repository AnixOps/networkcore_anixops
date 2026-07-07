# Linux Artifact Pre-Release Design

本文件定义首个 Linux release artifact 进入 `.github/workflows/release.yml` 前必须满足的源码、平台设计、安装/卸载、CI 和发布契约。它不是当前可发布产物说明；在本文门禁完成前，release workflow 仍只能保持 placeholder 状态。

评估时间：2026-07-06。

## 目标

- 明确 Linux artifact 进入 release workflow 前的最小源码边界。
- 保持 `control-domain` 和 `control-runtime` 平台无关，不把 Linux 权限、文件系统或服务管理细节泄漏到领域层。
- 定义 Linux packaging job 必须输出的 artifact、checksum、签名/证明、安装边界和回滚字段。
- 避免在没有可运行入口、安装/卸载策略和 GitHub Actions 验证前发布空壳产物。

## 非目标

- 不在本文实现 daemon、systemd unit、TUN 配置、安装器或真实 packaging job。
- 不在本机构建、测试、打包或验证 Linux artifact。
- 不承诺 `.deb`、`.rpm`、AppImage、container image 或发行版仓库发布。
- 不授予或配置 `CAP_NET_ADMIN`、root 权限、证书信任或系统 DNS 修改能力。

## 初始产物候选

首个 Linux artifact 只允许在源码和验证条件满足后加入 release workflow。候选形态按保守顺序评估：

1. `networkcore-linux` CLI 压缩包：包含单一可执行入口、版本信息、许可和最小运行说明。
2. Linux daemon 压缩包：在 CLI 能稳定启动和停止后，再评估长期运行模式。
3. 安装器或发行版包：只有安装/卸载、权限、服务管理和升级回滚路径明确后才允许进入矩阵。

首个 artifact 不应默认安装系统服务，不应自动修改 DNS、路由、证书信任或防火墙规则。

## 源码前置条件

真实 Linux artifact job 合入前必须至少具备：

- [Linux platform adapter design](linux-platform-adapter.md)，定义 TUN、权限、DNS、服务管理、证书和诊断边界。
- [Linux CLI entrypoint design](linux-cli-entrypoint.md) 和可运行入口源码，例如当前 `apps/linux-cli`、后续 `apps/linux-daemon` 或等价 crate，并明确依赖 `control-runtime` 的方向。
- [Linux CLI runtime wiring design](linux-cli-runtime-wiring.md)，定义 `prepare-config`、`start`、配置服务、代理引擎服务和前台生命周期接线边界。
- [Native engine listener and node config design](native-engine-listener-node-config.md)，定义原生 runtime handle 进入前 listener、node、route 和 DNS 配置图边界。
- [Linux native proxy engine start design](linux-native-proxy-engine-start.md)，定义首个原生 `ProxyEngineService` adapter、前台 lifecycle host 和 `networkcore-linux start` 接线门槛。
- [Linux CLI artifact installation and rollback design](linux-cli-artifact-installation-rollback.md)，定义首个压缩包的手动安装、卸载和用户侧回滚边界。
- [Linux package artifact manifest design](linux-package-artifact-manifest.md)，定义首个压缩包 sidecar manifest、manifest checksum 和 release summary metadata 输出边界。
- [Linux artifact license notice confirmation design](linux-artifact-license-notice-confirmation.md)，定义 license/NOTICE 人工确认记录的机器可读来源和 pending/confirmed 字段。
- [Release CI success source contract](release-ci-success-source-contract.md)，定义真实 packaging 前必须从 GitHub Actions 读取的同 commit CI run/source 字段。
- Release placeholder 和 release summary 已提前输出 manifest output contract 字段清单与 license/NOTICE source contract pending 状态，真实 `package-linux` 后续必须提供对应值并等待人工确认完成。
- Linux 平台能力实现或测试替身，能够通过 `PlatformCapabilityService` 表达 Linux 能力，而不是把 Linux API 放入领域 crate。
- 配置加载、启动、停止、状态查询和错误诊断的最小用例。
- GitHub Actions 中的 Linux build、test、lint 和 security scan 结果，并由 CI summary 显式门禁。

仅存在 `control-domain` 或 `control-runtime` library crate 不足以发布 Linux artifact。

## 平台能力边界

Linux adapter 必须把以下能力映射为领域诊断：

| 能力 | 初始要求 |
| --- | --- |
| TUN | 检查 `/dev/net/tun`、权限和所需 capability，不在领域层直接访问设备 |
| 路由 | 后续 adapter 负责系统路由变更；首个 artifact 不自动改路由 |
| DNS | 不默认修改 `/etc/resolv.conf`、systemd-resolved 或 NetworkManager 配置 |
| 服务管理 | 不假设 systemd 一定存在；daemon 模式必须有独立设计 |
| 证书 | MITM CA 安装与信任必须由用户明确授权，并有撤销路径 |
| 诊断 | 权限不足、设备缺失、DNS 不可写、服务管理不可用都必须返回稳定诊断 code |

## Packaging Job 契约

首个真实 Linux packaging job 必须满足 release strategy 中的通用门禁，并至少输出：

| 输出字段 | 含义 |
| --- | --- |
| `artifact_name` | Linux artifact 文件名 |
| `artifact_path` | runner 上待上传 artifact 路径 |
| `checksum_algorithm` | 固定为 `sha256`，除非 release strategy 先更新 |
| `checksum_file` | checksum 文件路径 |
| `checksum_value` | artifact 的 sha256 值 |
| `artifact_manifest_name` | Linux artifact sidecar manifest 文件名 |
| `artifact_manifest_path` | runner 上待上传 manifest 路径 |
| `artifact_manifest_checksum_file` | manifest checksum 文件路径 |
| `artifact_manifest_checksum_value` | manifest sha256 值 |
| `signing_policy` | `unsigned-placeholder`、`attested` 或后续明确签名策略 |
| `signing_status` | 签名执行结果或明确未签名原因 |
| `attestation_status` | artifact attestation 结果或未启用原因 |
| `provenance_file` | provenance/attestation 文件路径或未启用说明 |
| `rollback_scope` | 回滚影响范围 |
| `rollback_trigger` | 触发撤回或替换的条件 |
| `rollback_steps` | 撤回、替换或禁用步骤 |
| `replacement_version` | 需要替换时的后续版本策略 |
| `rollback_owner` | 负责执行回滚的角色或团队 |

这些字段必须进入 release summary；没有同 commit CI success source、archive checksum、manifest 和 manifest checksum
字段不得上传 Linux artifact。

## Release Workflow 形态

Linux artifact 进入 `.github/workflows/release.yml` 时应按以下依赖扩展：

1. `release-policy`
2. `release-ci-gate`
3. `release-artifact-contract`
4. `release-signing-contract`
5. `release-rollback-contract`
6. `linux-artifact-readiness`
7. `package-linux`
8. 后续可选 `sign-linux` 或 attestation job
9. `publish-github-release`
10. `post-release-summary`

`linux-artifact-readiness` 只检查源码、设计和人工事项，不构建、不打包、不上传 artifact。`package-linux` 必须在 GitHub-hosted `ubuntu-latest` 或后续受控 Linux runner 中运行。所有 build、test、package、checksum、attestation 和 upload 都必须在 GitHub Actions 中完成。

## 安装与回滚边界

首个 Linux artifact 必须以可撤回为优先：

- 压缩包必须能被用户解压后手动运行，不自动安装系统服务。
- 具体安装、卸载和用户侧回滚边界必须遵守 [Linux CLI Artifact Installation And Rollback Design](linux-cli-artifact-installation-rollback.md)。
- 如需要 root 或 capability，必须在说明中明确风险和撤销方式。
- 后续 systemd、launch wrapper、shell installer、`.deb` 或 `.rpm` 必须单独设计安装、升级和卸载流程。
- 已公开 asset 不得覆盖同名 tag；修复必须发布新版本或撤回说明。

## 验收条件

在 Linux artifact 真实进入 release workflow 前，必须完成：

- 本文档保持在 README、ROADMAP、Release Strategy 和 CI policy 中可发现。
- [Linux platform adapter design](linux-platform-adapter.md) 完成并通过 CI governance 检查。
- [Linux CLI entrypoint design](linux-cli-entrypoint.md) 完成并通过 CI governance 检查。
- [Linux CLI runtime wiring design](linux-cli-runtime-wiring.md) 完成并通过 CI governance 检查。
- [Native engine listener and node config design](native-engine-listener-node-config.md) 完成并通过 CI governance 检查。
- [Linux native proxy engine start design](linux-native-proxy-engine-start.md) 完成并通过 CI governance 检查。
- [Linux CLI artifact installation and rollback design](linux-cli-artifact-installation-rollback.md) 完成并通过 CI governance 检查。
- [Linux package artifact manifest design](linux-package-artifact-manifest.md) 完成并通过 CI governance 和 release readiness 检查。
- [Linux artifact license notice confirmation design](linux-artifact-license-notice-confirmation.md) 完成并通过 CI governance 和 release readiness 检查；当前 `docs/manual-intervention.md` 仍为 pending marker。
- [Release CI success source contract](release-ci-success-source-contract.md) 完成并通过 CI governance 和 `release-ci-gate` 检查；当前仍只输出 placeholder 字段，不查询 GitHub API。
- Linux 可运行入口源码和对应 GitHub Actions 验证存在；当前 `apps/linux-cli` 已接入只读平台诊断、只读 `prepare-config` 配置准备、前台 native runtime 启动和 foreground interruption stop/release 诊断聚合，但不代表 artifact 可发布。
- `linux-artifact-readiness` job 检查 Linux CLI 源码、platform adapter、native listener/node 配置设计、foreground stop/release 源码与合同测试、artifact manifest 合同设计、license/NOTICE confirmation source contract、安装/回滚设计和 license/NOTICE pending marker，并继续阻止 release asset。
- `release-placeholder` 和 release summary 输出 Linux artifact manifest output contract 字段清单、Linux artifact license/NOTICE source contract 与 pending 状态，且继续说明没有 artifact job。
- `release-ci-gate` 和 release summary 输出 release CI success source contract 与 required fields，且继续说明真实 artifact 前必须关联 `main` 上同 commit 成功 CI。
- `package-linux` job 输出 artifact、checksum、manifest、manifest checksum、签名/证明状态和回滚字段。
- release summary 门禁 `package-linux`、checksum、manifest checksum、签名/证明、安装边界和回滚字段。

## 后续工作

- 在完成 `package-linux` workflow job、checksum、manifest、签名/证明状态、license/NOTICE 人工确认和 release summary 门禁前，release workflow 不得生成 Linux artifact。
- 下一步可以补充 `package-linux` job 的 runner、toolchain 和 target triple 合同，仍不生成 artifact。
