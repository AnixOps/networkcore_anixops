# Release Strategy

本文件定义真实平台产物进入 `.github/workflows/release.yml` 前必须满足的发布策略。它是发布 workflow 的设计约束，不代表当前仓库已经具备可发布产物。

评估时间：2026-07-06。

## 当前发布状态

当前 release workflow 只保留 policy、release-ci-gate、release-artifact-contract、release-signing-contract 与 placeholder job：

- 允许 tag `v*` 和 `workflow_dispatch` 触发。
- release policy job 检查版本格式和触发来源一致性；手动 placeholder release 必须从 `main` 分支发起，tag release 必须使用同名 tag 版本。
- `release-ci-gate` job 记录真实 artifact 加入前必须关联 `main` 上同 commit 的成功 CI 结果；placeholder 阶段暂不执行 artifact CI 门禁。
- `release-artifact-contract` job 记录首个真实 artifact job 必须输出 `artifact_name`、`artifact_path`、`checksum_algorithm`、`checksum_file` 和 `checksum_value`，且 checksum 算法默认为 `sha256`。
- `release-signing-contract` job 记录真实平台 artifact 发布前必须声明签名或 attestation 策略，并要求后续 job 输出 `signing_policy`、`signing_status`、`attestation_status` 和 `provenance_file`。
- 不生成 release artifact。
- 不在本机打包、签名、测试或发布。
- 通过 release summary job 输出发布来源、policy、release-ci-gate、release-artifact-contract、release-signing-contract、placeholder、artifact 状态和后续 artifact 门禁。
- 任何真实产物必须先有对应源码、平台设计、GitHub Actions 验证和本文件定义的门禁。

## 发布原则

- CI/CD Only：所有 build、test、lint、security scan、package、sign、notarize、upload 都必须在 GitHub Actions 或官方平台完成。
- Source Of Truth：release 只能基于 Git tag、受控分支或手动指定版本，不接受本地构建产物。
- One Artifact, One Job：每类平台产物使用独立 job，避免一个失败路径污染其他平台。
- Reproducible Inputs：release job 必须记录 commit SHA、tag、workspace manifest、toolchain 和 artifact 名称。
- No Secret In Repo：签名证书、Provisioning Profile、App Store Connect、Windows signing、GitHub token 只能走 GitHub Secrets、Environments 或官方平台。
- Rollback First：每个产物都要有可描述的撤回、替换或禁用路径。

## 发布门禁

真实 artifact job 合入前必须满足：

1. `main` 上对应 commit 的 CI 全部通过，至少覆盖 policy、workspace smoke、语言 build/test/lint/security scan。
2. artifact 对应源码和平台设计已存在，不能发布 placeholder、空壳或本地生成产物。
3. release workflow 中的每个 artifact job 都显式声明 runner、toolchain、输入版本、输出文件名和上传路径。
4. 产物必须由 GitHub-hosted runner 或后续受控 runner 生成，并上传为 workflow artifact 或 GitHub Release asset。
5. 每个上传产物必须生成 checksum；首个真实 artifact job 至少输出 `artifact_name`、`artifact_path`、`checksum_algorithm`、`checksum_file` 和 `checksum_value`；后续有 signing 或 attestation 能力时必须纳入同一 release run。
6. 真实平台 artifact 发布前必须声明签名或 attestation 策略，并至少输出 `signing_policy`、`signing_status`、`attestation_status` 和 `provenance_file`。
7. 涉及 Apple、Windows 或商店发布的产物必须先完成人工账号、证书、密钥和 Secrets 配置，并记录到 `docs/manual-intervention.md`。
8. 发布说明必须链接对应 CHANGELOG、CI run、release run 和回滚方案。

## 初始产物矩阵

| 平台/产物 | 初始形态 | Release runner | 发布前置条件 |
| --- | --- | --- | --- |
| Rust crates | 暂不发布到 crates.io | `ubuntu-latest` | 公共 API 稳定、license 与 README 完整、crate publishing policy 单独评审 |
| Linux | 待定义 CLI 或 daemon 压缩包 | `ubuntu-latest` | Linux adapter 与安装/卸载设计完成 |
| Windows | 待定义 CLI、service 或 installer | `windows-latest` | Windows service 权限、签名证书和安装器策略完成 |
| macOS | 待定义 CLI、app bundle、`.pkg` 或 `.dmg` | `macos-26` | 签名、notarization、entitlement 和 Gatekeeper 路径完成 |
| iOS | App Store Connect 或 TestFlight 路径 | `macos-26` | Network Extension design、entitlement、Provisioning Profile、隐私政策和 App Review Notes 完成 |
| Source archive | GitHub release 自动源码包 | GitHub Release | tag、CHANGELOG 和 CI 通过 |

矩阵中的非源码包产物在对应平台设计完成前不得加入 release workflow。

## Workflow 形态

未来 release workflow 应按以下阶段扩展：

1. `release-policy`：检查 AGENT、CI/CD policy、release strategy、版本格式和 tag/ref 一致性。
2. `release-ci-gate`：确认当前 commit 对应 CI run 已成功，或在 release workflow 中重新执行等效验证。
3. `release-artifact-contract`：在 placeholder 阶段记录首个 artifact job 必须暴露的 checksum 输出字段，真实产物加入后由 `package-*` job 输出替代。
4. `release-signing-contract`：在 placeholder 阶段记录真实平台 artifact 发布前必须声明的 signing/attestation 输出字段，真实产物加入后由 `sign-*` 或 attestation job 输出替代。
5. `package-*`：每个平台独立构建产物并输出 checksum。
6. `sign-*`：需要签名的平台在受控 runner 中读取 GitHub Secrets 或官方平台凭据。
7. `notarize-*`：macOS 产物完成 Apple notarization 后再进入发布资产。
8. `publish-github-release`：上传 release assets、checksums、release notes 和 provenance/attestation 信息。
9. `post-release-summary`：输出产物清单、验证链接、人工事项和回滚说明。

真实产物加入前，`release-placeholder` 必须保留或替换为等价的显式说明，避免误认为 release 已经可用。

## 版本与回滚

- 版本号采用 `vMAJOR.MINOR.PATCH` tag 形式，预发布版本使用 `vMAJOR.MINOR.PATCH-rc.N`；当前 release policy gate 已按该格式检查手动版本输入与 tag 名。
- 任何 release 修复都通过新 tag 发布，不覆盖已发布 tag。
- 如果 release 失败在发布前发生，删除 draft 或 failed run artifact 即可；如果 release asset 已公开，必须发布撤回说明并以新版本替换。
- iOS 和商店渠道回滚依赖 App Store Connect 或对应商店能力，必须在发布说明中记录可用路径。
- macOS/Windows 签名凭据泄漏时必须撤销证书、轮换 Secrets，并记录人工处理项。

## 人工介入边界

以下外部事项不能由仓库自动完成：

- Apple Developer、App Store Connect、Network Extension entitlement、证书和 Provisioning Profile。
- Windows 代码签名证书、时间戳服务和商店账号。
- GitHub Environments、branch protection、release approval policy 和 protected tags。
- 第三方发布渠道账号、API token、税务或合规材料。

完成后应把下一步自动化动作写入 `docs/manual-intervention.md`，并继续用 GitHub Actions 验证。

## 下一步

- 真实平台产物进入 release workflow 前，先为目标平台补齐 adapter 设计文档。
- 引入第一个 artifact job 时，同步加入 checksum、release summary 和回滚说明。
- iOS 发布前必须先完成 `docs/architecture/ios-network-extension-design.md`。

## 参考

- GitHub Docs: Managing releases in a repository, `https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository`
- GitHub Docs: Storing workflow data as artifacts, `https://docs.github.com/en/actions/using-workflows/storing-workflow-data-as-artifacts`
- GitHub Docs: Using artifact attestations, `https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds`
- Apple Developer Documentation: Notarizing macOS software before distribution, `https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution`
- Apple Developer Account Help: Provisioning with capabilities, `https://developer.apple.com/help/account/reference/provisioning-with-managed-capabilities/`
