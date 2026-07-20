# Manual Intervention List

本文件记录当前无法由本地自动化完成、需要人工处理的事项。

## 当前待处理

- iOS App Review manual confirmation 仍为 pending；完成前不得启用 TestFlight upload、App Store upload、
  App Review submission 或 iOS release asset。
- iOS TestFlight/App Store Connect upload workflow 仍为 pending；完成前不得执行 archive/export、
  TestFlight upload、App Store upload、App Review submission 或 iOS release asset。当前 release workflow 仅允许
  `ios-upload-readiness` blocked placeholder 读取这些 marker，输出 source tree preflight 和 safe summary。

## Windows Foreground Tunnel Manual Acceptance

The following elevated-Windows record is required before the foreground EasyTier tunnel can be
considered operational. GitHub-hosted CI cannot supply this host, adapter, ACL, TUN, or data-plane
evidence; it verifies source and injected contracts only.

1. Secure ProgramData root evidence: owner and exact SYSTEM/Administrators-only ACL for
   `AnixOps\WindowsTunnel`, `state`, `secrets`, and `easytier`, with no reparse point. Stage the
   approved EasyTier core, CLI, and every loader sidecar (including DLL/Wintun) as existing
   non-reparse direct regular children of `easytier`, with no nested directories. Record the
   exact SYSTEM/Administrators-only, non-inheriting ACL for every direct file and the independently
   verified lower-case core/CLI SHA-256 values. The elevated start path must normalize and recheck
   that complete direct-file inventory before it launches the core; record the resulting ACL
   evidence. NetworkCore never copies or downloads executable content.
2. Delivery-ledger floor values for the verified client and POP identities before and after the
   accepted start reservation.
3. `Find-NetRoute` and `Get-NetAdapter -Physical` evidence that the selected endpoint underlay is
   the same up physical interface, not a virtual or VPN adapter.
4. Before/after `ActiveStore` tuples for every endpoint bypass and planned destination route,
   including destination prefix, next hop, interface index, and route metric. Record only in the
   protected operator evidence, not a CLI report or repository fixture.
5. Successful EasyTier peer and route readiness plus `ping` to the overlay address and `ping` and
   `curl` to the POP test subnet.
6. Stop evidence that both exact virtual destination routes and endpoint-bypass routes were removed
   before the owned EasyTier process ended.
7. A controlled missing and ambiguous tuple proof that leaves the owned process, state/config, and
   unrelated routes unchanged while `tunnel stop` fails closed; restore the fixture before normal
   cleanup.
8. State-write denial, disk-full, and native state move failure evidence for each durable cleanup
   transition. A failed `Stopping` write leaves routes, process, and config untouched; a failure
   after mutation retains retryable cleanup intent. After storage is restored, record fresh cleanup
   convergence: it removes only exact still-present tuples and accepts proven-absent resources only
   for persisted `Stopping` or `Failed` cleanup. Confirm that this cleanup can reprove and stop the
   protected running core without requiring the CLI artifact; `Running` requires all ownership
   proofs and the full direct-file artifact set. Leave unrelated resources unchanged and keep this
   evidence in protected operator records, without raw tuple, PID, or config details in CLI or
   repository output.

## 已完成的人工/外部事项

1. 已确认 GitHub 远端地址：`https://github.com/AnixOps/networkcore_anixops.git`。
2. 已初始化本地仓库并绑定远端。
3. 已为 GitHub CLI 授权 `workflow` scope，使其可以推送 GitHub Actions workflow。
4. 已推送 bootstrap 文件并打通 CI。
5. 已确认 `v0.1.0-alpha.1` alpha Windows 手工 smoke 测试通过；候选 commit 为
   `67e86a84388023df77e53537f3f209b5a05c1682`，CI run 为 `28901464670`，release run 为
   `28901692913`，确认环境为 Windows 11 24H2 x64，且未运行本地构建或测试。
6. 已确认 Linux CLI artifact 使用仓库 `LICENSE` 的 `Apache-2.0`，`NOTICE=not-required`，
   artifact files 为 `LICENSE`；该确认只解除 license/NOTICE 人工门禁，真实二进制仍必须由
   GitHub Actions 的 CI、checksum、manifest、attestation、release notes、rollback 和 publish
   eligibility gates 生成、校验和发布。

## 后续 CI 观察命令

需要观察 CI 时运行：

```bash
gh workflow run ci.yml
gh run list --workflow ci.yml --limit 5
```

如果 GitHub CLI 不可用，可在 GitHub 网页端进入 `Actions`，选择 `CI`，手动触发 `workflow_dispatch`。

## 后续预计人工事项

后续涉及 iOS 时，还需要人工处理：

- Apple Developer Program 组织账号和账号角色确认
- App ID、Bundle ID、Network Extension capability、entitlement 与 Provisioning Profile 配置
- 证书、signing asset redaction 和 Provisioning Profile 轮换策略确认
- App Store Connect 或 TestFlight 初次配置、App Privacy 问卷、Privacy Manifest/Required Reason API review、privacy policy URL、TestFlight group 和 export compliance 确认
- GitHub Secrets 写入 Apple 相关凭据
- App Review Notes、demo account、review attachment、隐私政策和目标地区 VPN compliance/VPN 牌照材料确认

后续涉及新的平台 release artifact、artifact 范围扩大或 license/NOTICE 来源变化时，还需要人工处理：

- 对应平台或新增 artifact 文件集合的 license/NOTICE 文本确认；Linux `networkcore-linux` 当前范围已确认，
  但范围变化前不得复用旧确认绕过 release gates
- GitHub Environments、protected tags、branch protection 和 release approval policy 配置
- Windows 代码签名证书、时间戳服务和商店账号确认
- 第三方发布渠道账号、API token、税务或合规材料确认

## Linux Artifact License/NOTICE Confirmation

以下字段是 release readiness 读取的机器状态。license/NOTICE 人工确认已完成；
该确认只允许进入后续 GitHub Actions gates，不表示可跳过 CI、checksum、manifest、
attestation、release notes、rollback 或 publish eligibility。

```text
linux-artifact-release-state=confirmed-release-path
linux-artifact-license-notice-status=confirmed
linux-artifact-license-notice-source-contract=docs/architecture/linux-artifact-license-notice-confirmation.md
linux-artifact-license-notice-transition-contract=docs/architecture/linux-package-license-notice-transition-validation-contract.md
linux-artifact-license-notice-transition-commit=independent-manual-confirmation-commit
linux-artifact-license-notice-confirmed-at=2026-07-08
linux-artifact-license-notice-confirmed-by=operator
linux-artifact-license-notice-scope=networkcore-linux
linux-artifact-license-notice-license-source=LICENSE
linux-artifact-license-notice-notice-source=not-required
linux-artifact-license-notice-artifact-files=LICENSE
linux-artifact-license-notice-package-linux=eligible-after-ci-and-release-gates
linux-artifact-license-notice-release-assets=eligible-after-package-signing-checksum-and-rollback-gates
```

`package-linux` 和 release assets 仍必须遵守
`docs/architecture/linux-package-license-notice-transition-validation-contract.md`、同 commit CI、
checksum/manifest、attestation、release notes、rollback 和 publish eligibility gates。

## Alpha Windows Manual Smoke Test

以下字段记录 alpha 启动期间由用户在外部 Windows 环境执行的手工 smoke 测试状态。该测试不能在本机自动完成，
也不能替代 GitHub Actions 的 `windows-latest` CI 矩阵。

```text
alpha-release-windows-manual-test-status=confirmed
alpha-release-windows-manual-test-source-contract=docs/alpha-windows-smoke-test.md
alpha-release-windows-manual-test-source=manual-user-windows-environment
alpha-release-windows-manual-test-version=v0.1.0-alpha.1
alpha-release-windows-manual-test-commit=67e86a84388023df77e53537f3f209b5a05c1682
alpha-release-windows-manual-test-ci-run=28901464670
alpha-release-windows-manual-test-release-run=28901692913
alpha-release-windows-manual-test-scope=windows-local-smoke-user-run
alpha-release-windows-manual-test-windows=Windows 11 24H2
alpha-release-windows-manual-test-arch=x64
alpha-release-windows-manual-test-ci=github-actions-windows-latest-confirmed-success
alpha-release-windows-manual-test-artifacts=not-produced-placeholder
alpha-release-windows-manual-test-local-build-test=not-run
alpha-release-windows-manual-test-result=passed
alpha-release-windows-manual-test-confirmed-at=2026-07-07T22:10:50Z
alpha-release-windows-manual-test-confirmed-by=operator
alpha-release-windows-manual-test-next-action=rerun-ci-release-workflows-after-marker-update
```

该确认仅覆盖上述 alpha placeholder 候选版本和 GitHub Actions Windows 证据；当前仍不生成 Windows artifact、
installer、service、code signing、store upload 或 release asset。

## iOS App Review Manual Confirmation

以下字段是后续 iOS upload/release readiness 读取的机器状态。当前仍未完成 App Privacy answers、
privacy policy URL、App Review Notes、demo account、review attachment、VPN compliance、TestFlight group、
App Store Connect app record、export compliance、beta app review 和 App Review submission 人工确认，
因此 iOS upload 和 release asset 发布保持阻断。

```text
ios-app-review-manual-confirmation-status=pending
ios-app-review-manual-confirmation-source-contract=docs/architecture/ios-app-review-manual-confirmation-source-contract.md
ios-app-review-app-privacy-answers=blocked
ios-app-review-privacy-policy-url=blocked
ios-app-review-notes=blocked
ios-app-review-demo-account=blocked
ios-app-review-demo-mode=blocked
ios-app-review-review-attachment=blocked
ios-app-review-vpn-compliance=blocked
ios-app-review-testflight-group=blocked
ios-app-review-app-store-connect-app-record=blocked
ios-app-review-export-compliance=blocked
ios-app-review-beta-app-review=blocked
ios-app-review-app-review-submission=blocked
ios-app-review-testflight-upload=blocked
ios-app-review-release-assets=blocked
ios-app-review-confirmed-at=pending
ios-app-review-confirmed-by=pending
```

人工确认完成前，不得定义 TestFlight upload、App Store upload、App Review submission 或 iOS release asset。
未来从 pending 切换到 confirmed 时，必须遵守
`docs/architecture/ios-app-review-manual-confirmation-source-contract.md` 中的独立人工确认提交、
字段、脱敏和 upload/release 阻断规则。

## iOS TestFlight/App Store Connect Upload Workflow

以下字段是后续 iOS release readiness 读取的机器状态。当前没有真实 Swift/Xcode source、signing、
archive/export、App Store Connect API、protected environment 或 manual approval，因此 upload/release 保持阻断。

```text
ios-upload-workflow-status=pending
ios-upload-workflow-source-contract=docs/architecture/ios-testflight-app-store-connect-upload-workflow-source-contract.md
ios-upload-workflow-archive-export=blocked
ios-upload-workflow-app-store-connect-api=blocked
ios-upload-workflow-protected-environment=blocked
ios-upload-workflow-manual-approval=blocked
ios-upload-workflow-testflight-upload=blocked
ios-upload-workflow-app-store-upload=blocked
ios-upload-workflow-app-review-submission=blocked
ios-upload-workflow-release-assets=blocked
ios-upload-workflow-macos-runner=blocked
ios-upload-workflow-build-processing-check=blocked
ios-upload-workflow-confirmed-at=pending
ios-upload-workflow-confirmed-by=pending
```

当前 workflow activation validation 仍是 blocked placeholder：`ios-upload-readiness` 只读取本节 marker、
检查 source contract、输出 source tree preflight、protected environment/manual approval/App Store Connect API secret status/
archive/export/upload/submission/release asset 的 blocked 状态，不读取 secret、不定义真实 upload job。

iOS Swift/Xcode source tree activation preflight 也保持 blocked：仓库只允许 `apps/ios/README.md` 作为 source tree
governance placeholder，仍没有真实 `apps/ios` Swift source tree、`Package.swift`、Swift source、Xcode project、
Network Extension target、`PrivacyInfo.xcprivacy`、entitlement/provisioning source 或 iOS release asset。
`ios-upload-workflow-status` 不得切换为 `enabled`，直到 source tree、manual confirmation、protected environment
和 secret setup 都按合同完成并通过 GitHub Actions。`Package.swift` source ownership preflight contract 和
`docs/architecture/ios-package-swift-manifest-only-activation-validation-contract.md` 已补充，当前 Package.swift ownership gate
与 manifest-only activation validation gate 仍是 blocked-placeholder；仍不得新增真实 `Package.swift` 或 Swift source。

人工确认和 workflow activation enabled marker 完成前，不得定义 archive/export、TestFlight upload、App Store upload、
App Review submission 或 iOS release asset。未来从 pending 切换到 enabled 时，必须遵守
`docs/architecture/ios-testflight-app-store-connect-upload-workflow-source-contract.md` 和
`docs/architecture/ios-upload-workflow-activation-validation-contract.md`、
`docs/architecture/ios-swift-xcode-source-tree-activation-preflight-contract.md` 中的独立启用提交、protected environment、
manual approval、secret redaction、source tree gate 和 upload/release 阻断规则。
