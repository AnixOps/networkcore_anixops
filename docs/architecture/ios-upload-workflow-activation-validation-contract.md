# iOS Upload Workflow Activation Validation Contract

本文件定义 iOS upload workflow 从 source contract 走向 release workflow placeholder 的 activation validation
contract。它只允许 GitHub Actions 静态读取 marker、输出 release workflow placeholder summary 和 blocked 状态；
不允许启用 archive/export、签名、TestFlight upload、App Store upload、App Review submission 或 iOS release asset。

本合同承接 [iOS TestFlight App Store Connect Upload Workflow Source Contract](ios-testflight-app-store-connect-upload-workflow-source-contract.md)
和 [iOS App Review Manual Confirmation Source Contract](ios-app-review-manual-confirmation-source-contract.md)，并由
[iOS Swift Xcode Source Tree Activation Preflight Contract](ios-swift-xcode-source-tree-activation-preflight-contract.md)
和 [iOS Package.swift Source Ownership Activation Preflight Contract](ios-package-swift-source-ownership-activation-preflight-contract.md)
以及 [iOS Package.swift Manifest-Only Activation Validation Contract](ios-package-swift-manifest-only-activation-validation-contract.md)
固定 upload enabled marker 前的 source tree preflight gate。

当前状态：blocked-placeholder。仓库只允许 `apps/ios/README.md` 作为 source tree governance placeholder，仍不包含
`apps/ios` Swift source tree、Swift source、`Package.swift`、Xcode project、Network Extension target、
`PrivacyInfo.xcprivacy`、ExportOptions.plist、`.ipa`、`.xcarchive`、`.xcresult`、dSYM bundle、Provisioning Profile、
App Store Connect API key、真实 signing material、TestFlight upload job、App Store upload job、App Review submission
job 或 iOS release asset。本地仍不得运行 `swift build`、`swift test`、`xcodebuild`、archive/export、签名、上传或发布验证。

## Goals

- 在 release workflow 中新增只读 `ios-upload-readiness` placeholder job，验证 source contract、manual marker 和禁止项。
- 固定 release workflow placeholder summary 必须输出 iOS upload workflow activation contract、marker 状态、protected
  environment、manual approval、App Store Connect API secret status、archive/export/upload/submission blocked 和 release
  asset blocked 字段。
- 固定 source tree preflight contract 必须先输出 `apps/ios` README placeholder、`Package.swift`、Package.swift ownership、
  Package.swift manifest-only activation、Xcode project、Network Extension target、`PrivacyInfo.xcprivacy`、
  entitlement/provisioning、upload enabled marker 和 release/upload blocked 状态。
- 定义 `ios-upload-workflow` marker 读取规则，任何 missing、unknown、enabled-without-activation 或 pending/enabled 冲突都 fail closed。
- 定义未来真实 workflow 的 required needs、permissions、protected environment、secret status、outputs 和 failure modes。
- 继续阻止 Swift/Xcode project、Network Extension target、`PrivacyInfo.xcprivacy`、ExportOptions.plist、`.ipa`、
  `.xcarchive`、`.xcresult`、dSYM bundle、真实 signing、TestFlight upload、App Store upload、App Review submission
  或 iOS release asset 过早进入仓库。

## Non-Goals

- 不新增真实 `ios-archive-export`、`ios-upload-testflight`、`ios-build-processing-gate`、`ios-app-review-submission-gate`
  或 `ios-release-summary` job。
- 不读取、验证、打印或解码 App Store Connect API secret、certificate、private key、Team ID、Provisioning Profile
  或 temporary keychain。
- 不运行 `xcodebuild archive`、`xcodebuild -exportArchive`、`altool`、`notarytool`、`app-store-connect` upload
  或任何 Apple 上传命令。
- 不上传 workflow artifact、GitHub Release asset、TestFlight build、App Store build 或 App Review submission。

## Current Placeholder Job Contract

当前 release workflow 只允许定义 `ios-upload-readiness`：

| Field | Value |
| --- | --- |
| Job | `ios-upload-readiness` |
| Runner | `ubuntu-latest` |
| Current mode | `contract-only-no-ios-upload` |
| Source contract | `docs/architecture/ios-testflight-app-store-connect-upload-workflow-source-contract.md` |
| Activation contract | `docs/architecture/ios-upload-workflow-activation-validation-contract.md` |
| Manual marker source | `docs/manual-intervention.md` |
| Secrets | not read |
| Environment | not attached |
| Archive/export | blocked |
| Upload/submission | blocked |
| Release asset | blocked |

该 job 只能 checkout 仓库、执行静态 grep/find 检查、写 GitHub Step Summary 和 stdout fields。它必须继续通过
`ubuntu-latest` 证明当前阶段是 repository governance placeholder；真实 archive/export 的 future runner 才能是
`macos-26`。

## Marker Read Contract

`ios-upload-readiness` 必须读取 `docs/manual-intervention.md` 中以下 `ios-upload-workflow` marker：

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

规则：

- 当前 placeholder 只接受 `ios-upload-workflow-status=pending` 和全部 blocked marker。
- 如果同一文件同时出现 `pending` 和 `enabled`，必须 fail closed。
- 如果 marker 缺失、未知、包含未脱敏 owner、或者提前出现 enabled upload/release 字段，必须 fail closed。
- `ios-app-review-manual-confirmation-status=confirmed`、真实 Swift/Xcode source、protected environment 和 signing/upload
  secrets 未完成前，不得把 `ios-upload-workflow-status` 切换为 `enabled`。

## Protected Environment And Manual Approval

未来真实 upload workflow 必须使用 protected environment：

| Item | Contract |
| --- | --- |
| Environment name | `ios-app-store-connect` |
| Required protection | manual approval or deployment protection rule |
| Current protected environment | blocked |
| Current manual approval | blocked |
| Current readiness job environment | none |
| Future archive/upload environment | `ios-app-store-connect` |

当前 placeholder 不验证 GitHub Environment 是否真实存在，因为没有安全方式在不启用 upload path 的情况下读取
environment secret 或 deployment approval 状态。placeholder 必须输出 protected environment/manual approval blocked；
未来真实 job 只能在 environment 配置完成后独立提交启用。

## Secret Status Contract

当前 placeholder 不读取 secret value，只输出 App Store Connect API secret status 和 signing secret status 为
`not-read-blocked`。未来真实 workflow 至少需要以下 environment secrets 或等价受控输入：

```text
APP_STORE_CONNECT_API_KEY_ID
APP_STORE_CONNECT_ISSUER_ID
APP_STORE_CONNECT_API_PRIVATE_KEY
TEAM_ID
APPLE_CERTIFICATE_P12_BASE64
APPLE_CERTIFICATE_PASSWORD
APPLE_KEYCHAIN_PASSWORD
APPLE_PROVISIONING_PROFILE_BASE64
APPLE_PACKET_TUNNEL_PROVISIONING_PROFILE_BASE64
```

输出规则：

- Current App Store Connect API secret status: `not-read-blocked`。
- Current signing secret status: `not-read-blocked`。
- Future readiness summary 只能输出 `present`、`missing`、`redacted`、`validated`、`blocked` 或 `not-read-blocked`。
- 任何 secret value、issuer id、Team ID、certificate fingerprint、profile UUID、private key、tester email 或 account token
  都不得出现在 logs、Step Summary、artifact、release notes 或 repository files。

## Future Workflow Shape

真实 upload workflow 只能在 source、manual confirmation、protected environment 和 secrets 全部完成后独立启用：

| Future job | Required needs | Runner | Environment | Current status |
| --- | --- | --- | --- | --- |
| `ios-upload-readiness` | `release-policy`, `release-ci-gate` | `ubuntu-latest` or `macos-26` | none | blocked-placeholder |
| `ios-archive-export` | `release-policy`, `release-ci-gate`, `ios-upload-readiness` | `macos-26` | `ios-app-store-connect` | not-defined |
| `ios-upload-testflight` | `ios-archive-export` | `macos-26` | `ios-app-store-connect` | not-defined |
| `ios-build-processing-gate` | `ios-upload-testflight` | `macos-26` | none or read-only environment | not-defined |
| `ios-app-review-submission-gate` | `ios-build-processing-gate` | `macos-26` | `ios-app-store-connect` | not-defined |
| `ios-release-summary` | all iOS upload jobs | `ubuntu-latest` | none | not-defined |

Future `ios-archive-export` must fail before upload if archive/export output is missing, checksum is missing, signing is not redacted,
or the source `.ipa` is not produced by the same release run. Future App Review submission must default to hold-only mode unless a
separate manual approval explicitly enables submission.

## Internal TestFlight Scope

维护者在 2026-10-13 把上传范围收窄为内部 TestFlight。本节只改变范围，不放宽本合同其它 fail-closed 规则。

- 允许范围：`ios-upload-scope=internal-testflight-only`。archive、export，并通过 App Store Connect API key 上传到 TestFlight 内部测试，全部在 protected environment `ios-app-store-connect` 中完成。
- 继续 blocked，不属于本范围：External TestFlight testing（需要 Beta App Review）、App Store submission、App Review submission、GitHub release asset 和 iOS release asset。
- 启用前必需：source tree 与 Xcode project gate 已通过 GitHub Actions；App Store Connect app record 已创建；protected environment 与 manual approval 已配置；App Store Connect API key secrets 已写入 environment；export compliance 已确认；internal testing group 已建立。
- 内部范围的人工确认：`ios-upload-internal-confirmation-status=confirmed` 代替 `ios-app-review-manual-confirmation-status=confirmed`，作为启用 `ios-upload-workflow-status` 的 precondition 7。这个 marker 只能由维护者在独立提交中设置，CI 不得设置。其它 precondition 不变。
- 启用前不要求：Beta App Review、App Review Notes、demo account、review attachment、VPN compliance 材料和 App Review submission。进行外部测试或上架前，这些必须补齐。
- 隐私政策 URL 与 App Privacy 问卷：以 App Store Connect 对内部测试构建的实际要求为准。在确认不要求之前，视为必需。
- Bundle ID 与 Team ID：只能存放在 GitHub Variables 或 environment secret 中。仓库文件、合同与 manual log 都不记录具体值。
- App Store Connect API key：个人账号的 Individual API Key 不能使用 Provisioning endpoints。上传 job 使用手动描述文件，不依赖自动签名。如果以后需要 Provisioning endpoints，必须改用团队 key 并重新审查本节。
- 启用仍需独立提交：真实 upload job 和 `ios-upload-workflow-status` 从 `pending` 切换为 `enabled`，都必须在各自的独立提交中完成。

## Internal TestFlight Workflow

内部 TestFlight 上传由独立的手动 workflow `.github/workflows/ios-testflight.yml` 承担，不进入 tag 触发的
`release.yml`，因此 `release.yml` 仍只定义 `ios-upload-readiness` placeholder，上面 Future Workflow Shape 中的 release
jobs 仍为 not-defined。本 workflow 是“真实 upload job”的独立提交；`ios-upload-workflow-status` 从 `pending` 切换为
`enabled` 仍是另一个独立提交。

| Item | Contract |
| --- | --- |
| Trigger | `workflow_dispatch` only |
| Preflight job | `ios-upload-preflight` on `ubuntu-latest`; fails closed unless `ios-upload-workflow-status=enabled` and `ios-upload-internal-confirmation-status=confirmed` |
| Upload job | `ios-archive-upload` on `macos-26`, `needs: ios-upload-preflight`, environment `ios-app-store-connect` |
| Signing | manual signing with the Apple Distribution certificate and two App Store provisioning profiles; temporary keychain removed with `if: always()` |
| Bundle IDs | GitHub Variables `IOS_APP_BUNDLE_ID` and `IOS_TUNNEL_BUNDLE_ID`, written into the runner copy of `project.yml` only |
| Build number | `github.run_number` |
| Export | runner-generated `ExportOptions.plist` with `method=app-store-connect`, `destination=upload`, `testFlightInternalTestingOnly=true` |
| Secrets output | `present` or `missing` only; no values, Team ID, profile UUID or bundle ID in logs or summary |
| Artifacts | no workflow artifact, GitHub Release asset or iOS release asset |

`ios-upload-workflow-status=enabled` 的独立提交必须同时把 `.github/workflows/ci.yml` 中
`^ios-upload-workflow-status=pending$` 的静态检查改为 enabled 分支，否则 CI 会按设计失败。

## Required Output Fields

`ios-upload-readiness`, `release-placeholder` and `release-summary` must output these safe fields while the workflow is blocked:

```text
ios-upload-workflow-activation-contract=present
ios-upload-workflow-activation-source=ios-upload-readiness
ios-upload-workflow-activation-status=blocked-placeholder
ios-upload-workflow-activation-current-mode=contract-only-no-ios-upload
ios-upload-workflow-source-contract=docs/architecture/ios-testflight-app-store-connect-upload-workflow-source-contract.md
ios-upload-workflow-activation-contract-path=docs/architecture/ios-upload-workflow-activation-validation-contract.md
ios-upload-workflow-manual-source=docs/manual-intervention.md
ios-upload-workflow-marker-status=pending
ios-upload-workflow-required-needs=release-policy,release-ci-gate,ios-upload-readiness
ios-upload-workflow-required-runner=macos-26
ios-upload-workflow-current-runner=ubuntu-latest-static-placeholder
ios-upload-workflow-protected-environment-name=ios-app-store-connect
ios-upload-workflow-protected-environment=blocked
ios-upload-workflow-manual-approval=blocked
ios-upload-workflow-app-store-connect-api-secret-status=not-read-blocked
ios-upload-workflow-signing-secret-status=not-read-blocked
ios-upload-workflow-archive-export=blocked
ios-upload-workflow-testflight-upload=blocked
ios-upload-workflow-app-store-upload=blocked
ios-upload-workflow-app-review-submission=blocked
ios-upload-workflow-build-processing-check=blocked
ios-upload-workflow-release-assets=blocked
ios-upload-workflow-upload-jobs=not-defined
ios-upload-workflow-release-asset=blocked
ios-upload-workflow-next-action=swift-xcode-source-and-manual-confirmation-before-activation
```

## Failure Modes

- Source contract missing: fail before release placeholder summary.
- Activation contract missing: fail before release placeholder summary.
- Manual marker missing or unknown: fail closed.
- Pending and enabled marker both present: fail closed.
- Protected environment missing: output blocked in placeholder; future real upload job fails before archive/export.
- Manual approval missing: output blocked in placeholder; future upload/submission job fails before upload or submission.
- App Store Connect API secret missing: output `not-read-blocked` in placeholder; future upload job fails before upload.
- Archive/export blocked: output blocked and do not create `.ipa`, `.xcarchive`, `.xcresult` or dSYM bundle.
- Upload blocked: do not call Apple upload tooling, App Store Connect API upload endpoint or release asset upload.
- Submission blocked: do not submit beta app review, App Review or App Store release.

## GitHub Actions Static Gate

`.github/workflows/ci.yml` must statically check:

- This file exists and includes iOS Upload Workflow Activation Validation Contract.
- The source contract, release workflow placeholder summary, `ios-upload-workflow` marker, protected environment, manual approval,
  App Store Connect API secret status, archive/export/upload/submission blocked, `ios-upload-readiness`, required needs,
  `not-read-blocked`, `blocked-placeholder`, `macos-26` and no iOS release asset anchors are present.
- The source tree preflight, Package.swift ownership and Package.swift manifest-only activation contracts exist, and their
  `ios-source-tree-preflight`, `ios-package-swift-ownership` and `ios-package-swift-manifest-only` fields are emitted before upload
  activation fields.
- `.github/workflows/release.yml` defines only the placeholder `ios-upload-readiness` job and not real iOS upload jobs.
- `docs/manual-intervention.md` still contains the pending/blocked `ios-upload-workflow` marker set.
- Except for the `apps/ios/README.md` governance placeholder, the repository still has no `apps/ios` Swift source tree,
  `Package.swift`, Swift source, `PrivacyInfo.xcprivacy`, Xcode project, Network Extension target, ExportOptions.plist, `.ipa`,
  `.xcarchive`, `.xcresult`, dSYM bundle, signing material, Provisioning Profile, TestFlight upload, App Store upload,
  App Review submission or iOS release asset.

`.github/workflows/release.yml` must output the source tree preflight fields and activation fields in `ios-upload-readiness`,
`release-placeholder` and `release-summary`, and must make release summary depend on `ios-upload-readiness`.

## Acceptance Criteria

- README, ROADMAP, TODO, CHANGELOG, CI/CD policy, release strategy, source tree preflight contract, Package.swift ownership
  contract, Package.swift manifest-only activation validation contract and this source contract chain are updated.
- `docs/manual-intervention.md` documents that the current iOS upload workflow activation remains blocked-placeholder.
- `.github/workflows/ci.yml` checks this contract, Package.swift ownership contract, Package.swift manifest-only activation
  validation contract, release workflow fields, manual marker and forbidden iOS artifact/source material.
- `.github/workflows/release.yml` includes only a blocked `ios-upload-readiness` placeholder and summary fields.
- No real `apps/ios` Swift source tree beyond the README governance placeholder, Swift source, `Package.swift`,
  Xcode project, Network Extension target, `PrivacyInfo.xcprivacy`, ExportOptions.plist,
  `.ipa`, `.xcarchive`, `.xcresult`, dSYM bundle, Provisioning Profile, signing config, TestFlight upload, App Store upload,
  App Review submission or iOS release asset is added.
- Linux artifact release path is confirmed; iOS release asset remains undefined/blocked.
