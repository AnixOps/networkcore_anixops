# iOS Package.swift Manifest-Only Activation Validation Contract

本文件定义未来独立提交引入 `apps/ios/Package.swift` 前必须满足的 manifest-only activation validation
contract。当前增量只允许合同、CI 静态治理检查和 release/upload blocked 输出；不允许新增真实
`Package.swift`、Swift source、Swift/Xcode project、Network Extension target、`PrivacyInfo.xcprivacy`、
entitlement/provisioning source、archive/export、签名、TestFlight upload、App Store upload、App Review submission
或 iOS release asset。

本合同承接 [iOS Package.swift Source Ownership Activation Preflight Contract](ios-package-swift-source-ownership-activation-preflight-contract.md)、
[iOS Swift Xcode Source Tree Activation Preflight Contract](ios-swift-xcode-source-tree-activation-preflight-contract.md) 和
[iOS Upload Workflow Activation Validation Contract](ios-upload-workflow-activation-validation-contract.md)。它把
`Package.swift` ownership preflight 之后、Swift source gate 之前的 manifest-only source scan 和 target list
verification 固定为独立门禁。

当前状态：blocked-placeholder-before-package-swift。仓库仍只允许 `apps/ios/README.md` 作为 source tree governance
placeholder；`apps/ios/Package.swift`、`apps/ios/Sources`、`apps/ios/Tests`、Swift source、Xcode project/workspace、
Network Extension target、Privacy Manifest、entitlements、signing material、archive/export、upload workflow enabled marker
和 iOS release asset 继续保持 blocked。

## Goals

- 固定 future independent manifest-only commit 的边界：只允许引入 `apps/ios/Package.swift`，且必须由 CI 静态验证。
- 定义 manifest-only source scan，确保 manifest 只位于 `apps/ios/Package.swift`，且不引用仓库外路径、生成目录或 secret。
- 定义 target list verification，固定 `NetworkCoreBridge`、`NetworkCoreApp`、`NetworkCorePacketTunnel` 和
  `NetworkCoreBridgeTests` 名称。
- 固定 source directory guard：future target path 只能指向 `apps/ios/Sources` 和 `apps/ios/Tests`。
- 明确 no Swift source before source gate 和 no Swift source until package gate：manifest-only activation 不能同时提交 Swift source。
- 明确 Xcode project blocked、Network Extension target blocked、upload workflow enabled marker blocked 和 release/upload blocked。

## Non-Goals

- 不新增真实 `apps/ios/Package.swift`、`Sources/`、`Tests/` 或 `*.swift`。
- 不新增 `.xcodeproj`、`.xcworkspace`、`PrivacyInfo.xcprivacy`、`.entitlements`、ExportOptions.plist、`.ipa`、
  `.xcarchive`、`.xcresult`、dSYM bundle、Provisioning Profile、certificate、private key、App Store Connect API material
  或 iOS release asset。
- 不运行 `swift build`、`swift test`、`xcodebuild`、archive/export、signing、TestFlight upload、App Store upload 或
  App Review submission。
- 不定义 `ios-archive-export`、`ios-upload-testflight`、`ios-build-processing-gate`、`ios-app-review-submission-gate`
  或 `ios-release-summary` job。

## Future Manifest-Only Activation

未来 manifest-only activation 必须是独立提交。该提交只能新增：

```text
apps/ios/Package.swift
```

未来 `Package.swift` 必须声明的 target ownership：

| Item | Required value | Current status |
| --- | --- | --- |
| Package manifest path | `apps/ios/Package.swift` | blocked |
| Package root | `apps/ios` | readme-placeholder |
| Bridge target | `NetworkCoreBridge` | blocked |
| App target | `NetworkCoreApp` | blocked |
| Network Extension target name | `NetworkCorePacketTunnel` | blocked |
| Test target | `NetworkCoreBridgeTests` | blocked |
| Source directory guard | `apps/ios/Sources`, `apps/ios/Tests` | blocked |
| Swift source | no Swift source before source gate | blocked |
| Xcode project | Xcode project blocked | blocked |
| Upload workflow marker | upload workflow enabled marker blocked | blocked |
| Release/upload | release/upload blocked | blocked |

## manifest-only source scan

当未来提交引入 `apps/ios/Package.swift` 时，GitHub Actions 必须在 `macos-26` 上新增 Swift package validation hook。
manifest-only source scan 的最小职责：

- Verify `Package.swift` exists only at `apps/ios/Package.swift`.
- Verify package, product, target and test target names match target list verification.
- Verify target paths stay under `apps/ios/Sources` or `apps/ios/Tests`.
- Verify no Swift source before source gate: `apps/ios/Sources`, `apps/ios/Tests` and `*.swift` stay absent unless a later Swift
  source activation gate is also complete.
- Verify no signing, provisioning, Team ID, profile UUID, certificate, App Store Connect, local absolute path, `../`, DerivedData,
  generated artifact or secret-bearing setting appears in the manifest.
- Keep Xcode project blocked, Network Extension target blocked, archive/export blocked, upload blocked and no iOS release asset.

The Swift package validation hook may report a manifest-only state, but `swift build` and `swift test` must remain blocked until the
later Swift source gate exists and passes in GitHub Actions. Local validation is not accepted.

## Required Placeholder Output Fields

`ios-upload-readiness`, `release-placeholder` and `release-summary` must output these fields while manifest-only activation is blocked:

```text
ios-package-swift-manifest-only-contract=present
ios-package-swift-manifest-only-source=ios-upload-readiness
ios-package-swift-manifest-only-status=blocked-placeholder
ios-package-swift-manifest-only-current-mode=readme-placeholder-no-package-swift
ios-package-swift-manifest-only-contract-path=docs/architecture/ios-package-swift-manifest-only-activation-validation-contract.md
ios-package-swift-manifest-only-package-path=apps/ios/Package.swift
ios-package-swift-manifest-only-manifest-status=blocked
ios-package-swift-manifest-only-activation-scope=future-independent-manifest-only-commit
ios-package-swift-manifest-only-source-scan=manifest-only-source-scan-blocked-before-package-swift
ios-package-swift-manifest-only-target-list-verification=blocked-before-package-swift
ios-package-swift-manifest-only-targets=NetworkCoreBridge,NetworkCoreApp,NetworkCorePacketTunnel
ios-package-swift-manifest-only-test-targets=NetworkCoreBridgeTests
ios-package-swift-manifest-only-source-directory-guard=apps/ios/Sources,apps/ios/Tests
ios-package-swift-manifest-only-swift-source=blocked-before-source-gate
ios-package-swift-manifest-only-swift-build-test=blocked-until-swift-source-gate
ios-package-swift-manifest-only-macos-runner=macos-26
ios-package-swift-manifest-only-validation-hook=manifest-only-validation-blocked-before-package-swift
ios-package-swift-manifest-only-xcode-project=blocked
ios-package-swift-manifest-only-network-extension-target=blocked
ios-package-swift-manifest-only-upload-enabled-marker=blocked
ios-package-swift-manifest-only-release-upload=blocked
ios-package-swift-manifest-only-release-asset=blocked
ios-package-swift-manifest-only-next-action=add-package-swift-manifest-only-after-contract-gate
```

## Failure Modes

- Contract missing: fail repository policy and release readiness before summary.
- `apps/ios/README.md` missing or claiming `Package.swift` is enabled: fail repository policy and release readiness.
- `Package.swift` appears before this contract and CI static governance pass: fail closed.
- Swift source appears in the same manifest-only activation without a later Swift source gate: fail source scan.
- `Package.swift` contains signing, provisioning, App Store Connect, local path, generated artifact or secret-bearing settings:
  fail source scan.
- Xcode project/workspace, Network Extension target, archive/export, signing, upload job or iOS release asset appears in the same
  activation path: fail closed before upload.
- `ios-upload-workflow-status=enabled` appears before source/manual/protected-environment gates: fail closed before upload.

## GitHub Actions Static Gate

Current `.github/workflows/ci.yml` must check:

- This file exists and contains `iOS Package.swift Manifest-Only Activation Validation Contract`.
- Required anchors are present: `apps/ios/Package.swift`, `manifest-only activation`, `manifest-only source scan`,
  `target list verification`, `NetworkCoreBridge`, `NetworkCoreApp`, `NetworkCorePacketTunnel`, `NetworkCoreBridgeTests`,
  `source directory guard`, `no Swift source before source gate`, `no Swift source until package gate`, `macos-26`,
  `Swift package validation hook`, `Xcode project blocked`, `upload workflow enabled marker blocked`, `release/upload blocked`,
  `ios-package-swift-manifest-only`, `blocked-placeholder` and no iOS release asset.
- `.github/workflows/release.yml` emits the required placeholder fields in `ios-upload-readiness`, `release-placeholder`
  and `release-summary`.
- The repository still has no `Package.swift`, Swift source, Xcode project/workspace, `PrivacyInfo.xcprivacy`, `.entitlements`,
  ExportOptions.plist, `.ipa`, `.xcarchive`, `.xcresult`, dSYM bundle, Provisioning Profile, signing config, TestFlight upload,
  App Store upload, App Review submission or iOS release asset.

## Acceptance Criteria

- README, ROADMAP, TODO, CHANGELOG, CI/CD policy, release strategy, source tree preflight contract, Package.swift ownership
  preflight contract and upload workflow activation contract link this contract.
- CI static governance checks this contract, release workflow fields and forbidden iOS source/artifact material.
- Release workflow placeholder and summary output `ios-package-swift-manifest-only-*` blocked fields.
- `apps/ios/README.md` remains the only iOS source tree file.
- No `apps/ios/Package.swift`, Swift source, Xcode project/workspace, Network Extension target, `PrivacyInfo.xcprivacy`,
  `.entitlements`, ExportOptions.plist, `.ipa`, `.xcarchive`, `.xcresult`, dSYM bundle, signing config, TestFlight upload,
  App Store upload, App Review submission or iOS release asset is added.
- Linux artifact remains blocked on license/NOTICE confirmed marker; `package-linux` and release asset remain undefined/blocked.
