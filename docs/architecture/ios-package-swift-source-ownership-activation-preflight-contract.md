# iOS Package.swift Source Ownership Activation Preflight Contract

本文件定义 `apps/ios/Package.swift` 引入前的 source ownership activation preflight contract。它只允许
GitHub Actions 静态治理检查和 release/upload blocked 输出；不允许在当前增量新增真实 `Package.swift`、Swift
source、Swift/Xcode project、Network Extension target、`PrivacyInfo.xcprivacy`、entitlement/provisioning source、
archive/export、签名、TestFlight upload、App Store upload、App Review submission 或 iOS release asset。

本合同承接 [iOS Swift Xcode Source Tree Activation Preflight Contract](ios-swift-xcode-source-tree-activation-preflight-contract.md)、
[iOS Swift Xcode Bridge Source Contract](ios-swift-xcode-bridge-source-contract.md) 和
[iOS Upload Workflow Activation Validation Contract](ios-upload-workflow-activation-validation-contract.md)，并由
[iOS Package.swift Manifest-Only Activation Validation Contract](ios-package-swift-manifest-only-activation-validation-contract.md)
固定 `Package.swift` 实际进入仓库前的 manifest-only activation gate。

当前状态：blocked-placeholder-before-package-swift。仓库只允许 `apps/ios/README.md` 作为 source tree governance
placeholder；`apps/ios/Package.swift`、`apps/ios/Sources`、`apps/ios/Tests`、Swift source、Xcode project/workspace、
Network Extension target、Privacy Manifest、entitlements、signing material、archive/export、upload workflow enabled marker
和 iOS release asset 继续保持 blocked。

## Goals

- 固定未来 `apps/ios/Package.swift` 的唯一 repository-relative 路径和 target ownership。
- 定义 future Swift package target list、test target list、source directory guard 和 no Swift source until package gate。
- 定义 GitHub Actions `macos-26` Swift package validation hook 的最小职责。
- 明确 Xcode project/workspace 继续 blocked，不能与 `Package.swift` 同一增量启用。
- 明确 upload workflow enabled marker 继续 blocked，直到 source tree、manual confirmation、protected environment 和
  secret setup gates 全部完成。

## Non-Goals

- 不新增真实 `apps/ios/Package.swift`、`Sources/`、`Tests/` 或 `*.swift`。
- 不新增 `.xcodeproj`、`.xcworkspace`、Network Extension target、`PrivacyInfo.xcprivacy`、`.entitlements`、
  ExportOptions.plist、`.ipa`、`.xcarchive`、`.xcresult`、dSYM bundle、Provisioning Profile、certificate、private key、
  App Store Connect API material 或 iOS release asset。
- 不运行 `swift build`、`swift test`、`xcodebuild`、archive/export、signing、TestFlight upload、App Store upload 或
  App Review submission。
- 不读取、创建、提交或输出 Team ID、Bundle ID owner、profile UUID、certificate identity、private key、tester email、
  demo account credential 或 App Store Connect token。

## Future Package.swift Ownership

未来 `Package.swift` 只能位于：

```text
apps/ios/Package.swift
```

未来 Swift package ownership 必须满足：

| Item | Required value | Current status |
| --- | --- | --- |
| Package manifest path | `apps/ios/Package.swift` | blocked |
| Package root | `apps/ios` | readme-placeholder |
| Product ownership | `NetworkCoreIOS` package products only | blocked |
| Bridge target | `NetworkCoreBridge` | blocked |
| App target | `NetworkCoreApp` | blocked |
| Network Extension target | `NetworkCorePacketTunnel` | blocked |
| Test target | `NetworkCoreBridgeTests` | blocked |
| Xcode project/workspace | not enabled by Package.swift activation | blocked |
| Upload workflow marker | `ios-upload-workflow-status=pending` | blocked |

`Package.swift` activation must be an independent future commit. That commit may introduce the manifest only after this contract and
the manifest-only activation validation contract are checked by CI, and it must not introduce Swift source in the same change unless
a separate Swift source activation gate has already been defined and passed.

## Source Directory Guard

Future `Package.swift` may reference only repository-relative paths inside `apps/ios`:

```text
apps/ios/Sources/NetworkCoreBridge
apps/ios/Sources/NetworkCoreApp
apps/ios/Sources/NetworkCorePacketTunnel
apps/ios/Tests/NetworkCoreBridgeTests
```

Rules:

- No Swift source until package gate: `apps/ios/Sources`, `apps/ios/Tests` and `*.swift` stay absent until the package ownership
  gate is checked and a later Swift source activation gate is ready.
- No `../`, absolute path, generated source path, DerivedData path, toolchain cache path or local user path may appear in
  `Package.swift`.
- No signing settings, Team ID, provisioning reference, bundle identifier owner, App Store Connect identifier or secret-bearing
  build setting may appear in `Package.swift`.
- No remote package dependency may be added until a dependency review and license/security source contract exists.
- `NetworkCorePacketTunnel` may be named in target ownership, but the actual Network Extension target and
  `PacketTunnelProvider.swift` remain blocked until the Xcode/Network Extension source gate is complete.

## macos-26 Swift Package Validation Hook

When a future commit introduces `apps/ios/Package.swift`, GitHub Actions must add a `macos-26` Swift package validation hook before
any upload workflow can be enabled. The hook must:

- Verify the manifest exists only at `apps/ios/Package.swift`.
- Verify every target path is under `apps/ios/Sources` or `apps/ios/Tests`.
- Verify package, product, target and test target names match this contract.
- Verify no signing, provisioning, Team ID, profile UUID, certificate, App Store Connect or local path material is present.
- Keep Xcode project/workspace, Network Extension target, archive/export, signing, upload and release asset paths blocked.
- Run Swift package validation only in GitHub Actions on `macos-26`; local validation is not an accepted gate.

If Swift source is still intentionally absent during a manifest-only activation, the validation hook must explicitly report the
manifest-only state and keep `swift build`/`swift test` blocked until the later Swift source activation gate. Once Swift source is
introduced, `swift build` and `swift test` must run only in GitHub Actions.

The manifest-only activation validation contract owns the `ios-package-swift-manifest-only-*` release fields. Ownership fields remain
blocked until that later gate explicitly permits the manifest-only commit.

## Required Placeholder Output Fields

`ios-upload-readiness`, `release-placeholder` and `release-summary` must output these fields while `Package.swift` ownership
activation is blocked:

```text
ios-package-swift-ownership-contract=present
ios-package-swift-ownership-source=ios-upload-readiness
ios-package-swift-ownership-status=blocked-placeholder
ios-package-swift-ownership-current-mode=readme-placeholder-no-package-swift
ios-package-swift-ownership-contract-path=docs/architecture/ios-package-swift-source-ownership-activation-preflight-contract.md
ios-package-swift-ownership-package-path=apps/ios/Package.swift
ios-package-swift-ownership-targets=NetworkCoreBridge,NetworkCoreApp,NetworkCorePacketTunnel
ios-package-swift-ownership-test-targets=NetworkCoreBridgeTests
ios-package-swift-ownership-source-directory-guard=apps/ios/Sources,apps/ios/Tests
ios-package-swift-ownership-swift-source=blocked-until-package-gate
ios-package-swift-ownership-macos-runner=macos-26
ios-package-swift-ownership-validation-hook=swift-package-validation-blocked-before-package-swift
ios-package-swift-ownership-xcode-project=blocked
ios-package-swift-ownership-upload-enabled-marker=blocked
ios-package-swift-ownership-release-upload=blocked
ios-package-swift-ownership-next-action=add-package-swift-only-after-ownership-gate
```

## Failure Modes

- Contract missing: fail repository policy and release readiness before summary.
- `apps/ios/README.md` missing or claiming `Package.swift` is enabled: fail repository policy and release readiness.
- `Package.swift` appears outside `apps/ios/Package.swift`: fail future package source scan.
- Swift source appears before the package ownership gate: fail source scan.
- `Package.swift` contains signing, provisioning, App Store Connect, local path, generated artifact or secret-bearing settings:
  fail source scan.
- Xcode project/workspace appears in the same activation path: fail source scan until the Xcode project gate exists.
- `ios-upload-workflow-status=enabled` appears before source/manual/protected-environment gates: fail closed before upload.

## GitHub Actions Static Gate

Current `.github/workflows/ci.yml` must check:

- This file exists and contains `iOS Package.swift Source Ownership Activation Preflight Contract`.
- The manifest-only activation validation contract exists and contains `manifest-only source scan`, `target list verification`,
  no Swift source before source gate, `ios-package-swift-manifest-only` and blocked release anchors.
- Required anchors are present: `apps/ios/Package.swift`, `NetworkCoreBridge`, `NetworkCoreApp`,
  `NetworkCorePacketTunnel`, `NetworkCoreBridgeTests`, `source directory guard`, `no Swift source until package gate`,
  `macos-26 Swift package validation hook`, `Xcode project blocked`, `upload workflow enabled marker blocked`,
  `ios-package-swift-ownership`, `blocked-placeholder` and no iOS release asset.
- `.github/workflows/release.yml` emits the required placeholder fields in `ios-upload-readiness`, `release-placeholder`
  and `release-summary`.
- The repository still has no `Package.swift`, Swift source, Xcode project/workspace, `PrivacyInfo.xcprivacy`,
  `.entitlements`, ExportOptions.plist, `.ipa`, `.xcarchive`, `.xcresult`, dSYM bundle, Provisioning Profile, signing config,
  TestFlight upload, App Store upload, App Review submission or iOS release asset.

## Acceptance Criteria

- README, ROADMAP, TODO, CHANGELOG, CI/CD policy, release strategy, manual intervention notes, `apps/ios/README.md`,
  manifest-only activation validation contract and upstream iOS activation contracts link this contract.
- CI static governance checks this contract, release workflow fields and forbidden iOS source/artifact material.
- Release workflow placeholder and summary output `ios-package-swift-ownership-*` blocked fields.
- No real `apps/ios/Package.swift`, Swift source, Swift/Xcode project, Network Extension target, Privacy Manifest,
  entitlement/provisioning source, archive/export, signing, TestFlight upload, App Store upload, App Review submission or iOS
  release asset is added.
- Linux artifact remains blocked on license/NOTICE confirmed marker; `package-linux` and release asset remain undefined/blocked.
