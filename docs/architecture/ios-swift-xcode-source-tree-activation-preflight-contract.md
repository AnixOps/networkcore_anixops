# iOS Swift Xcode Source Tree Activation Preflight Contract

本文件定义真实 `apps/ios` source tree、`Package.swift`、Xcode project、Network Extension target、
`PrivacyInfo.xcprivacy`、entitlement/provisioning source 和 upload workflow enabled marker 进入仓库前的
activation preflight contract。它只允许 GitHub Actions 静态检查和 release/upload blocked 输出；不允许新增
Swift/Xcode project、Network Extension target、Privacy Manifest、ExportOptions.plist、archive/export、签名、
TestFlight upload、App Store upload、App Review submission 或 iOS release asset。

本合同承接 [iOS Swift Xcode Bridge Source Contract](ios-swift-xcode-bridge-source-contract.md)、
[iOS Package.swift Source Ownership Activation Preflight Contract](ios-package-swift-source-ownership-activation-preflight-contract.md)、
[iOS Entitlement Provisioning Source Contract](ios-entitlement-provisioning-source-contract.md)、
[iOS Privacy Manifest Source Contract](ios-privacy-manifest-source-contract.md)、
[iOS TestFlight App Store Connect Upload Workflow Source Contract](ios-testflight-app-store-connect-upload-workflow-source-contract.md) 和
[iOS Upload Workflow Activation Validation Contract](ios-upload-workflow-activation-validation-contract.md)。

当前状态：readme-placeholder-no-swift-source。仓库只允许 `apps/ios/README.md` 作为 source tree governance
placeholder；仍不包含 `Package.swift`、Swift source、Xcode project、workspace、Network Extension target、
`PrivacyInfo.xcprivacy`、`.entitlements`、ExportOptions.plist、`.ipa`、`.xcarchive`、`.xcresult`、dSYM bundle、
Provisioning Profile、signing config、TestFlight upload、App Store upload、App Review submission 或 iOS release asset。

## Goals

- 固定未来真实 `apps/ios` source tree 的目录布局和 source ownership。
- 定义 `Package.swift`、Xcode project/workspace、Network Extension target、`PrivacyInfo.xcprivacy`、
  entitlement/provisioning source 的 activation preflight gate。
- 定义 GitHub Actions `macos-26` source scan 在 Swift/Xcode 文件出现后的最小验证职责。
- 定义 upload workflow enabled marker 的前置条件，确保 source tree 未验证前不能把 upload workflow 从 pending 切换为 enabled。
- 让 release workflow placeholder summary 输出 source tree preflight、source scan、Privacy Manifest、entitlement/provisioning、
  Network Extension target、upload marker 和 release/upload blocked 状态。

## Non-Goals

- 不新增 Swift source、`Package.swift`、`.xcodeproj`、`.xcworkspace`、Network Extension target、
  `PrivacyInfo.xcprivacy`、`.entitlements` 或 Apple project 文件。
- 不执行 `swift build`、`swift test`、`xcodebuild`、archive/export、signing、TestFlight upload、App Store upload、
  App Review submission 或 release asset upload。
- 不读取、创建、提交或解码 Team ID、Provisioning Profile、certificate、private key、App Store Connect API key、
  Keychain item、App Group secret、tester email 或 demo account credential。

## Future Source Tree Layout

未来真实 source tree 必须以 `apps/ios` 为唯一根目录。最小 layout：

```text
apps/ios/
  README.md
  Package.swift
  Sources/
    NetworkCoreBridge/
      IosPlatformSnapshotDTO.swift
      IosPlatformBridgeMapper.swift
      NetworkCoreRuntimeFFI.swift
    NetworkCoreApp/
      AppCoordinator.swift
      VpnConfigurationController.swift
    NetworkCorePacketTunnel/
      PacketTunnelProvider.swift
  Tests/
    NetworkCoreBridgeTests/
      IosPlatformBridgeMapperTests.swift
```

规则：

- `apps/ios/README.md` 是当前唯一允许的 source tree governance placeholder，不能声称 Swift/Xcode source tree 已启用。
- `Package.swift` 出现前，必须先满足 [iOS Package.swift Source Ownership Activation Preflight Contract](ios-package-swift-source-ownership-activation-preflight-contract.md)。
- `Package.swift` 出现时，CI 必须在 GitHub Actions 上启用 Swift package source scan，并只在 Actions 中运行
  `swift build`/`swift test`；manifest-only activation 仍必须保持 Swift source blocked，直到后续 Swift source gate 完成。
- `.xcodeproj` 或 `.xcworkspace` 出现时，必须引用同一 `apps/ios` source tree，不能成为唯一 source of truth。
- `NetworkCorePacketTunnel` 是唯一允许承载 `NEPacketTunnelProvider` 的 target 名称。
- `NetworkCoreBridge` 是 Swift DTO、FFI handoff 和 safe diagnostics 的唯一 Swift bridge package target。

## Activation Preflight Gates

| Gate | Required before enablement | Current status |
| --- | --- | --- |
| Source root | `apps/ios` layout reviewed and repository-relative | readme-placeholder |
| Swift package | `Package.swift` source ownership, target list and no secret settings | blocked |
| Xcode project | project/workspace references `apps/ios` only and no signing secrets | blocked |
| Network Extension target | `NetworkCorePacketTunnel` target membership and `PacketTunnelProvider.swift` source check | blocked |
| Privacy Manifest | `PrivacyInfo.xcprivacy` location and required privacy fields contract | blocked |
| Entitlement/provisioning | `.entitlements` source contract and no provisioning/signing material in repo | blocked |
| macOS source scan | `macos-26` static source scan for Swift/Xcode/Privacy/entitlement files | blocked-before-source |
| Upload enabled marker | `ios-upload-workflow-status=enabled` only after all source and manual gates pass | blocked |
| Release/upload | no archive/export/upload/submission/release asset until all gates are complete | blocked |

## README Governance Placeholder

`apps/ios/README.md` is allowed before Swift/Xcode activation only if it:

- States `readme-placeholder-no-swift-source`.
- Defines future Swift package ownership under `apps/ios`.
- Defines the source directory guard for future `Package.swift`, `Sources` and `Tests`.
- States no `Package.swift`, no Swift source and no Xcode project are currently enabled.
- Names the `macos-26` source scan hook for future Swift/Xcode validation.
- States the upload workflow enabled marker remains blocked.

This placeholder is not a source tree activation. It must not introduce source, project, signing, archive/export or upload material.

## GitHub Actions `macos-26` Source Scan

When Swift/Xcode source files are introduced, CI must add an Apple platform static source scan on `macos-26` before any upload
workflow can be enabled. The scan must verify:

- `Package.swift` exists only under `apps/ios/Package.swift`.
- Swift files exist only under `apps/ios/Sources` or `apps/ios/Tests`.
- `NetworkCorePacketTunnel/PacketTunnelProvider.swift` exists before any Network Extension target is declared.
- Xcode project or workspace target membership points to `apps/ios` paths only.
- `PrivacyInfo.xcprivacy` exists only at the contract-approved path and contains no account identifiers or secrets.
- `.entitlements` files contain only minimal capability keys and no Team ID, profile UUID, certificate identity or secret value.
- No `ExportOptions.plist`, `.ipa`, `.xcarchive`, `.xcresult`, dSYM bundle, Provisioning Profile, certificate, private key,
  temporary keychain, DerivedData or upload credential is committed.

Current repository policy may run the preflight contract check on `ubuntu-latest` because it is a pure repository governance static
gate. Any Swift/Xcode build, source scan using Apple tooling, signing, archive/export or upload validation must run only in GitHub
Actions on `macos-26` or Apple official platforms.

## Upload Workflow Enabled Marker Preconditions

`docs/manual-intervention.md` must keep `ios-upload-workflow-status=pending` until all of these are true in independent commits:

1. This source tree activation preflight contract passes CI static governance.
2. `apps/ios/README.md` governance placeholder exists with source ownership and source directory guard.
3. `apps/ios` source tree exists and `Package.swift` passes GitHub Actions Swift validation.
4. Xcode project/workspace and `NetworkCorePacketTunnel` target pass `macos-26` source scan.
5. `PrivacyInfo.xcprivacy` passes Privacy Manifest source contract and App Privacy answer source checks.
6. Entitlement/provisioning source passes redaction checks and GitHub Secrets/manual intervention are configured.
7. iOS App Review manual confirmation marker is confirmed.
8. Protected environment, manual approval and App Store Connect API secret setup are complete.

If any precondition is missing, `ios-upload-workflow-status` must remain `pending`, and release/upload outputs must remain blocked.

## Required Placeholder Output Fields

`ios-upload-readiness`, `release-placeholder` and `release-summary` must output these fields while source tree activation is blocked:

```text
ios-source-tree-preflight-contract=present
ios-source-tree-preflight-source=ios-upload-readiness
ios-source-tree-preflight-status=blocked-placeholder
ios-source-tree-preflight-current-mode=readme-placeholder-no-swift-source
ios-source-tree-preflight-contract-path=docs/architecture/ios-swift-xcode-source-tree-activation-preflight-contract.md
ios-source-tree-preflight-root=apps/ios
ios-source-tree-preflight-root-status=readme-placeholder
ios-source-tree-preflight-readme-placeholder=present
ios-source-tree-preflight-package-swift=blocked
ios-source-tree-preflight-xcode-project=blocked
ios-source-tree-preflight-network-extension-target=blocked
ios-source-tree-preflight-privacy-manifest=blocked
ios-source-tree-preflight-entitlement-provisioning=blocked
ios-source-tree-preflight-macos-runner=macos-26
ios-source-tree-preflight-source-scan=blocked-before-source
ios-source-tree-preflight-upload-enabled-marker=blocked
ios-source-tree-preflight-release-upload=blocked
ios-source-tree-preflight-next-action=add-package-swift-only-after-ownership-gate
```

## Failure Modes

- Contract missing: fail repository policy and release readiness before summary.
- Package.swift ownership contract missing: fail before any future `Package.swift` activation.
- `apps/ios/README.md` missing or claiming Swift/Xcode enablement: fail repository policy and release readiness.
- `Package.swift` appears outside `apps/ios`: fail source scan.
- Swift source appears outside `apps/ios/Sources` or `apps/ios/Tests`: fail source scan.
- Xcode project declares signing identity, Team ID, profile UUID or account identifier: fail source scan.
- `NetworkCorePacketTunnel` target missing while Network Extension source exists: fail source scan.
- `PrivacyInfo.xcprivacy` missing after privacy manifest source is enabled: fail source scan.
- `.entitlements` includes non-minimal or secret-bearing values: fail source scan.
- `ios-upload-workflow-status=enabled` before source/manual/protected-environment gates: fail closed before upload.

## GitHub Actions Static Gate

Current `.github/workflows/ci.yml` must check:

- This file exists and contains `iOS Swift Xcode Source Tree Activation Preflight Contract`.
- The Package.swift ownership contract exists and contains `apps/ios/Package.swift`, target ownership, source directory guard,
  no Swift source until package gate, `macos-26` Swift package validation hook and blocked upload/release anchors.
- Required anchors are present: `apps/ios`, `Package.swift`, `Xcode project`, `NetworkCorePacketTunnel`,
  `PrivacyInfo.xcprivacy`, `entitlement/provisioning`, `macos-26 source scan`, `upload workflow enabled marker`,
  `release/upload blocked`, `readme-placeholder-no-swift-source`, `ios-source-tree-preflight`, `blocked-placeholder`
  and no iOS release asset.
- `apps/ios/README.md` exists and contains source ownership, source directory guard, no `Package.swift`, no Swift source,
  no Xcode project, `macos-26` source scan hook and upload workflow enabled marker blocked anchors.
- `.github/workflows/release.yml` emits the required placeholder fields in `ios-upload-readiness`, `release-placeholder`
  and `release-summary`.
- The repository still has no `Package.swift`, Swift source, Xcode project/workspace, `PrivacyInfo.xcprivacy`,
  `.entitlements`, ExportOptions.plist, `.ipa`, `.xcarchive`, `.xcresult`, dSYM bundle, Provisioning Profile,
  signing config, TestFlight upload, App Store upload, App Review submission or iOS release asset.

## Acceptance Criteria

- README, ROADMAP, TODO, CHANGELOG, CI/CD policy, release strategy, Package.swift ownership preflight contract and upstream iOS
  contracts link this contract.
- CI static governance checks this contract, release workflow fields and forbidden iOS source/artifact material.
- Release workflow placeholder and summary output source tree preflight blocked fields.
- `apps/ios/README.md` exists as the only source tree governance placeholder.
- No `apps/ios` Swift source tree, `Package.swift`, Swift source, Xcode project/workspace, Network Extension target,
  `PrivacyInfo.xcprivacy`, `.entitlements`, ExportOptions.plist, `.ipa`, `.xcarchive`, `.xcresult`, dSYM bundle,
  signing config, TestFlight upload, App Store upload, App Review submission or iOS release asset is added.
- Linux artifact remains blocked on license/NOTICE confirmed marker; `package-linux` and release asset remain undefined/blocked.
