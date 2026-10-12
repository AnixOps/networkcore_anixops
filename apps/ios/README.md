# iOS Source Tree Governance Placeholder

Current status: `swift-source-gate-active`.

This directory is the iOS application and Network Extension source tree root. The manifest-only activation adds
`Package.swift` and nothing else. Swift sources, the Xcode project, the Network Extension target and signing or upload
material remain blocked until their own gates pass.

## Ownership

- The iOS Swift package is owned by `apps/ios`. Its manifest is `apps/ios/Package.swift` and no other `Package.swift` may exist.
- Package ownership is governed by
  `docs/architecture/ios-package-swift-source-ownership-activation-preflight-contract.md`.
- Manifest-only activation is governed by
  `docs/architecture/ios-package-swift-manifest-only-activation-validation-contract.md`.
- Package targets: `NetworkCoreBridge` and `NetworkCoreApp` (library product `NetworkCoreIOS`), with `NetworkCoreBridgeTests`
  as the test target.
- `NetworkCorePacketTunnel` is the only approved Network Extension target name. It is reserved in this manifest and is not
  declared until the Network Extension gate passes.
- Swift sources may only live under `apps/ios/Sources` or `apps/ios/Tests`.
- Future Xcode project or workspace files must reference this source tree and must not become the only source of truth.

## Current Boundary

Current boundary: `Package.swift`, the Swift package sources under `Sources/` and `Tests/`, and the XcodeGen spec `project.yml` are enabled. The generated `.xcodeproj` is never committed. No Network Extension target yet.

These files and directories must stay absent until their own activation gates are complete:

- `*.swift` outside `apps/ios/Sources` and `apps/ios/Tests`
- `*.xcodeproj`
- `*.xcworkspace`
- `PrivacyInfo.xcprivacy`
- `*.entitlements`
- `ExportOptions.plist`
- `.ipa`, `.xcarchive`, `.xcresult` or dSYM bundles
- Provisioning Profile, certificate, private key, temporary keychain or App Store Connect API material

`swift build` and `swift test` run only in GitHub Actions on `macos-26`, never locally.

## CI Hook

GitHub Actions statically checks this README and runs the `macos-26` manifest validation hook,
`.github/scripts/verify-ios-package-manifest.sh`. Any Swift/Xcode source scan, Swift build, Swift test, Xcode project validation,
signing, archive/export or upload validation must run only in GitHub Actions on `macos-26` or Apple official platforms.

The upload workflow enabled marker remains blocked. `ios-upload-workflow-status` must stay `pending` until source tree,
manual confirmation, protected environment and secret setup gates are complete.
