# iOS Source Tree Governance Placeholder

Current status: `swift-source-gate-active`.

This directory is the iOS application and Network Extension source tree root. The Swift package, the XcodeGen spec and
the `NetworkCorePacketTunnel` extension target are active. Signing, archive/export and upload material remain blocked until
their own gates pass.

## Ownership

- The iOS Swift package is owned by `apps/ios`. Its manifest is `apps/ios/Package.swift` and no other `Package.swift` may exist.
- Package ownership is governed by
  `docs/architecture/ios-package-swift-source-ownership-activation-preflight-contract.md`.
- Manifest-only activation is governed by
  `docs/architecture/ios-package-swift-manifest-only-activation-validation-contract.md`.
- Package targets: `NetworkCoreBridge` and `NetworkCoreApp` (library product `NetworkCoreIOS`), with `NetworkCoreBridgeTests`
  as the test target.
- `NetworkCorePacketTunnel` is the only approved Network Extension target name. It is declared in `project.yml` as an
  app extension, not in `Package.swift`. It links the embedded Rust runtime (`crates/engine-embedded`) as
  `Generated/NetworkCoreRuntime.xcframework`, which GitHub Actions builds with
  `.github/scripts/build-ios-runtime-xcframework.sh` and never commits. The extension imports the C ABI as the Clang
  module `NetworkCoreRuntimeC` and fails closed when the runtime handshake or the tunnel profile is invalid. The containing
  app does not link the runtime.
- M1a tunnel profile: the app imports one Shadowsocks-2022 `ss://` link. The node key goes into the Keychain
  (`NodeSecretStore`, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`) and the profile keeps only its persistent
  reference in `NETunnelProviderProtocol.passwordReference`; `providerConfiguration` holds the runtime config without
  the key. Both targets list `$(AppIdentifierPrefix)networkcore.shared` first in `keychain-access-groups`, so the
  extension reads the item the app saved. The default team-prefixed profiles already allow this group.
- Swift sources may only live under `apps/ios/Sources` or `apps/ios/Tests`.
- Future Xcode project or workspace files must reference this source tree and must not become the only source of truth.

## Current Boundary

Current boundary: `Package.swift`, the Swift package sources under `Sources/` and `Tests/`, the XcodeGen spec `project.yml`,
the `NetworkCorePacketTunnel` extension target, the minimal entitlements under `Entitlements/` and the `PrivacyInfo.xcprivacy`
manifests under `Sources/*/Resources/` are enabled. The generated `.xcodeproj` is never committed.

These files and directories must stay absent until their own activation gates are complete:

- `*.swift` outside `apps/ios/Sources` and `apps/ios/Tests`
- `*.xcodeproj`
- `*.xcworkspace`
- `PrivacyInfo.xcprivacy` outside `apps/ios/Sources/*/Resources`
- `*.entitlements` outside `apps/ios/Entitlements`
- `ExportOptions.plist`
- `.ipa`, `.xcarchive`, `.xcresult` or dSYM bundles
- Provisioning Profile, certificate, private key, temporary keychain or App Store Connect API material

`swift build` and `swift test` run only in GitHub Actions on `macos-26`, never locally.

## CI Hook

GitHub Actions statically checks this README and runs the `macos-26` manifest validation hook,
`.github/scripts/verify-ios-package-manifest.sh`. Any Swift/Xcode source scan, Swift build, Swift test, Xcode project validation,
signing, archive/export or upload validation must run only in GitHub Actions on `macos-26` or Apple official platforms.

`ios-upload-workflow-status=enabled` (2026-10-22) unlocks only the manual internal TestFlight workflow,
`.github/workflows/ios-testflight.yml`. External TestFlight, App Store submission and release assets stay blocked.

## App icon

`Design/AppIcon.svg` is the source of the app icon. The asset catalog uses one
1024×1024 sRGB PNG without an alpha channel
(`Sources/NetworkCoreApp/Resources/Assets.xcassets/AppIcon.appiconset/AppIcon-1024.png`);
iOS applies the corner mask. Re-export the PNG at 1024×1024 and drop the alpha
channel whenever the SVG changes.
