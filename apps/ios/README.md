# iOS Source Tree Governance Placeholder

Current status: `readme-placeholder-no-swift-source`.

This directory is reserved for the future iOS application and Network Extension source tree. The current repository state only
allows this README as a governance placeholder. It does not enable Swift, Xcode, signing, archive/export or upload work.

## Ownership

- Future iOS Swift package ownership starts at `apps/ios`.
- Future `Package.swift` may only live at `apps/ios/Package.swift`.
- Future Swift sources may only live under `apps/ios/Sources` or `apps/ios/Tests`.
- Future Xcode project or workspace files must reference this source tree and must not become the only source of truth.
- `NetworkCorePacketTunnel` remains the only approved Network Extension target name.
- Source directory guard: only `apps/ios/README.md` is present before Swift/Xcode activation.

## Current Boundary

Current boundary: no Package.swift, no Swift source, no Xcode project.

These files and directories must stay absent until their own activation gates are complete:

- `Package.swift`
- `Sources/`
- `Tests/`
- `*.swift`
- `*.xcodeproj`
- `*.xcworkspace`
- `PrivacyInfo.xcprivacy`
- `*.entitlements`
- `ExportOptions.plist`
- `.ipa`, `.xcarchive`, `.xcresult` or dSYM bundles
- Provisioning Profile, certificate, private key, temporary keychain or App Store Connect API material

## CI Hook

GitHub Actions may statically check this README from `ubuntu-latest` as repository governance. Any future Swift/Xcode source scan,
Swift build, Swift test, Xcode project validation, signing, archive/export or upload validation must run only in GitHub Actions on
`macos-26` or Apple official platforms.

This is the macos-26 source scan hook placeholder.

The upload workflow enabled marker remains blocked. `ios-upload-workflow-status` must stay `pending` until source tree,
manual confirmation, protected environment and secret setup gates are complete.
