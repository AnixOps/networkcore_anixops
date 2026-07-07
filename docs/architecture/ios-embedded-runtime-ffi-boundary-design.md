# iOS Embedded Runtime FFI Boundary Design

本文件定义后续 iOS Network Extension 内嵌 Rust runtime 的 FFI boundary。它承接
[iOS Network Extension Design](ios-network-extension-design.md)、
[iOS Platform Adapter Source Contract](ios-platform-adapter-source-contract.md)、
[iOS Swift Network Extension Bridge Design](ios-swift-network-extension-bridge-design.md)、
[iOS Swift Xcode Bridge Source Contract](ios-swift-xcode-bridge-source-contract.md)、
[iOS MITM Certificate Lifecycle Design](ios-mitm-certificate-lifecycle-design.md)、
[iOS Entitlement Provisioning Source Contract](ios-entitlement-provisioning-source-contract.md)、
[iOS App Review Privacy Release Readiness Design](ios-app-review-privacy-release-readiness-design.md)、
[iOS Privacy Manifest Source Contract](ios-privacy-manifest-source-contract.md) 和
[iOS App Review Manual Confirmation Source Contract](ios-app-review-manual-confirmation-source-contract.md) 以及
[iOS Platform Risk Assessment](ios-platform-risk-assessment.md)。

当前状态：design-only。仓库仍不包含 iOS runtime FFI crate、C header、generated bindings、Swift source、
`Package.swift`、Xcode project、Network Extension target、staticlib、XCFramework、entitlement、
Provisioning Profile、签名配置、TestFlight/App Store 上传 job 或 iOS release asset。本地仍不得运行
`cargo build`、`swift build`、`swift test`、`xcodebuild`、签名、打包或发布验证。

## Goals

- 固定后续 Rust staticlib、XCFramework、C ABI symbol、owned string/buffer 和 opaque handle 边界。
- 定义 Swift bridge 与 Rust embedded runtime 的 ABI version negotiation、schema version negotiation 和错误映射。
- 约束 FFI 只能传递去敏配置、诊断、状态和 buffer，不跨越 Apple SDK object、Keychain value、证书私钥或用户流量样本。
- 规定 Rust panic、Swift error、OSStatus、resource exhaustion 和 lifecycle failure 如何映射到
  `IosEmbeddedRuntimeProbe`、`IosEmbeddedRuntimeState` 和稳定 `platform.ios.embedded_runtime.*` diagnostics。
- 定义 GitHub Actions `macos-26` 上的未来 `cargo build`、`swift build`、`swift test`、`xcodebuild` 验证入口。

## Non-Goals

- 不新增 Rust FFI crate、C header、Swift source、generated bindings、`Package.swift`、Xcode project 或 target。
- 不生成 staticlib、XCFramework、`.a`、`.framework`、`.xcframework`、archive、TestFlight upload 或 iOS release asset。
- 不实现 packet processing、tun/device IO、proxy runtime、DNS runtime、MITM data plane 或 plugin execution。
- 不申请或配置 Apple Developer Program、Network Extension entitlement、Provisioning Profile、signing certificate、
  App Store Connect、GitHub Secrets 或 App Review workflow。

## Boundary Position

后续 runtime embedding 必须保持以下层次：

1. `control-domain` 定义领域类型、诊断、能力状态和证书状态。
2. `control-runtime` 编排配置、平台能力、MITM gate 和代理内核端口，不依赖 Apple SDK 或 Swift。
3. future iOS runtime FFI crate 只暴露 C ABI facade，内部复用可移植 Rust runtime 组件。
4. `platform-ios` 只接收 sanitized `IosPlatformSnapshot`，表达 runtime 可用性和拒绝原因。
5. Swift bridge 的 `NetworkCoreRuntimeFFI.swift` 只负责 C ABI 调用、buffer ownership、error mapping 和 lifecycle handoff。
6. `NetworkCorePacketTunnel` 的 `PacketTunnelProvider.swift` 只在 Extension 进程内调用 Swift bridge，不启动外部进程。

FFI boundary 不得跨越 `NEPacketTunnelProvider`、`NETunnelProviderManager`、`SecTrust`、`SecCertificate`、
Keychain item reference、App Group file URL、Swift object reference、file descriptor、socket、private key、
certificate payload、Provisioning Profile、Team ID、Bundle ID、subscription secret 或用户流量内容。

## Future Source Shape

后续源码可以采用以下形态。该布局是未来验收目标，不代表当前仓库已经存在这些文件：

```text
crates/ios-runtime-ffi/
  Cargo.toml
  build.rs
  include/networkcore_ios_runtime.h
  src/lib.rs
  tests/ios_runtime_ffi_contracts.rs

apps/ios/
  Sources/NetworkCoreBridge/
    NetworkCoreRuntimeFFI.swift
    NetworkCoreRuntimeBuffers.swift
    NetworkCoreRuntimeErrors.swift
  Sources/NetworkCorePacketTunnel/
    PacketTunnelProvider.swift
```

Rust crate 的 `crate-type` 只能在对应 source contract 完成后声明为 `staticlib` 或 Apple 允许的等价嵌入形态。
XCFramework 只能由 GitHub Actions `macos-26` runner 从同一 commit 的受控 build output 组装，不能提交到仓库。

## C ABI Surface

未来最小 C ABI 必须是 stable、versioned、panic-safe 的函数集合。建议 symbol：

| symbol | 方向 | 责任 |
| --- | --- | --- |
| `networkcore_ios_abi_version` | Swift -> Rust | 返回当前 C ABI version |
| `networkcore_ios_schema_version` | Swift -> Rust | 返回 runtime config schema version |
| `networkcore_ios_runtime_init` | Swift -> Rust | 创建 opaque runtime handle |
| `networkcore_ios_runtime_start_tunnel` | Swift -> Rust | 在 Extension 进程内启动 runtime |
| `networkcore_ios_runtime_stop_tunnel` | Swift -> Rust | 幂等停止并释放 runtime resources |
| `networkcore_ios_runtime_collect_status` | Swift -> Rust | 返回去敏 status/diagnostic buffer |
| `networkcore_ios_runtime_free_buffer` | Swift -> Rust | 释放 Rust-owned output buffer |
| `networkcore_ios_runtime_free_handle` | Swift -> Rust | 释放 opaque runtime handle |

所有 exported symbol 必须使用明确前缀 `networkcore_ios_`，避免和 Apple SDK、系统库或第三方内核冲突。所有 ABI
struct 必须采用 C-compatible layout，字段必须固定大小、对齐和 ownership；Swift-only object layout 不得作为 ABI。

## ABI Version Negotiation

Swift bridge 在调用 `networkcore_ios_runtime_init` 前必须完成 version negotiation：

1. 读取 `networkcore_ios_abi_version`。
2. 读取 `networkcore_ios_schema_version`。
3. 比对 Swift bridge 编译时声明的 minimum/current ABI version 和 DTO schema version。
4. ABI 不兼容时不得继续初始化 runtime，必须映射为 `IosEmbeddedRuntimeState::AbiMismatch`。
5. Schema 不兼容时不得尝试 best-effort 解析，必须输出 `platform.ios.embedded_runtime.abi_mismatch`。

ABI version mismatch、missing symbol、header/generated binding version mismatch 和 XCFramework slice mismatch 都属于
`platform.ios.embedded_runtime.abi_mismatch`。Artifact 缺失、link target 缺失或 symbol lookup 失败前置不可恢复时，
映射为 `platform.ios.embedded_runtime.missing`。

## Buffer Ownership

FFI 只能使用明确 ownership 的 string/buffer 模型：

- Swift 输入 buffer 由 Swift 拥有，Rust 只能在调用期间读取，不得保存 pointer。
- Rust 输出 buffer 由 Rust 分配，Swift 必须调用 `networkcore_ios_runtime_free_buffer` 释放。
- Opaque runtime handle 由 Rust 创建，Swift 必须调用 `networkcore_ios_runtime_free_handle` 释放。
- 字符串必须使用 UTF-8 bytes 加长度，不依赖 NUL terminator。
- 空 buffer、null pointer、长度溢出、非 UTF-8、schema 不匹配必须返回结构化 error，不得 panic。

返回给 Swift 的 output buffer 只能包含去敏 JSON、CBOR 或后续设计指定的稳定二进制 envelope。Envelope 不得包含
Keychain value、private key、certificate DER/PEM、完整 subscription URL、用户账号 token、Bundle ID、Team ID、
Provisioning Profile UUID、absolute path 或用户流量内容。

## Runtime Config Envelope

`networkcore_ios_runtime_init` 和 `networkcore_ios_runtime_start_tunnel` 的输入必须来自已验证的 tunnel profile：

- `profile_id`：可展示、可审计的配置 id，不包含账号 secret。
- `schema_version`：配置 envelope schema。
- `content_hash`：用于回滚和 last-known-good 校验。
- `listener_mode`：iOS Extension 内允许的 packet/tunnel mode。
- `node_refs`：只允许引用已由 Keychain/App Group 解析并授权的节点引用，不传 secret value。
- `mitm_policy`：用户显式 MITM 开关和证书状态摘要。
- `diagnostic_context`：不含 secret 的 safe correlation id。

输入 envelope 必须由 Swift bridge 在调用前完成 schema、profile id、content hash 和 required field 校验。Rust 仍必须重复校验，
并在失败时返回 stable error code；任何失败都不能让 Extension fallback 到 daemon、CLI、helper process 或外部代理二进制。

## Error Mapping

未来 FFI error enum 必须可稳定映射到 iOS platform diagnostics：

| FFI error | `platform-ios` state | diagnostic |
| --- | --- | --- |
| `ok` | `IosEmbeddedRuntimeState::Available` | `platform.ios.embedded_runtime.available` |
| `artifact_missing` | `IosEmbeddedRuntimeState::Missing` | `platform.ios.embedded_runtime.missing` |
| `missing_symbol` | `IosEmbeddedRuntimeState::AbiMismatch` | `platform.ios.embedded_runtime.abi_mismatch` |
| `abi_mismatch` | `IosEmbeddedRuntimeState::AbiMismatch` | `platform.ios.embedded_runtime.abi_mismatch` |
| `schema_mismatch` | `IosEmbeddedRuntimeState::AbiMismatch` | `platform.ios.embedded_runtime.abi_mismatch` |
| `invalid_argument` | `IosEmbeddedRuntimeState::InitializationFailed` | `platform.ios.embedded_runtime.initialization_failed` |
| `config_rejected` | `IosEmbeddedRuntimeState::InitializationFailed` | `platform.ios.embedded_runtime.initialization_failed` |
| `resource_exhausted` | `IosEmbeddedRuntimeState::InitializationFailed` | `platform.ios.embedded_runtime.initialization_failed` |
| `panic_caught` | `IosEmbeddedRuntimeState::InitializationFailed` | `platform.ios.embedded_runtime.initialization_failed` |
| `internal_error` | `IosEmbeddedRuntimeState::InitializationFailed` | `platform.ios.embedded_runtime.initialization_failed` |

FFI error message 可以面向 UI 或 debug，但只能包含 safe message、stable code、source 和 retry hint。不得包含 secret、
absolute path、Apple account identity、Keychain key、raw config payload、certificate payload 或 traffic sample。

## Panic And Unwind Boundary

Rust panic 不能跨 C ABI unwinding。未来 FFI facade 必须：

- 在所有 exported symbol 边界 catch panic。
- 将 panic 映射为 `panic_caught` 和 `platform.ios.embedded_runtime.initialization_failed`。
- 清理已分配但未交给 Swift ownership 的 buffer 和 runtime resource。
- 不把 panic message 原样返回给 Swift；只返回 safe diagnostic。
- 不在 panic 后继续复用状态未知的 runtime handle。

Swift `throw`、Objective-C exception、OSStatus failure 和 Network Extension lifecycle callback error 必须先在 Swift bridge
转成 FFI-safe error envelope，再进入 `platform-ios` snapshot；不能让 exception 穿透到 Rust。

## Lifecycle Contract

Extension 内 runtime lifecycle 必须显式可重入：

1. `PacketTunnelProvider.startTunnel` 采集 Apple facts 和 active profile。
2. Swift bridge 完成 ABI/schema negotiation。
3. Swift bridge 调用 `networkcore_ios_runtime_init` 创建 opaque handle。
4. Swift bridge 调用 `networkcore_ios_runtime_start_tunnel` 启动 runtime。
5. Runtime start 成功后，`IosEmbeddedRuntimeProbe` 映射为 available。
6. `stopTunnel`、系统回收或 start 失败必须调用 stop/free，并记录 safe diagnostics。
7. 重复 stop/free 必须幂等，不能 double free、panic 或泄露 resource。

Runtime 可用性只表示 Extension 进程内 embedded runtime 可加载且 ABI/schema 兼容，不代表 Network Extension entitlement、
VPN authorization、MITM certificate 或 remote script policy 已通过；MITM certificate lifecycle 必须遵守
[iOS MITM Certificate Lifecycle Design](ios-mitm-certificate-lifecycle-design.md)，entitlement/provisioning 边界必须遵守
[iOS Entitlement Provisioning Source Contract](ios-entitlement-provisioning-source-contract.md)，这些状态仍由 `IosPlatformSnapshot`
和 `control-runtime` gate 独立判断。

## GitHub Actions Validation Entry

当前本设计只通过 `.github/workflows/ci.yml` Repository policy 静态检查：

- 本文件存在，标题为 `iOS Embedded Runtime FFI Boundary Design`。
- 包含 `staticlib`、`XCFramework`、`C ABI`、`networkcore_ios_abi_version`、
  `networkcore_ios_runtime_init`、`networkcore_ios_runtime_start_tunnel`、
  `networkcore_ios_runtime_stop_tunnel`、`networkcore_ios_runtime_free_buffer`、
  `ABI version negotiation`、`owned string`、`owned buffer`、`panic boundary`、`error mapping`、
  `IosEmbeddedRuntimeProbe`、`IosEmbeddedRuntimeState`、
  `platform.ios.embedded_runtime.abi_mismatch`、`platform.ios.embedded_runtime.initialization_failed`,
  `NetworkCoreRuntimeFFI.swift`、`macos-26`、`cargo build`、`swift build`、`swift test`、`xcodebuild`
  和 no iOS release asset。
- 仓库仍不包含 iOS runtime FFI crate、C header、Swift source、`Package.swift`、Xcode project、workspace、
  entitlement、Provisioning Profile、signing 配置、TestFlight/App Store upload job 或 iOS release asset。

后续出现 FFI crate、Swift bridge 或 Xcode project 后，验证只能在 GitHub Actions 中运行：

- Rust iOS staticlib build 使用 `cargo build`，只在 GitHub Actions `macos-26` runner 执行。
- Swift bridge 使用 `swift build` 和 `swift test`，只在 GitHub Actions runner 执行。
- Xcode project 或 Network Extension target 使用 `xcodebuild`，只在 GitHub Actions `macos-26` runner 执行。
- XCFramework packaging、signing、TestFlight 或 App Store Connect upload 必须先有独立 release/signing workflow design
  和 manual-intervention 记录。

## Acceptance Criteria

本设计增量完成时必须满足：

- README、ROADMAP、TODO、CHANGELOG、CI/CD policy 和 release strategy 同步记录本文件。
- `.github/workflows/ci.yml` 检查本文件存在和关键锚点。
- 相关 iOS design/source contract 指向本 FFI boundary。
- 不新增 Rust FFI crate、C header、Swift source、`Package.swift`、`.xcodeproj`、`.xcworkspace`、`.entitlements`、
  Provisioning Profile、signing config、TestFlight/App Store upload job 或 iOS release asset。
- Linux artifact 继续等待 license/NOTICE confirmed marker；期间不得定义 `package-linux` 或发布 release asset。

## Release Boundary

本设计不允许发布 iOS artifact。iOS release workflow 在以下条件满足前不得定义 artifact、signing、
TestFlight upload 或 App Store upload job：

- 本设计和相关 iOS contracts 已通过 GitHub Actions static governance。
- iOS entitlement/provisioning source contract 已完成并通过 GitHub Actions static governance。
- iOS App Review/privacy release readiness design 已完成并通过 GitHub Actions static governance。
- iOS Privacy Manifest source contract 已完成并通过 GitHub Actions static governance。
- iOS App Review manual confirmation source contract 已完成并通过 GitHub Actions static governance。
- Rust staticlib、XCFramework、Swift bridge、Network Extension target 和 FFI contract tests 已在 GitHub Actions
  `macos-26` runner 通过验证。
- Apple Developer、App ID、Network Extension entitlement、Provisioning Profile、GitHub Secrets、App Privacy disclosure、
  隐私政策、App Review Notes、demo account、review attachment、TestFlight/App Store Connect 人工确认 marker、
  export compliance、beta app review 和目标地区 VPN compliance 已完成。
- MITM certificate lifecycle design 已完成；对应 CA generation、installation prompt、trust confirmation、
  fingerprint validation、expiration/revocation handling 和 source contract tests 已通过 GitHub Actions。

Linux artifact 发布继续受 license/NOTICE confirmed marker、`package-linux` preflight 和后续 artifact gates 阻断。

## References

- Apple Developer Documentation: Network Extension, `https://developer.apple.com/documentation/networkextension`
- Apple Developer Documentation: Packet Tunnel Provider, `https://developer.apple.com/documentation/networkextension/packet-tunnel-provider`
- Apple Developer Documentation: `NEPacketTunnelProvider`, `https://developer.apple.com/documentation/networkextension/nepackettunnelprovider`
- Apple Developer Documentation: `NETunnelProviderManager`, `https://developer.apple.com/documentation/networkextension/netunnelprovidermanager`
- Rust Reference: FFI, `https://doc.rust-lang.org/reference/items/external-blocks.html`
- Rust Nomicon: FFI, `https://doc.rust-lang.org/nomicon/ffi.html`
