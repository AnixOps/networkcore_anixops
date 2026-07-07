# iOS MITM Certificate Lifecycle Design

本文件定义 iOS MITM CA 证书从生成、安装提示、用户信任确认、fingerprint 校验、撤销/过期检测到
`CertificateTrustState` 映射的生命周期设计。它承接
[iOS Network Extension Design](ios-network-extension-design.md)、
[iOS Platform Adapter Source Contract](ios-platform-adapter-source-contract.md)、
[iOS Swift Network Extension Bridge Design](ios-swift-network-extension-bridge-design.md)、
[iOS Swift Xcode Bridge Source Contract](ios-swift-xcode-bridge-source-contract.md)、
[iOS Embedded Runtime FFI Boundary Design](ios-embedded-runtime-ffi-boundary-design.md)、
[iOS Entitlement Provisioning Source Contract](ios-entitlement-provisioning-source-contract.md)、
[iOS App Review Privacy Release Readiness Design](ios-app-review-privacy-release-readiness-design.md) 和
[iOS Platform Risk Assessment](ios-platform-risk-assessment.md)。

当前状态：design-only。仓库仍不包含 Swift source、`Package.swift`、Xcode project、Network Extension target、
configuration profile、CA 证书、私钥、Keychain item、entitlement、Provisioning Profile、签名配置、
TestFlight/App Store 上传 job 或 iOS release asset。本地仍不得运行 `swift build`、`swift test`、
`xcodebuild`、证书安装、签名、打包或发布验证。

## Goals

- 固定后续 iOS MITM CA 生成、存储、安装提示、用户信任确认、撤销和轮换的生命周期边界。
- 定义 `CertificateTrustState` mapping，确保 `NotInstalled`、`InstalledUntrusted`、`Trusted`、`Revoked`
  和 `Unknown` 都有保守且可审计的来源。
- 规定 fingerprint 校验、过期检测、revocation marker、私钥缺失和状态未知时如何映射到
  `IosMitmCertificateProbe`、`MitmCertificateStatus` 和稳定 `platform.ios.mitm_certificate.*` diagnostics。
- 保持 Apple SDK、profile payload、certificate DER/PEM、private key 和 trust database details 不进入
  `control-domain`、`control-runtime` 或 `platform-ios`。
- 定义 GitHub Actions `macos-26` 上的未来 Swift certificate lifecycle tests 和 Xcode validation 入口。

## Non-Goals

- 不新增 Swift、Xcode project、Network Extension target、UI、configuration profile 生成器或证书源码。
- 不生成、提交、安装、导出或信任真实 CA 证书。
- 不读取 iOS trust store、Keychain value、profile payload、证书私钥或用户流量内容。
- 不启用 iOS signing、TestFlight upload、App Store upload、release workflow artifact 或 iOS release asset。
- 不改变当前 `platform-ios` Rust 类型；本设计只约束后续源码进入条件。

## Lifecycle Position

iOS MITM certificate lifecycle 必须分层实现：

1. `control-domain` 只定义 `CertificateTrustState`、`MitmCertificateStatus`、诊断和 MITM gate 可消费状态。
2. `platform-ios` 只接收去敏 `IosMitmCertificateProbe`，并映射为 `MitmCertificateStatus`。
3. Swift bridge 后续负责读取 Apple SDK、Keychain、App Group、profile install result 和 trust probe fact。
4. Containing app 负责用户提示、证书安装引导、撤销入口和状态展示。
5. Network Extension 只消费已确认的 MITM certificate snapshot，不自行安装 profile 或修改 trust state。
6. `control-runtime` 继续通过 MITM gate 决定是否允许插件执行，不能绕过证书状态。

任何层都不得把 `SecCertificate`、`SecTrust`、profile payload、Keychain query、Keychain value、certificate DER/PEM、
private key、Bundle ID、Team ID、Provisioning Profile UUID、absolute path、subscription secret 或用户流量样本传入
Rust 领域层。

## Future Source Shape

后续源码可以采用以下形态。该布局是未来验收目标，不代表当前仓库已经存在这些文件：

```text
apps/ios/
  Sources/NetworkCoreBridge/
    MitmCertificateFacts.swift
    MitmCertificateLifecycleController.swift
    MitmCertificateTrustProbe.swift
    IosPlatformBridgeMapper.swift
  Sources/NetworkCoreApp/
    MitmCertificatePromptCoordinator.swift
  Sources/NetworkCorePacketTunnel/
    PacketTunnelProvider.swift
  Tests/NetworkCoreBridgeTests/
    MitmCertificateLifecycleTests.swift
```

如果未来需要生成 configuration profile、导出 `.cer` 或调用 Security.framework，必须先有 Swift/Xcode bridge
源码合同覆盖对应文件、secret redaction 和 GitHub Actions `macos-26` 验证。真实签名、entitlement、
Provisioning Profile、TestFlight 或 App Store Connect 凭据还必须遵守
[iOS Entitlement Provisioning Source Contract](ios-entitlement-provisioning-source-contract.md)，并且仍只能来自
GitHub Secrets、GitHub Environments 或 Apple 官方平台。

## Managed CA Metadata

NetworkCore 只能管理自己生成或导入并绑定的 CA。后续 Swift bridge 必须保存一份去敏 metadata，用于状态恢复和审计：

| 字段 | 用途 | Secret policy |
| --- | --- | --- |
| `ca_id` | 稳定证书记录 id，与 profile 和 prompt flow 关联 | 不得包含账号或设备唯一标识 |
| `subject` | UI 展示和 `MitmCertificateStatus.subject` | 可展示，不含用户隐私 |
| `serial_number` | 轮换与撤销判定 | 可保存 hash 或安全展示值 |
| `fingerprint_sha256` | fingerprint 校验和 `IosMitmCertificateProbe.fingerprint_sha256` | 可展示，不保存 DER/PEM |
| `public_key_sha256` | 区分同 subject 不同 key | 可展示或 hash |
| `not_before` / `not_after` | expiration 检测 | 可展示 |
| `created_at` / `last_checked_at` | 状态审计 | 可展示 |
| `revoked_at` | 本地撤销 marker | 可展示 |
| `trust_confirmation_version` | 用户提示文案和确认流程版本 | 可展示 |
| `keychain_private_key_ref_present` | 私钥引用是否仍存在 | 只保存 bool，不保存 Keychain reference |

私钥必须由 Keychain 或 Apple 允许的安全存储持有，且只能通过 access group 或系统授权路径供 containing app 和
Network Extension 使用。Rust snapshot 只能看到私钥是否可用的去敏事实；缺少私钥时不得返回 `Trusted`。

## CA Generation

CA generation 必须满足以下规则：

- 只能由用户显式触发，默认不生成 MITM CA。
- 每个 CA 必须有唯一 `ca_id`、可展示 subject、SHA-256 fingerprint 和有限有效期。
- 私钥不得写入 App Group 文件、日志、GitHub Actions artifact、profile payload 或 Rust snapshot。
- 生成失败必须返回稳定 diagnostic，不能重试到不受控存储或外部 helper。
- 后续如支持 CA rotation，必须先保留旧 CA revocation marker，再生成新 CA，不得静默覆盖。
- 生成后的 CA 仍只是 `InstalledUntrusted` 前置条件；没有用户安装和 trust confirmation 时不能返回 `Trusted`。

## Installation Prompt

安装提示必须由 containing app 发起，并且必须清楚表达：

- MITM 默认关闭，只有用户启用并选择范围后才会使用。
- 安装 CA 可能允许 NetworkCore 对用户选择范围内的 TLS 连接进行检查。
- 安装 profile 不等于 SSL/TLS 完全信任，用户还需要在系统设置中显式启用 full trust。
- 用户可以随时关闭 MITM、撤销 CA、删除 profile 或轮换证书。
- 对 certificate pinning、公钥固定、系统拒绝信任或用户未授权的连接，不提供绕过路径。

安装 flow 必须分成两个确认点：

1. 用户在 app 内选择生成或安装 NetworkCore CA。
2. 用户在系统设置或 Apple 允许的 profile flow 中完成安装和 full trust 操作。

App 侧的“我已完成”按钮不能单独证明信任成功；它只能触发 user trust confirmation probe。

## User Trust Confirmation

`Trusted` 只能在受支持路径同时满足时返回：

- 找到 NetworkCore 管理的 CA metadata。
- CA fingerprint 与 metadata 中的 `fingerprint_sha256` 完全一致。
- CA 未过期，且没有本地 `revoked_at` marker。
- 私钥引用仍可由后续 MITM leaf certificate signing path 使用。
- 用户已完成安装提示流程，并触发 trust confirmation。
- trust probe 使用默认系统信任评估成功，且未通过 custom anchor、debug override 或 test-only bypass 强行信任。

未来 Swift bridge 可以使用 Security.framework 做 `SecTrust` based trust probe，但必须遵守：

- 只能把最终结果映射为去敏 enum 和 stable diagnostics。
- 不把 `SecTrust`、`SecCertificate`、certificate chain、DER/PEM 或 trust database details 传入 Rust。
- 不通过自定义 anchor 覆盖默认系统 trust 结果来制造 `Trusted`。
- probe 失败、API 不可用、chain 不完整或结果无法解释时返回 `Unknown` 或 `InstalledUntrusted`。

## Fingerprint Validation

fingerprint 校验是所有状态转换的硬门禁：

- `fingerprint_sha256` 必须来自 NetworkCore 管理 CA 的 public certificate bytes。
- metadata、profile、trust probe chain 或可展示证书事实中的 fingerprint 不一致时，必须映射为
  `CertificateTrustState::Revoked`。
- fingerprint 缺失但其他事实显示证书可能存在时，必须映射为 `Unknown`。
- fingerprint 只允许作为 SHA-256 展示值进入 `IosMitmCertificateProbe` 和 `MitmCertificateStatus`。
- 不得把完整 certificate DER/PEM、profile payload 或私钥作为 fingerprint 证据传入 Rust。

fingerprint mismatch 必须输出 source 为 `platform.ios.mitm_certificate` 的 Error 诊断。当前稳定 code 复用
`platform.ios.mitm_certificate.revoked`；后续如需要更细分 code，必须先扩展 `platform-ios` source contract 和合同测试。

## Expiration And Revocation

expiration 和 revocation 都必须保守处理：

| 条件 | `CertificateTrustState` | diagnostic |
| --- | --- | --- |
| 未找到 NetworkCore CA metadata | `NotInstalled` | `platform.ios.mitm_certificate.not_installed` |
| metadata 存在但 profile/trust confirmation 未完成 | `InstalledUntrusted` | `platform.ios.mitm_certificate.installed_untrusted` |
| 默认系统 trust probe 成功且 fingerprint/有效期/私钥均通过 | `Trusted` | `platform.ios.mitm_certificate.trusted` |
| `revoked_at` 存在、fingerprint mismatch、CA 过期或被轮换废弃 | `Revoked` | `platform.ios.mitm_certificate.revoked` |
| trust probe 不可用、结果矛盾、Keychain fact 无法读取或状态无法可靠判断 | `Unknown` | `platform.ios.mitm_certificate.unknown` |

过期 CA 不得继续用于新 leaf certificate signing。撤销或过期后必须：

- 关闭 MITM available 状态。
- 保留 subject 和 fingerprint 展示值，方便用户识别需要删除的 profile。
- 记录 safe diagnostic 和 audit reason。
- 允许用户生成新 CA 或进入删除旧 profile 指引。
- 不自动修改系统 trust store，不自动删除用户 profile。

## CertificateTrustState Mapping

`CertificateTrustState mapping` 的来源必须可审计：

| Source facts | Mapping | MITM gate outcome |
| --- | --- | --- |
| 无 metadata、无 fingerprint、无安装记录 | `NotInstalled` | 拒绝 |
| metadata 存在，安装流程启动但 full trust 未确认 | `InstalledUntrusted` | 拒绝 |
| metadata、fingerprint、有效期、私钥和默认系统 trust probe 均通过 | `Trusted` | 允许后续 MITM gate 继续检查用户策略、插件权限和 remote script policy |
| revoked marker、过期、fingerprint mismatch、被轮换废弃或用户选择撤销 | `Revoked` | 拒绝 |
| Apple API 不可用、状态互相矛盾、无法读取 Keychain fact 或 probe 结果不可解释 | `Unknown` | 拒绝 |

`IosMitmCertificateProbe` 必须继续只保存 `state`、`subject`、`fingerprint_sha256` 和 `diagnostics`。
`MitmCertificateStatus` 不得包含 CA 私钥、profile payload、完整证书、系统 trust store 路径或 Apple SDK object。

## Diagnostics

后续 Swift bridge 和 `platform-ios` 必须复用稳定 source：

- `platform.ios.mitm_certificate`

当前稳定 code：

- `platform.ios.mitm_certificate.not_installed`
- `platform.ios.mitm_certificate.installed_untrusted`
- `platform.ios.mitm_certificate.trusted`
- `platform.ios.mitm_certificate.revoked`
- `platform.ios.mitm_certificate.unknown`

message 可以面向 UI 或日志，但不能包含私钥、profile payload、certificate DER/PEM、Keychain key、absolute path、
Bundle ID、Team ID、Provisioning Profile UUID、subscription URL、account token 或用户流量内容。

## GitHub Actions Validation Entry

当前本设计只通过 `.github/workflows/ci.yml` Repository policy 静态检查：

- 本文件存在，标题为 `iOS MITM Certificate Lifecycle Design`。
- 包含 `CA generation`、`installation prompt`、`user trust confirmation`、`fingerprint_sha256`、
  `CertificateTrustState mapping`、`NotInstalled`、`InstalledUntrusted`、`Trusted`、`Revoked`、`Unknown`、
  `IosMitmCertificateProbe`、`MitmCertificateStatus`、`SecTrust`、`expiration`、`revocation`、
  `platform.ios.mitm_certificate.not_installed`、`platform.ios.mitm_certificate.installed_untrusted`、
  `platform.ios.mitm_certificate.trusted`、`platform.ios.mitm_certificate.revoked`、
  `platform.ios.mitm_certificate.unknown`、`macos-26`、`swift test`、`xcodebuild` 和 no iOS release asset。
- 仓库仍不包含 Swift source、`Package.swift`、Xcode project、workspace、Network Extension target、
  configuration profile、CA certificate、private key、entitlement、Provisioning Profile、signing 配置、
  TestFlight/App Store upload job 或 iOS release asset。

后续出现 Swift 或 Xcode 源码后，验证只能在 GitHub Actions `macos-26` runner 中执行：

- `MitmCertificateLifecycleTests.swift` 覆盖 state matrix、fingerprint mismatch、expired CA、revoked marker、
  missing private key、unknown trust probe 和 safe diagnostic redaction。
- `swift test` 和 `swift build` 只在 GitHub Actions runner 执行。
- Xcode project 或 Network Extension target 使用 `xcodebuild`，只在 GitHub Actions `macos-26` runner 执行。
- CI 不得在 runner trust store 中安装真实 root CA，不得提交或上传 CA 私钥、profile payload 或 signing asset。

## Acceptance Criteria

本设计增量完成时必须满足：

- README、ROADMAP、TODO、CHANGELOG、CI/CD policy 和 release strategy 同步记录本文件。
- `.github/workflows/ci.yml` 检查本文件存在和关键锚点。
- 相关 iOS design/source contract 指向本 certificate lifecycle design。
- 不新增 Swift source、`Package.swift`、`.xcodeproj`、`.xcworkspace`、`.entitlements`、configuration profile、
  CA certificate、private key、Provisioning Profile、signing config、TestFlight/App Store upload job 或 iOS release asset。
- Linux artifact 继续等待 license/NOTICE confirmed marker；期间不得定义 `package-linux` 或发布 release asset。

## Release Boundary

本设计不允许发布 iOS artifact。iOS release workflow 在以下条件满足前不得定义 artifact、signing、
TestFlight upload 或 App Store upload job：

- 本设计和相关 iOS contracts 已通过 GitHub Actions static governance。
- iOS entitlement/provisioning source contract 已完成并通过 GitHub Actions static governance。
- iOS App Review/privacy release readiness design 已完成并通过 GitHub Actions static governance。
- Swift certificate lifecycle source、Swift bridge、Network Extension target、FFI boundary 和 embedded runtime
  已在 GitHub Actions `macos-26` runner 通过验证。
- Apple Developer、App ID、Network Extension entitlement、Provisioning Profile、GitHub Secrets、App Privacy disclosure、
  隐私政策、App Review Notes、TestFlight/App Store Connect 人工确认和目标地区 VPN compliance 已完成。
- MITM certificate lifecycle 的 CA generation、installation prompt、user trust confirmation、fingerprint validation、
  expiration/revocation handling 和 `CertificateTrustState` mapping 已有源码合同测试。

Linux artifact 发布继续受 license/NOTICE confirmed marker、`package-linux` preflight 和后续 artifact gates 阻断。

## References

- Apple Support: Trust manually installed certificate profiles in iOS, iPadOS, and visionOS,
  `https://support.apple.com/en-us/102390`
- Apple App Review Guidelines, `https://developer.apple.com/app-store/review/guidelines/`
- Apple Developer Documentation: Packet Tunnel Provider,
  `https://developer.apple.com/documentation/networkextension/packet-tunnel-provider`
- Apple Developer Documentation: `NETunnelProviderManager`,
  `https://developer.apple.com/documentation/networkextension/netunnelprovidermanager`
