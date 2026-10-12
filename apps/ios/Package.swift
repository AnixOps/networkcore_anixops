// swift-tools-version:5.10
//
// Manifest-only activation of the iOS Swift package.
// Contract: docs/architecture/ios-package-swift-manifest-only-activation-validation-contract.md
//
// NetworkCorePacketTunnel is reserved for the Network Extension gate and is intentionally not declared here.
// Swift sources are enabled by the later Swift source gate, under Sources/ and Tests/ only.
import PackageDescription

let package = Package(
    name: "NetworkCoreIOS",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        // NetworkCoreApp is compiled directly by the XcodeGen app target, so it is not a product.
        .library(name: "NetworkCoreIOS", targets: ["NetworkCoreBridge"]),
    ],
    targets: [
        .target(
            name: "NetworkCoreBridge",
            path: "Sources/NetworkCoreBridge"
        ),
        .target(
            name: "NetworkCoreApp",
            dependencies: ["NetworkCoreBridge"],
            path: "Sources/NetworkCoreApp"
        ),
        .testTarget(
            name: "NetworkCoreBridgeTests",
            dependencies: ["NetworkCoreBridge", "NetworkCoreApp"],
            path: "Tests/NetworkCoreBridgeTests"
        ),
    ]
)
