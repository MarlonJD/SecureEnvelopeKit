// swift-tools-version: 5.9

import PackageDescription

// Thin compatibility manifest for public SwiftPM consumers.
//
// The canonical Swift package lives at `platforms/swift` (see
// `platforms/swift/Package.swift`), alongside the Android and .NET platform
// implementations in this monorepo. SwiftPM resolves git/local dependencies
// from the repository root, so this manifest re-exposes the same library by
// pointing its target at the relocated sources. It must stay a thin entry
// point: the source of truth is `platforms/swift`.
//
// Run tests from the canonical package:
//
//     cd platforms/swift && swift test
let package = Package(
    name: "SecureEnvelopeKit",
    platforms: [
        .iOS(.v15),
        .macOS(.v12)
    ],
    products: [
        .library(
            name: "SecureEnvelopeKit",
            targets: ["SecureEnvelopeKit"]
        )
    ],
    targets: [
        .target(
            name: "SecureEnvelopeKit",
            path: "platforms/swift/Sources/SecureEnvelopeKit",
            linkerSettings: [
                .linkedFramework("Security")
            ]
        )
    ]
)
