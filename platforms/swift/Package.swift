// swift-tools-version: 5.9

import PackageDescription

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
            linkerSettings: [
                .linkedFramework("Security")
            ]
        ),
        .testTarget(
            name: "SecureEnvelopeKitTests",
            dependencies: ["SecureEnvelopeKit"]
        )
    ]
)
