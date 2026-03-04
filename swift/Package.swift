// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "EcliptixOPAQUE",
    platforms: [
        .iOS(.v15),
        .macOS(.v12)
    ],
    products: [
        .library(
            name: "EcliptixOPAQUE",
            targets: ["EcliptixOPAQUE"]
        )
    ],
    targets: [
        .target(
            name: "EcliptixOPAQUE",
            dependencies: ["EcliptixOPAQUEBinary"],
            path: "Sources/EcliptixOPAQUE"
        ),

        .binaryTarget(
            name: "EcliptixOPAQUEBinary",
            url: "https://github.com/oleksandrmelnychenko/ecliptix-opaque-rs/releases/download/v1.0.0/EcliptixOPAQUE.xcframework.zip",
            checksum: "fd4aad38057d2aa6406a8e59af7517402b49bb4ae96a0e1cb855a771001d056a"
        )
    ]
)
