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
            checksum: "5860bd4d7495d7a0e55ea6a849c5b4cd9f279ed280388046784758075c110cc9"
        )
    ]
)
