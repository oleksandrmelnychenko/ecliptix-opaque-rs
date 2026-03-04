// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "EcliptixOPAQUE",
    platforms: [
        .iOS(.v18),
        .macOS(.v15)
    ],
    products: [
        .library(
            name: "EcliptixOPAQUE",
            targets: ["EcliptixOPAQUE"]
        )
    ],
    targets: [
        .binaryTarget(
            name: "EcliptixOPAQUEBinary",
            url: "https://github.com/oleksandrmelnychenko/ecliptix-opaque-rs/releases/download/v1.0.0/EcliptixOPAQUE.xcframework.zip",
            checksum: "e45027308e30217e4c9bbe1c8282aace1ddf2a89e7936efc781c517c29ba97cb"
        ),
        .target(
            name: "EcliptixOPAQUE",
            dependencies: ["EcliptixOPAQUEBinary"],
            path: "swift/Sources/EcliptixOPAQUE"
        )
    ]
)
