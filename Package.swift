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
            targets: ["EcliptixOPAQUESwift"]
        )
    ],
    targets: [
        .binaryTarget(
            name: "EcliptixOPAQUEBinary",
            url: "https://github.com/oleksandrmelnychenko/ecliptix-opaque-rs/releases/download/v1.0.0/EcliptixOPAQUE.xcframework.zip",
            checksum: "f2799110c1d800092325486160cf26752521ce15e09ea40020e83cc1b4951c47"
        ),
        .target(
            name: "EcliptixOPAQUESwift",
            dependencies: ["EcliptixOPAQUEBinary"],
            path: "swift/Sources/EcliptixOPAQUE"
        )
    ]
)
