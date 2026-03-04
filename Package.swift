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
            name: "EcliptixOPAQUE",
            url: "https://github.com/oleksandrmelnychenko/ecliptix-opaque-rs/releases/download/v1.0.0/EcliptixOPAQUE.xcframework.zip",
            checksum: "e57a1309f664fade0bb6c5dc4f814c1f5437dbc28cd8665686cef2854d76e179"
        ),
        .target(
            name: "EcliptixOPAQUESwift",
            dependencies: ["EcliptixOPAQUE"],
            path: "swift/Sources/EcliptixOPAQUE"
        )
    ]
)
