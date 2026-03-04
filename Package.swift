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
            checksum: "cea76b210fc2757f56e00e846cb60eb5e183c0ba270f9fa0bb538adda0d6a746"
        ),
        .target(
            name: "EcliptixOPAQUESwift",
            dependencies: ["EcliptixOPAQUE"],
            path: "swift/Sources/EcliptixOPAQUE"
        )
    ]
)
