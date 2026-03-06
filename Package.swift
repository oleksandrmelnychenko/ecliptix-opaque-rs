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
            url: "https://github.com/oleksandrmelnychenko/ecliptix-opaque-rs/releases/download/v1.0.1/EcliptixOPAQUE.xcframework.zip",
            checksum: "9e92ea23055168caa46e9b322c568a574604b835bfb9193c3fedbfd8819327ab"
        ),
        .target(
            name: "EcliptixOPAQUESwift",
            dependencies: ["EcliptixOPAQUEBinary"],
            path: "swift/Sources/EcliptixOPAQUE"
        )
    ]
)
