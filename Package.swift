// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "EcliptixOPAQUE",
    platforms: [
        .iOS(.v17),
        .macOS(.v14)
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
            checksum: "c742e7035868312d16c86b19e2a37ed8fa5eb01ef7d79ac5df20b2d3f0da791e"
        ),
        .target(
            name: "EcliptixOPAQUE",
            dependencies: ["EcliptixOPAQUEBinary"],
            path: "swift/Sources/EcliptixOPAQUE"
        )
    ]
)
