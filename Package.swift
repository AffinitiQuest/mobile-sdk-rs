// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.
// Swift Package: SpruceIDMobileSdkRs

import PackageDescription

let package = Package(
    name: "SpruceIDMobileSdkRs",
    platforms: [
        .iOS(.v14),
        .macOS(.v10_15),
    ],
    products: [
        .library(
            name: "SpruceIDMobileSdkRs",
            targets: ["SpruceIDMobileSdkRs"]
        )
    ],
    dependencies: [],
    targets: [
       .binaryTarget(
            name: "RustFramework",
            url:
                "https://github.com/affinitiquest/mobile-sdk-rs/releases/download/1.0.5/RustFramework.xcframework.zip",
            checksum: "6b8527e74975430f9870f6051046df8e53cc99978ff0cdc44b19f20a9d7b3ad7"),
        .target(
            name: "SpruceIDMobileSdkRs",
            dependencies: [
                .target(name: "RustFramework")
            ],
            path: "./MobileSdkRs/Sources/MobileSdkRs"
        ),
    ]
)
