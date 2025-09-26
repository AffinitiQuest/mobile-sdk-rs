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
        //.binaryTarget(name: "RustFramework", path: "MobileSdkRs/RustFramework.xcframework"),
        .binaryTarget(
           name: "RustFramework",
           url:
               "https://github.com/affinitiquest/mobile-sdk-rs/releases/download/1.0.9/RustFramework.xcframework.zip",
           checksum: "67733924b4de8d79fbe0ee1f16d718014e823f4177e13e1108158baadc40c0d8"),
        .target(
            name: "SpruceIDMobileSdkRs",
            dependencies: [
                .target(name: "RustFramework")
            ],
            path: "./MobileSdkRs/Sources/MobileSdkRs"
        ),
    ]
)
