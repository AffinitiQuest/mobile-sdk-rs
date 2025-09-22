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
               "https://github.com/affinitiquest/mobile-sdk-rs/releases/download/1.0.6/RustFramework.xcframework.zip",
           checksum: "3fce83010745aaae2388fa9d81816aefad60a0ba974c308d9d78703006db98d9"),
        .target(
            name: "SpruceIDMobileSdkRs",
            dependencies: [
                .target(name: "RustFramework")
            ],
            path: "./MobileSdkRs/Sources/MobileSdkRs"
        ),
    ]
)
