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
               "https://github.com/affinitiquest/mobile-sdk-rs/releases/download/1.0.14/RustFramework.xcframework.zip",
           checksum: "9b5d0febd0c2491cdf0fff1288ade1abf101e6d8d1474485f2ee5774d9fff41f"),
        .target(
            name: "SpruceIDMobileSdkRs",
            dependencies: [
                .target(name: "RustFramework")
            ],
            path: "./MobileSdkRs/Sources/MobileSdkRs"
        ),
    ]
)
