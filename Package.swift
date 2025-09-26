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
               "https://github.com/affinitiquest/mobile-sdk-rs/releases/download/1.0.10/RustFramework.xcframework.zip",
           checksum: "63b0203d647ee110f0c2ac7935e6530d0745fa924e86e5e56fff3e156d0cf897"),
        .target(
            name: "SpruceIDMobileSdkRs",
            dependencies: [
                .target(name: "RustFramework")
            ],
            path: "./MobileSdkRs/Sources/MobileSdkRs"
        ),
    ]
)
