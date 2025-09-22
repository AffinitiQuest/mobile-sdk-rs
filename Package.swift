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
                "https://github.com/affinitiquest/mobile-sdk-rs/releases/download/1.0.6/RustFramework.xcframework.zip",
            checksum: "ed73dd076ad615ea269018690273717c3bdc877225d425ed06a4a6501261e981"),
        // .binaryTarget(name: "RustFramework", path: "MobileSdkRs/RustFramework.xcframework"),
        .target(
            name: "SpruceIDMobileSdkRs",
            dependencies: [
                .target(name: "RustFramework")
            ],
            path: "./MobileSdkRs/Sources/MobileSdkRs"
        ),
    ]
)
