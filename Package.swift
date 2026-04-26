// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "VouchflowSDK",
    platforms: [
        .iOS(.v15),
    ],
    products: [
        .library(
            name: "VouchflowSDK",
            type: .dynamic,
            targets: ["VouchflowSDK"]
        ),
    ],
    targets: [
        .target(
            name: "VouchflowSDK",
            path: "Sources/VouchflowSDK"
        ),
        .testTarget(
            name: "VouchflowSDKTests",
            dependencies: ["VouchflowSDK"],
            path: "Tests/VouchflowSDKTests"
        ),
    ]
)
