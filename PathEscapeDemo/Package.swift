// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "PathEscapeDemo",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "PathEscapeDemo", targets: ["PathEscapeDemo"]),
    ],
    targets: [
        .target(name: "PathEscapeDemo"),
        .testTarget(name: "PathEscapeDemoTests", dependencies: ["PathEscapeDemo"]),
    ]
)
