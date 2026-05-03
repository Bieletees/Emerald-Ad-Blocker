// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "EmeraldTestBrowser",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "EmeraldTestBrowser",
            path: "Sources/EmeraldTestBrowser"
        )
    ]
)
