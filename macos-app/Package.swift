// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "GitlawbNode",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "GitlawbNode",
            path: "Sources/GitlawbNode",
            exclude: ["Info.plist"],
            resources: [
                .copy("Resources/docker-compose.yml"),
                .copy("Resources/MenuBarIcon.png"),
                .copy("Resources/MenuBarIcon@2x.png"),
                .copy("Resources/AppIcon.icns"),
            ]
        ),
    ]
)
