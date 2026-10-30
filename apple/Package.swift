// swift-tools-version: 6.0
// The menu bar app. Run apple/build-bindings.sh first; apple/package.sh
// assembles the .app and the .pkg.
import PackageDescription

let package = Package(
    name: "Omnitun",
    platforms: [.macOS(.v14)],
    dependencies: [
        // Updates from the GitHub Releases (appcast.xml, EdDSA-signed .pkg).
        .package(url: "https://github.com/sparkle-project/Sparkle", exact: "2.10.0"),
    ],
    targets: [
        .binaryTarget(name: "VPNClientCoreFFI", path: "Generated/VPNClientCoreFFI.xcframework"),
        .target(
            name: "VPNClientCore",
            dependencies: ["VPNClientCoreFFI"],
            path: "Generated/Swift",
            swiftSettings: [.swiftLanguageMode(.v5)],
            linkerSettings: [.linkedFramework("Security"), .linkedFramework("SystemConfiguration")]
        ),
        .executableTarget(
            name: "Omnitun",
            dependencies: ["VPNClientCore", .product(name: "Sparkle", package: "Sparkle")],
            path: "Omnitun",
            swiftSettings: [.swiftLanguageMode(.v5)],
            // Sparkle.framework is copied into Contents/Frameworks.
            linkerSettings: [.unsafeFlags(["-Xlinker", "-rpath", "-Xlinker", "@executable_path/../Frameworks"])]
        ),
        .executableTarget(name: "Smoke", dependencies: ["VPNClientCore"], path: "Smoke"),
        .testTarget(name: "OmnitunTests", dependencies: ["Omnitun"], path: "Tests", swiftSettings: [.swiftLanguageMode(.v5)]),
    ]
)
