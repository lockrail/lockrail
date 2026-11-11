// swift-tools-version: 6.0
// The Lockrail menu-bar app: a thin native shell over the Rust `lockrail` binary
// (research/lockrail-2026-11-08/fleet/INSTALL-DECISION.md, D1). Built and bundled by
// scripts/build-macos-app.sh.
import PackageDescription

let package = Package(
    name: "Lockrail",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(name: "Lockrail", path: "Sources/Lockrail")
    ]
)
