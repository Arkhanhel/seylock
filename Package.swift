// swift-tools-version:5.9
// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//
// Swift package for SeyLock. The Rust library ships as a binary
// XCFramework (iOS devices, iOS simulator on Apple silicon, macOS), attached
// to each GitHub release; tools/build_xcframework.sh builds it and prints the
// checksum below. When bindings/swift/SeyLockFFI.xcframework exists locally
// (after running that script and copying the result there), it is used
// instead, which is how the package is developed and tested.
import PackageDescription
import Foundation

let releaseURL = "https://github.com/Arkhanhel/seylock/releases/download/v0.2.0/SeyLockFFI.xcframework.zip"
let releaseChecksum = "61edea4c6867254503722ef4fa7a0cab72519bcf2755ac5712c8400084562dea"

let localFramework = "bindings/swift/SeyLockFFI.xcframework"
let packageDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let useLocal = FileManager.default.fileExists(
    atPath: packageDir.appendingPathComponent(localFramework).path)

let ffi: Target = useLocal
    ? .binaryTarget(name: "SeyLockFFI", path: localFramework)
    : .binaryTarget(name: "SeyLockFFI", url: releaseURL, checksum: releaseChecksum)

let package = Package(
    name: "SeyLock",
    platforms: [.iOS(.v13), .macOS(.v11)],
    products: [
        .library(name: "SeyLock", targets: ["SeyLock"]),
    ],
    targets: [
        ffi,
        .target(
            name: "SeyLock",
            dependencies: ["SeyLockFFI"],
            path: "bindings/swift/Sources/SeyLock",
            linkerSettings: [.linkedLibrary("iconv")]
        ),
        .testTarget(
            name: "SeyLockTests",
            dependencies: ["SeyLock"],
            path: "bindings/swift/Tests/SeyLockTests"
        ),
    ]
)
