// swift-tools-version:5.9
// SPDX-License-Identifier: Apache-2.0
//
// QoreSign for Swift: hybrid secp256k1 + ML-DSA-87 (FIPS 204) signing,
// verification and Sign In With QoreChain, over the Rust core in
// crates/qoresign through UniFFI.
//
// The native code ships as the binary target QoreSignFFI:
// - Release builds download the xcframework zip attached to the GitHub
//   release. `releaseChecksum` is a placeholder until a release:
//   `scripts/build-xcframework.sh --write-checksum` builds the zip and writes
//   its checksum here; that commit is what gets tagged (see swift/README.md).
// - Local development uses swift/QoreSignFFI.xcframework, built by
//   scripts/build-xcframework.sh. It is selected when the QORESIGN_LOCAL_FFI
//   environment variable is set, or when that directory exists (it is
//   git-ignored, so it never exists in a checkout fetched by SwiftPM).

import Foundation
import PackageDescription

let releaseVersion = "0.1.0"
let releaseChecksum = "0000000000000000000000000000000000000000000000000000000000000000"

let localFFIPath = "swift/QoreSignFFI.xcframework"
let packageDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path
let useLocalFFI = ProcessInfo.processInfo.environment["QORESIGN_LOCAL_FFI"] != nil
    || FileManager.default.fileExists(atPath: packageDir + "/" + localFFIPath)

let ffiTarget: Target = useLocalFFI
    ? .binaryTarget(name: "QoreSignFFI", path: localFFIPath)
    : .binaryTarget(
        name: "QoreSignFFI",
        url: "https://github.com/qorechain/qoresign/releases/download/v\(releaseVersion)/QoreSignFFI.xcframework.zip",
        checksum: releaseChecksum
    )

let package = Package(
    name: "QoreSign",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(name: "QoreSign", targets: ["QoreSign"]),
    ],
    targets: [
        ffiTarget,
        .target(
            name: "QoreSign",
            dependencies: ["QoreSignFFI"],
            path: "swift/Sources/QoreSign"
        ),
        .testTarget(
            name: "QoreSignTests",
            dependencies: ["QoreSign"],
            path: "swift/Tests/QoreSignTests"
        ),
    ]
)
