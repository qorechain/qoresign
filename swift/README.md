# QoreSign for Swift

Hybrid secp256k1 + ML-DSA-87 (FIPS 204) signing, verification and Sign In With
QoreChain (SIWQ) for iOS 16+ and macOS 13+. The package wraps the Rust
implementation (`crates/qoresign`) through UniFFI, so its output is
byte-identical to the TypeScript, Rust, Go and Kotlin packages; all of them
are checked against `vectors/qoresign-v1.json`.

It is offline: key derivation, signing, verification, key registration
messages and SIWQ. Fetching account numbers and broadcasting stay in your app.

## Lanes

| Lane   | Today                                                                    |
| ------ | ------------------------------------------------------------------------ |
| native | hybrid ML-DSA-87 (FIPS 204) signature plus secp256k1                     |
| EVM    | quantum-ready only: the account registers an ML-DSA-87 key and opens an authorization window from the native lane; EVM transactions carry no ML-DSA-87 signature |
| SVM    | not available (`LANE_NOT_AVAILABLE`)                                     |

## Install

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/qorechain/qoresign", from: "0.1.0"),
],
targets: [
    .target(name: "MyWallet", dependencies: [
        .product(name: "QoreSign", package: "qoresign"),
    ]),
]
```

In Xcode: File > Add Package Dependencies, then the repository URL.

## Example

```swift
import QoreSign

// Public BIP-39 test phrase: never send funds to it.
let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

let classical = try deriveClassicalKey(mnemonic: mnemonic, keyType: .secp256k1) // m/44'/118'/0'/0/0
let account = try addressFromPublicKey(publicKey: classical.publicKey, keyType: .secp256k1)
let pqKey = try deriveCanonicalPqKey(mnemonic: mnemonic, address: account.bech32)

// bodyBytes, authInfoBytes and accountNumber come from the transaction you build.
let signed = try signHybrid(
    chainId: "qorechain-vladi", accountNumber: accountNumber,
    bodyBytes: bodyBytes, authInfoBytes: authInfoBytes,
    classicalKey: classical, pqKey: pqKey)
// signed.txBytes is the encoded TxRaw, ready to broadcast.

let result = try verifyHybridTx(
    txBytes: signed.txBytes, chainId: "qorechain-vladi", accountNumber: accountNumber,
    classicalPublicKey: classical.publicKey, pqPublicKey: pqKey.publicKey)
assert(result.valid)
```

Sign arbitrary data (`signArbitrary` style, spec/message-signing-v1.md):

```swift
let data = Data("Approve export of report 2026-10".utf8)
let sig = try signMessage(chainId: "qorechain-vladi", signer: account.bech32, data: data,
                          classicalKey: classical, pqKey: pqKey)
let json = try messageSignatureToJson(signature: sig) // shared JSON shape
// pqPublicKey: the key registered on chain for the signer.
try verifyMessage(chainId: "qorechain-vladi", signer: account.bech32, data: data,
                  signature: try messageSignatureFromJson(json: json), pqPublicKey: pqKey.publicKey)
```

Errors are `QoreSignError`; `code` is the stable code shared by every
implementation:

```swift
do {
    _ = try deriveClassicalKey(mnemonic: "not a phrase", keyType: .secp256k1)
} catch let error as QoreSignError {
    print(error.code, error.message) // INVALID_MNEMONIC ...
}
```

Byte fields are `Data`. Optional arguments default to the same values as the
TypeScript package (v2 sign-bytes, deterministic ML-DSA-87, hybrid mode).
`verifySiwq(... nowMs:)` takes Unix milliseconds; `nil` reads the system clock.

## Build locally

Needs macOS with Xcode, Rust 1.95 and the Apple targets:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin
scripts/build-xcframework.sh          # swift/QoreSignFFI.xcframework + zip + checksum
QORESIGN_LOCAL_FFI=1 swift test
```

When `xcode-select` points to the Command Line Tools, prefix both commands
with `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`.

`Package.swift` uses `swift/QoreSignFFI.xcframework` when `QORESIGN_LOCAL_FFI`
is set or that directory exists (it is git-ignored). Otherwise it uses the
xcframework zip attached to the GitHub release.

The script also regenerates `swift/Sources/QoreSign/QoreSign.swift` (UniFFI
output, do not edit by hand); CI fails when the committed file is stale.

## Releasing

SwiftPM verifies the downloaded zip against the checksum in the tagged
`Package.swift`, so the checksum must be committed before the tag:

1. Set `releaseVersion` in `Package.swift`.
2. `scripts/build-xcframework.sh --write-checksum` builds the zip and writes
   its checksum into `releaseChecksum` (a zero placeholder until then).
3. Commit, tag `v<version>`, push the tag.
4. `gh release upload v<version> swift/QoreSignFFI.xcframework.zip` with that
   same zip. The release workflow checks the uploaded zip against
   `Package.swift`; when no zip is uploaded it attaches its own build only if
   the checksum matches.

## License

Apache-2.0
