# QoreSign for Kotlin

Hybrid secp256k1 + ML-DSA-87 (FIPS 204) signing, verification and Sign In With
QoreChain (SIWQ) for Kotlin on the JVM (17+) and on Android (API 24+). The
package wraps the Rust implementation (`crates/qoresign`) through UniFFI and
JNA, so its output is byte-identical to the TypeScript, Rust, Go and Swift
packages; all of them are checked against `vectors/qoresign-v1.json`.

It is offline: key derivation, signing, verification, key registration
messages and SIWQ. Fetching account numbers and broadcasting stay in your app.

| Artifact | Contents |
| --- | --- |
| `io.github.qorechain:qoresign` | JVM jar with native libraries for macOS (arm64, x86-64), Linux (x86-64, arm64) and Windows (x86-64) |
| `io.github.qorechain:qoresign-android` | AAR with `arm64-v8a`, `armeabi-v7a` and `x86_64` libraries |

## Lanes

| Lane   | Today                                                                    |
| ------ | ------------------------------------------------------------------------ |
| native | hybrid ML-DSA-87 (FIPS 204) signature plus secp256k1                     |
| EVM    | quantum-ready only: the account registers an ML-DSA-87 key and opens an authorization window from the native lane; EVM transactions carry no ML-DSA-87 signature |
| SVM    | not available (`LANE_NOT_AVAILABLE`)                                     |

## Install

```kotlin
// JVM
implementation("io.github.qorechain:qoresign:0.1.0")
// Android
implementation("io.github.qorechain:qoresign-android:0.1.0")
```

The Android AAR ships R8 keep rules for JNA and the bindings.

## Example

```kotlin
import io.github.qorechain.qoresign.*

// Public BIP-39 test phrase: never send funds to it.
val mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

val classical = deriveClassicalKey(mnemonic, ClassicalKeyType.SECP256K1) // m/44'/118'/0'/0/0
val account = addressFromPublicKey(classical.publicKey, ClassicalKeyType.SECP256K1)
val pqKey = deriveCanonicalPqKey(mnemonic, account.bech32)

// bodyBytes, authInfoBytes and accountNumber come from the transaction you build.
val signed = signHybrid("qorechain-vladi", accountNumber, bodyBytes, authInfoBytes, classical, pqKey = pqKey)
// signed.txBytes is the encoded TxRaw, ready to broadcast.

val result = verifyHybridTx(
    signed.txBytes, "qorechain-vladi", accountNumber, classical.publicKey,
    pqPublicKey = pqKey.publicKey,
)
check(result.valid)
```

Errors are `QoreSignException`; `code` is the stable code shared by every
implementation:

```kotlin
try {
    deriveClassicalKey("not a phrase", ClassicalKeyType.SECP256K1)
} catch (e: QoreSignException) {
    println("${e.code}: ${e.detail}") // INVALID_MNEMONIC: ...
}
```

Byte fields are `ByteArray`; account numbers are `ULong`. Optional arguments
default to the same values as the TypeScript package (v2 sign-bytes,
deterministic ML-DSA-87, hybrid mode). `verifySiwq(..., nowMs = ...)` takes
Unix milliseconds; `null` reads the system clock. Records are data classes
holding `ByteArray`s, so compare their byte fields with `contentEquals`.

## Build locally

Needs Rust 1.95 and JDK 17 or 21 (run Gradle with `JAVA_HOME` pointing to it).

```sh
scripts/build-kotlin-natives.sh             # this machine's library -> kotlin/natives/
cd kotlin && ./gradlew test
```

`scripts/build-kotlin-natives.sh` takes a list of targets: `darwin-aarch64`,
`darwin-x86-64`, `linux-x86-64`, `linux-aarch64`, `win32-x86-64`, `android`
(or one ABI: `android-arm64-v8a`, `android-armeabi-v7a`, `android-x86_64`),
`host`, and `bindings` (regenerates
`src/main/kotlin/io/github/qorechain/qoresign/qoresign_ffi.kt`, UniFFI output,
do not edit by hand). The release workflow builds every target.

The Android module is included with `-PqoresignAndroid=true` and needs an
Android SDK (`ANDROID_HOME`) and, for the native libraries, NDK 27
(`ANDROID_NDK_HOME`):

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
ANDROID_NDK_HOME=... scripts/build-kotlin-natives.sh android
cd kotlin && ./gradlew -PqoresignAndroid=true :android:assembleRelease
```

Publishing is configured (Central Portal, signed) but runs only from the
release workflow; `./gradlew publishToMavenLocal` checks the packaging.

## License

Apache-2.0
