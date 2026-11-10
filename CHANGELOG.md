# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org); before 1.0, a minor version may contain breaking changes, which are always called out.

## [Unreleased]

## [0.2.0] - 2026-11-10

Security details will be published separately.

### Changed

- Sign In With QoreChain: verification applies a maximum age to a message without `Expiration Time`, counted from `Issued At`: 600 seconds (10 minutes) by default, configurable through a new option in every binding (Rust `VerifySiwqArgs::max_age_seconds`, Go `VerifySiwqOptions.MaxAge`, TypeScript `maxAgeSeconds`, Python `max_age_seconds`, Swift `maxAgeSeconds`, Kotlin `maxAgeSeconds`). An older message fails with `SIWQ_EXPIRED`; a zero or negative value fails with `INVALID_ARGUMENT`. The specification now says servers SHOULD require `Expiration Time`.
- Sign In With QoreChain timestamps (`Issued At`, `Expiration Time`, `Not Before`) follow one strict RFC 3339 grammar, applied the same way when creating, parsing, signing and verifying a message: hour 00 to 23, minute and second 00 to 59, real calendar dates, uppercase `Z` or an offset within 00:00 to 23:59. A timestamp outside it fails with `SIWQ_MALFORMED`. Shared vectors in `vectors/siwq-timestamps-v1.json`.
- `assertPqLayerMatchesRegisteredKey` / `AssertPqLayerMatchesRegisteredKey` and `inspectTransaction` check the ML-DSA-87 layer against the sign-bytes version the network uses, or the one passed in the new `signBytesVersion` / `SignBytesVersion` option. Accepting a layer over either version needs the explicit diagnostic option `allowLegacyEither` / `AllowLegacyEither`.
- Sign-bytes version resolution (`resolveSignBytesVersion` / `ResolveSignBytesVersion`) reads the `pqc-sign-bytes-v2` entry of the network's protocol feature list first. When the list can be read it decides the version (not listed means v1); the applied-upgrade check is used only when the list cannot be read.
- FFI: `verify_siwq` takes the maximum age as a new last parameter, so every native library (xcframework, JVM, Android, Python wheels) is rebuilt for this version.

### Added

- Go `ParseSiwqTimestamp` and TypeScript `parseSiwqTimestamp`, which return the Unix milliseconds of a timestamp in the grammar above.
- Go `FetchProtocolFeature` and TypeScript `fetchProtocolFeature`, `PROTOCOL_FEATURES_PATH` and `SIGN_BYTES_V2_FEATURE`.

### Fixed

- Python: the Linux wheels were built without their generated bindings (`import qoresign` failed with `cannot import name 'qoresign_ffi'`). The native library on Linux now keeps the symbols the bindings are generated from, and the build checks that every wheel carries them.

### Migration from 0.1.x

- A sign-in message without `Expiration Time` is refused once it is older than 10 minutes. Set `expirationTime` on every message your server issues, or pass a larger maximum age if you need one.
- The registered-key layer check no longer accepts a layer over either sign-bytes version by default. It uses the network's version; pass `signBytesVersion: "v1"` for a transaction committed before the network moved to v2, or `allowLegacyEither: true` for diagnostics only.
- Rust, Go and TypeScript (and the Python, Swift and Kotlin bindings over the Rust core) refuse timestamps outside the grammar, including `24:00:00`, leap seconds, a space separator, lowercase `t` or `z` and an offset without a colon. Messages created by QoreSign already use the grammar.
- Swift, Kotlin and Python: upgrade the package and its native library together; a 0.1.x native library does not match the 0.2.0 bindings.

## [0.1.1] - 2026-10-27

### Added

- Python package `qorechain-qoresign` (import `qoresign`), bindings over the Rust implementation: wheels for macOS, Linux (manylinux2014) and Windows, Python 3.9+, checked against `vectors/qoresign-v1.json`.
- TypeScript `@qorechain/qoresign/network`: `inspectTransaction` (messages, signer, fee, ML-DSA-87 layer verified against the registered key, security tier) and `fetchEvmWindow`.

### Fixed

- The Swift xcframework zip no longer contains a resource-fork folder.
- The macOS native libraries (Kotlin and Python packages) no longer record the build directory as their install name.

## [0.1.0] - 2026-10-27

First release, in TypeScript, Rust, Go, Swift and Kotlin.

### Added

- Canonical ML-DSA-87 key derivation (the key QoreChain wallets register) and a draft hardened-only HD derivation.
- Hybrid secp256k1 + ML-DSA-87 signing of native-lane transactions (`signHybrid`, `signPqLayer`), deterministic by default, with sign-bytes versions v1 and v2.
- Local verification of hybrid transactions and of a dApp-provided ML-DSA-87 layer.
- Proof of possession and `MsgRegisterPQCKeyV2` construction.
- Sign In With QoreChain: message format, signing and verification (ADR-36 secp256k1 plus ML-DSA-87).
- Arbitrary message signing (`signMessage` / `verifyMessage`): ADR-36 plus ML-DSA-87 over `"qorechain-msg-v1|" + chainId + "|" + data`, and the list of reserved ML-DSA-87 signing domains.
- Lane rules: native hybrid, EVM quantum-ready only, SVM unavailable.
- Network helpers (TypeScript and Go): key status, sign-bytes version, simulation with balance changes and a gas limit suggestion, broadcast with a single sign-bytes fallback, sign-in verification against the key on chain.
- Specifications and shared test vectors (`vectors/qoresign-v1.json`).
