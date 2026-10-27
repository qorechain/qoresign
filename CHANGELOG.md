# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org); before 1.0, a minor version may contain breaking changes, which are always called out.

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
