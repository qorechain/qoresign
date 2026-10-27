# QoreSign documentation

- [Quickstart](quickstart.md): derive keys, sign and verify a hybrid transaction in a few minutes.
- Guides
  - [Add hybrid signing to a Keplr-compatible wallet](guides/keplr-compatible-wallets.md)
  - [Sign In With QoreChain: server verification](guides/sign-in.md)
  - [EVM wallets: quantum-ready mode](guides/evm-quantum-ready.md)
  - [Key derivation: canonical keys and the HD draft](guides/key-derivation.md)
  - [Sizes and transport](guides/sizes-and-transport.md)
- Specifications
  - [Hybrid transaction signing v1](../spec/hybrid-signing-v1.md)
  - [Sign In With QoreChain v1](../spec/siwq-v1.md)
  - [ML-DSA-87 key derivation](../spec/hd-derivation-draft.md)
- [Test vectors](../vectors/README.md)
- API reference: run `pnpm -C packages/ts docs` (TypeScript), `cargo doc -p qorechain-qoresign` (Rust), `go doc github.com/qorechain/qoresign/go` (Go). Swift and Kotlin bindings mirror the Rust API; see [swift/README.md](../swift/README.md) and [kotlin/README.md](../kotlin/README.md).

## What QoreSign covers today

| Lane | Status |
|---|---|
| Native (Cosmos SDK) | Hybrid secp256k1 + ML-DSA-87 (FIPS 204) signing and verification. The network requires the ML-DSA-87 signature by default. |
| EVM | Ethereum transactions carry no ML-DSA-87 signature. An account with a registered ML-DSA-87 key can open a bounded authorization window from the native lane ("quantum-ready mode"). Hybrid EVM signing needs per-lane PQC support in the network first. |
| SVM | Not open on the network yet. Calls that need it fail with `LANE_NOT_AVAILABLE`. |
