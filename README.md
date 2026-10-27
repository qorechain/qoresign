# QoreSign

Hybrid secp256k1 + ML-DSA-87 (FIPS 204) signing for wallets and backends on [QoreChain](https://www.qorechain.io).

QoreSign lets a wallet other than QoreChain's own derive an account's ML-DSA-87 key, sign native-lane transactions with both keys, verify hybrid signatures locally, simulate a transaction before signing, and implement Sign In With QoreChain. It is a thin layer over the [`qorechain-pqc`](https://github.com/qorechain/qorechain-pqc) bindings and adds no cryptographic primitives of its own.

| Lane | What QoreSign does today |
|---|---|
| **Native** (Cosmos SDK) | Hybrid signing and verification. The network requires the ML-DSA-87 signature by default. |
| **EVM** | Quantum-ready mode only: the account registers an ML-DSA-87 key and opens a bounded authorization window from the native lane. Ethereum transactions themselves carry no ML-DSA-87 signature. |
| **SVM** | Not open on the network yet (`LANE_NOT_AVAILABLE`). |

## Packages

| Language | Package | Install |
|---|---|---|
| TypeScript | [`@qorechain/qoresign`](packages/ts) | `npm install @qorechain/qoresign` |
| Rust | [`qorechain-qoresign`](crates/qoresign) | `cargo add qorechain-qoresign` |
| Go | [`github.com/qorechain/qoresign/go`](go) | `go get github.com/qorechain/qoresign/go` |
| Swift | [`QoreSign`](swift) (Swift Package, iOS 16+, macOS 13+) | `.package(url: "https://github.com/qorechain/qoresign", from: "0.1.0")` |
| Kotlin / JVM | [`io.github.qorechain:qoresign`](kotlin) | `implementation("io.github.qorechain:qoresign:0.1.0")` |

All five implementations check themselves against the same [test vectors](vectors).

## Example

```ts
import {
  addressFromPublicKey,
  deriveCanonicalPqKey,
  deriveClassicalKey,
  signHybrid,
  verifyHybridTx,
} from "@qorechain/qoresign";

const classical = deriveClassicalKey({ mnemonic });                 // m/44'/118'/0'/0/0
const address = addressFromPublicKey(classical.publicKey, "secp256k1").bech32;
const pqKey = deriveCanonicalPqKey({ mnemonic, address });         // the key QoreChain wallets register

// bodyBytes / authInfoBytes / accountNumber come from the dApp's SignDoc
const signed = signHybrid({ chainId: "qorechain-vladi", accountNumber, bodyBytes, authInfoBytes, classicalKey: classical, pqKey });

verifyHybridTx({
  txBytes: signed.txBytes,
  chainId: "qorechain-vladi",
  accountNumber,
  classicalPublicKey: classical.publicKey,
  pqPublicKey: pqKey.publicKey,
}); // { valid: true, classical: true, pq: { valid: true, signBytesVersion: "v2" } }
```

Network helpers (key status, simulation with balance changes, broadcast, sign-in verification against the chain) are in `@qorechain/qoresign/network`.

## Documentation

- [Quickstart](docs/quickstart.md)
- Guides: [Keplr-compatible wallets](docs/guides/keplr-compatible-wallets.md), [Sign In With QoreChain](docs/guides/sign-in.md), [EVM quantum-ready mode](docs/guides/evm-quantum-ready.md), [key derivation](docs/guides/key-derivation.md), [sizes and transport](docs/guides/sizes-and-transport.md)
- Specifications: [hybrid signing](spec/hybrid-signing-v1.md), [Sign In With QoreChain](spec/siwq-v1.md), [ML-DSA-87 key derivation](spec/hd-derivation-draft.md)
- [Examples](examples)

## Scope

QoreSign signs locally. It does not hold keys for you, does not do threshold or MPC signing, and does not sign on hardware wallets. The ML-DSA-87 and secp256k1 implementations come from `qorechain-pqc` (built on `@noble/post-quantum`, `fips204` and Cloudflare CIRCL) and from `@noble/curves`, `k256` and `decred/secp256k1`.

## Versioning

QoreSign is pre-1.0: minor versions may change the API, and every breaking change is listed in the [changelog](CHANGELOG.md). The wire formats are versioned separately (`spec/*-v1.md`, `vectors/qoresign-v1.json`) and do not change within a version.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE). Copyright 2026 QoreChain Association.
