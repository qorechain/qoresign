# @qorechain/qoresign

Hybrid secp256k1 + ML-DSA-87 (FIPS 204) signing, verification and Sign In With QoreChain for wallets and backends on QoreChain.

```bash
npm install @qorechain/qoresign
```

- **Native lane:** hybrid signing and verification; the network requires the ML-DSA-87 signature by default.
- **EVM lane:** quantum-ready mode only (registered key plus an authorization window opened from the native lane).
- **SVM lane:** not open on the network yet.

```ts
import { addressFromPublicKey, deriveCanonicalPqKey, deriveClassicalKey, signHybrid } from "@qorechain/qoresign";

const classical = deriveClassicalKey({ mnemonic });
const address = addressFromPublicKey(classical.publicKey, "secp256k1").bech32;
const pqKey = deriveCanonicalPqKey({ mnemonic, address });

const { txBytes } = signHybrid({ chainId, accountNumber, bodyBytes, authInfoBytes, classicalKey: classical, pqKey });
```

Two entry points:

| Import | Contents |
|---|---|
| `@qorechain/qoresign` | offline: keys and addresses, hybrid signing, verification, key registration, Sign In With QoreChain, lane rules |
| `@qorechain/qoresign/network` | REST helpers: key status, sign-bytes version, simulation, broadcast, sign-in verification against the chain |

Documentation, specifications and examples: <https://github.com/qorechain/qoresign>.

Apache-2.0. Copyright 2026 QoreChain Association.
