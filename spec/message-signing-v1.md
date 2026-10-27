# Message signing, version 1

Status: stable. For signing arbitrary data off chain (the `signArbitrary` request of Keplr-compatible wallets), for example to prove control of an account to a service.

## Signature

```json
{
  "signatureType": "ml-dsa-87-hybrid",
  "classical": { "keyType": "secp256k1", "publicKey": "<base64>", "signature": "<base64>" },
  "pq": { "algorithmId": 1, "signature": "<base64>" }
}
```

- **Classical part:** ADR-36. The account's secp256k1 key signs the amino JSON sign document of `MsgSignData { signer, data }`, exactly as in [siwq-v1.md](siwq-v1.md) (SHA-256 digest for `secp256k1` accounts, KECCAK-256 for `eth_secp256k1`; 64 bytes `r || s`, low-S).
- **Post-quantum part:**

```
pq.signature = ML-DSA-87.Sign(sk, UTF-8("qorechain-msg-v1|" + chain_id + "|") || data, ctx = "")
```

`data` is the raw message bytes. `chain_id` contains only letters, digits, `.`, `_` and `-`.

## Domain separation

Every ML-DSA-87 signature an account makes on QoreChain starts with a domain of its own, so a signature produced for one purpose cannot be replayed as another. A wallet must never sign raw bytes with the ML-DSA-87 key without one of these prefixes, and must never let a message start with a prefix reserved for another use.

| Prefix | Use |
|---|---|
| `qorechain-pqc-hybrid-v2` | transaction sign-bytes ([hybrid-signing-v1.md](hybrid-signing-v1.md)) |
| `qorechain-pqc-pop-v1\|` | proof of possession at key registration |
| `qorechain:pqc:recovery:v1` | account recovery |
| `qorechain-svm-auth-v2` | SVM lane authorization |
| `qorechain-siwq-v1\|` | Sign In With QoreChain ([siwq-v1.md](siwq-v1.md)) |
| `qorechain-msg-v1\|` | this specification |

## Verification

1. The classical public key derives to `signer` under `keyType`, and the ADR-36 signature verifies.
2. The ML-DSA-87 signature verifies under the key **registered on chain** for `signer` (`/qorechain/pqc/v1/account/{address}`), over the bytes above with the expected chain id.

## Test vectors

`vectors/qoresign-v1.json`, field `message`.
