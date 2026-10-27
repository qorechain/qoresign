# qorechain-qoresign

Hybrid secp256k1 + ML-DSA-87 (FIPS 204) signing, verification and Sign In With
QoreChain (SIWQ) for Rust. This is the Rust implementation of QoreSign; it is
offline (no network code) and byte-compatible with the other implementations
through the shared test vectors in `vectors/qoresign-v1.json`.

It covers:

- key derivation: BIP-39 / BIP-32 classical keys, the canonical ML-DSA-87 key
  QoreChain wallets use, and the draft hardened-only HD derivation;
- hybrid transaction signing and local verification (v2 and v1 sign-bytes);
- ML-DSA-87 key registration (`MsgRegisterPQCKeyV2` with proof of possession);
- SIWQ messages: create, parse, sign, verify;
- message signing (`signArbitrary` style): ADR-36 plus ML-DSA-87.

## Lanes

| Lane   | Today                                                                  |
| ------ | ---------------------------------------------------------------------- |
| native | hybrid ML-DSA-87 (FIPS 204) signature plus secp256k1                   |
| EVM    | quantum-ready only: no PQC layer on EVM transactions                   |
| SVM    | not available                                                          |

## Install

```sh
cargo add qorechain-qoresign
```

The library is imported as `qoresign`.

## Example

```rust
use qoresign::{address_from_public_key, derive_canonical_pq_key, derive_classical_key, sign_hybrid,
    verify_hybrid_tx, ClassicalKeyType, SignHybridArgs, VerifyHybridTxArgs};

// Public BIP-39 test mnemonic: never send funds to it.
let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
let classical = derive_classical_key(mnemonic, ClassicalKeyType::Secp256k1, 0)?;
let account = address_from_public_key(&classical.public_key, ClassicalKeyType::Secp256k1)?;
let pq = derive_canonical_pq_key(mnemonic, &account.bech32)?;

// Encoded TxBody and AuthInfo, as your transaction builder produced them.
let (body, auth_info) = (tx_body_bytes(), auth_info_bytes());
let args = SignHybridArgs::new("qorechain-vladi", 7, &body, &auth_info, &classical, Some(&pq));
let signed = sign_hybrid(&args)?; // signed.tx_bytes is ready to broadcast

let check = VerifyHybridTxArgs::new(&signed.tx_bytes, "qorechain-vladi", 7, &classical.public_key, Some(&pq.public_key));
assert!(verify_hybrid_tx(&check)?.valid);
```

### Sign a message

```rust
use qoresign::{sign_message, verify_message, VerifyMessageArgs};

let data = b"Approve export of report 2026-10";
let sig = sign_message("qorechain-vladi", &account.bech32, data, &classical, Some(&pq), false)?;
// MessageSignature is serde Serialize/Deserialize in the JSON shape every implementation exchanges.

// pq.public_key stands for the key registered on chain for the signer.
verify_message(&VerifyMessageArgs::new("qorechain-vladi", &account.bech32, data, &sig, Some(&pq.public_key)))?;
```

## More

- Guides: [../../docs](../../docs)
- Specifications (hybrid signing, SIWQ, message signing, HD derivation draft): [../../spec](../../spec)

## License

Apache-2.0
