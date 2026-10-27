# Sizes and transport

| Item | Bytes | Source |
|---|---|---|
| ML-DSA-87 public key | 2592 | FIPS 204, Table 2 |
| ML-DSA-87 secret key | 4896 | FIPS 204, Table 2 |
| ML-DSA-87 signature | 4627 | FIPS 204, Table 2 |
| ML-DSA-87 seed | 32 | FIPS 204 |
| secp256k1 compressed public key | 33 | SEC 1 |
| secp256k1 signature (r, s) | 64 | |
| PQC extension in a body | about 4640 (signature plus protobuf framing; plus 2595 when the public key is embedded) | `qorechain.pqc.v1.PQCHybridSignature` |

Consequences for wallets:

- A hybrid transaction is about 4.7 KB larger than a classical one. Gas and fees scale with transaction size; simulate before signing (`simulateTx`) and use the suggested gas limit.
- A single static QR code holds at most 2953 bytes (version 40, binary, low error correction), so an ML-DSA-87 signature or public key does not fit in one. Air-gapped signers need multi-part encodings (animated or fountain-coded QR).
- Store the 32-byte seed, not the 4896-byte secret key, when you need to persist an ML-DSA-87 key; `pqKeyFromSeed` re-creates the key pair.
