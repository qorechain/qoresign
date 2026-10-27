# Hybrid transaction signing on QoreChain, version 1

Status: stable. Applies to the native (Cosmos SDK) lane of `qorechain-vladi` (mainnet) and `qorechain-diana` (testnet).

## Summary

A hybrid transaction is an ordinary Cosmos SDK `TxRaw` signed twice by the same account:

1. an ML-DSA-87 (FIPS 204) signature, carried inside the transaction body as the extension option `/qorechain.pqc.v1.PQCHybridSignature`;
2. a secp256k1 `SIGN_MODE_DIRECT` signature over the final body, in `TxRaw.signatures`.

The network verifies both. On the native lane the network requires the ML-DSA-87 signature by default (`HybridSignatureMode = Required`, a chain-wide parameter); apart from a small set of exempt messages, such as those that register or maintain the account's ML-DSA-87 key, a transaction without it is refused.

## Keys

| Key | Algorithm | Size |
|---|---|---|
| Classical | secp256k1 (`secp256k1` accounts: address = RIPEMD160(SHA256(compressed key)); `eth_secp256k1` accounts: address = last 20 bytes of KECCAK256(uncompressed key)) | 33-byte compressed public key |
| Post-quantum | ML-DSA-87, algorithm id `1` | public key 2592 bytes, signature 4627 bytes |

The ML-DSA-87 public key must be registered for the account with `MsgRegisterPQCKeyV2` before hybrid transactions verify (see "Registration"). A transaction may instead embed the public key in the extension (field 3) to register it on first use.

## The extension

```protobuf
package qorechain.pqc.v1;

message PQCHybridSignature {
  uint32 algorithm_id   = 1; // 1 = ML-DSA-87
  bytes  pqc_signature  = 2; // 4627 bytes
  bytes  pqc_public_key = 3; // optional, 2592 bytes
}
```

It is added to `TxBody.extension_options` (field 1023) as `google.protobuf.Any` with `type_url = "/qorechain.pqc.v1.PQCHybridSignature"` and the protobuf encoding as `value`. A body must carry exactly one such extension.

## Sign-bytes

Let `B0` be the canonical protobuf encoding of the `TxBody` **without** the PQC extension (every other field and extension kept, in order) and `A` the `AuthInfo` bytes exactly as broadcast. `BE32`/`BE64` are big-endian unsigned lengths.

```
v1 = BE32(len(B0)) || B0 || BE32(len(A)) || A
v2 = "qorechain-pqc-hybrid-v2" || BE64(len(chain_id)) || chain_id || v1
```

A network verifies exactly one form at a given height. Both public networks verify `v2` since their `v3.1.98` / `v3.2.0` upgrades (mainnet: `v3.2.0` at height 2,981,742); any other network verifies `v2` from genesis. `v1` is only needed to reproduce signatures made before those heights. A client can ask a node which form it verifies by reading `/cosmos/upgrade/v1beta1/applied_plan/{v3.1.98|v3.2.0}`.

The ML-DSA-87 signature is `ML-DSA.Sign(sk, signBytes, ctx = "")`. The network accepts both the deterministic and the hedged variant; QoreSign signs deterministically by default (FIPS 204, `rnd` = 32 zero bytes) so signatures are reproducible against the published vectors.

## Order of operations

1. Encode `B0` and `A` (the fee, gas limit and signer info are fixed at this point).
2. Compute the sign-bytes and the ML-DSA-87 signature.
3. Append the extension to `B0`, in canonical field order (after existing `extension_options`, before `non_critical_extension_options`), giving the final body `B`.
4. Sign `SignDoc { body_bytes = B, auth_info_bytes = A, chain_id, account_number }` with secp256k1: SHA-256 for `secp256k1` accounts, KECCAK-256 for `eth_secp256k1` accounts; 64-byte `r || s`, low-S.
5. Broadcast `TxRaw { B, A, [classical signature] }`.

The classical signature covers the extension; the ML-DSA-87 signature covers everything else in the body and the auth info, including the fee. Neither signature signs itself.

## Registration

`MsgRegisterPQCKeyV2` (type URL `/qorechain.pqc.v1.MsgRegisterPQCKeyV2`):

| Field | Number | Value |
|---|---|---|
| `sender` | 1 | the `qor1` account |
| `public_key` | 2 | ML-DSA-87 public key |
| `algorithm_id` | 3 | `1` |
| `ecdsa_pubkey` | 4 | the account's 33-byte compressed secp256k1 key; it must derive to `sender` |
| `key_type` | 5 | `hybrid` |
| `proof_of_possession` | 6 | ML-DSA-87 signature over the message below |

```
"qorechain-pqc-pop-v1|" + chain_id + "|" + algorithm_id + "|" + sender + "|" + lowercase_hex(public_key)
```

The registration transaction itself is signed with the classical key only. A public key whose `t1` part (bytes 32 onward) is all zero is refused, because its signatures can be forged.

## Other lanes

- EVM lane: Ethereum transactions have no field for an extension, so they carry no ML-DSA-87 signature. An account with a registered ML-DSA-87 key can open a bounded EVM authorization window from the native lane (expiry height, maximum transactions, maximum value).
- SVM lane: not open on the network yet.

## Test vectors

`vectors/qoresign-v1.json`, field `hybridTx`, gives a body, auth info and account number with the expected sign-bytes, signatures, final body and `TxRaw` for both versions.
