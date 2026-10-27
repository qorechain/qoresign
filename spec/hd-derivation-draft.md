# ML-DSA-87 key derivation

Status: the canonical derivation is stable. The hierarchical derivation is a **draft**: implementations may change before it is final, and keys derived with it must be registered on chain like any other key.

## Canonical derivation (stable)

QoreChain wallets and the QoreChain SDK derive one ML-DSA-87 key per account from the BIP-39 mnemonic and the account address:

```
seed = SHAKE256( UTF-8( "qorechain:pqc:v1|" + bech32_address + "|" + mnemonic ), 32 bytes )
(pk, sk) = ML-DSA-87.KeyGen_internal(seed)
```

- `bech32_address` is the `qor1` form of the account (an `0x` address is converted to the same 20 bytes first).
- `mnemonic` is the phrase in canonical form: lowercase English words separated by single spaces, nothing before or after. Implementations must refuse any other spelling rather than normalize it silently, because a different string gives a different key.
- The key is bound to the address: the same mnemonic gives a different key for each account.

A wallet that uses this derivation signs with the key already registered for accounts created by QoreChain wallets.

## Hierarchical derivation (draft)

For wallets that need several post-quantum keys from one seed without tying them to an address. ML-DSA has no public child derivation, so every path segment is hardened.

The construction is SLIP-0010 with its own master key string:

```
I  = HMAC-SHA512(key = "qorechain-mldsa87-seed", data = seed)
k  = I[0..32],  c = I[32..64]
for each index i (all >= 2^31):
    I = HMAC-SHA512(key = c, data = 0x00 || k || ser32(i))
    k = I[0..32],  c = I[32..64]
(pk, sk) = ML-DSA-87.KeyGen_internal(k)
```

- `seed` is the 64-byte BIP-39 seed (mnemonic plus optional passphrase), or any 16 to 64 byte seed.
- The default path is `m/44'/118'/{account}'/0'/0'`.
- A path with any non-hardened segment is refused.

Open points before this becomes final: the coin type to use in the path, interaction with key rotation on chain (`MsgRotatePQCKey`), and alignment with other ecosystems that derive post-quantum keys from a seed.

## Test vectors

`vectors/qoresign-v1.json`, fields `canonical`, `hd` and `hdRejected`.
