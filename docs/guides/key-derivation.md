# Key derivation

QoreSign offers two ways to get an ML-DSA-87 key from a BIP-39 mnemonic. Full definitions: [spec/hd-derivation-draft.md](../../spec/hd-derivation-draft.md).

| | `deriveCanonicalPqKey` | `deriveHdPqKey` (draft) |
|---|---|---|
| Input | mnemonic + account address | mnemonic (or seed) + hardened path |
| Bound to the address | yes | no |
| Same key as QoreChain wallets | yes | no |
| Needs registration on chain | only if not registered yet | always |
| Stability | stable | may change before it is final |

Use the canonical derivation unless you need several post-quantum keys per seed that are independent of addresses.

The mnemonic must be in canonical form (lowercase words, single spaces). QoreSign refuses other spellings instead of normalizing them, because the phrase is part of the derivation input and a different spelling would give a different key.

Wallets that do not have the mnemonic (for example, keys held in hardware) cannot use the canonical derivation. They can generate a random ML-DSA-87 key with `pqKeyFromSeed(randomBytes(32))` or use the HD draft, and register that key.
