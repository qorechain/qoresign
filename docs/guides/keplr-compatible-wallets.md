# Add hybrid signing to a Keplr-compatible wallet

QoreChain's native lane refuses a transaction from an account with a registered ML-DSA-87 key unless the transaction also carries that key's signature. A Keplr-compatible wallet (Keplr, Leap, Cosmostation and others that implement `signDirect`) produces the secp256k1 part; the ML-DSA-87 part has to come from whoever holds the post-quantum key.

There are two ways to add it.

## Option A: the wallet holds both keys (QoreSign)

The wallet derives the ML-DSA-87 key next to the secp256k1 key and adds the layer before it signs.

```ts
import { deriveCanonicalPqKey, signPqLayer } from "@qorechain/qoresign";

// at account creation or import, from the same mnemonic and address
const pqKey = deriveCanonicalPqKey({ mnemonic, address });

// inside signDirect(signerAddress, signDoc):
const { bodyBytes } = signPqLayer({
  chainId: signDoc.chainId,
  bodyBytes: signDoc.bodyBytes,
  authInfoBytes: signDoc.authInfoBytes,
  pqKey,
});
const finalDoc = { ...signDoc, bodyBytes }; // sign this with the secp256k1 key, as for any Cosmos SDK chain
```

Rules that keep the user safe:

- Show the user the messages and fee from `bodyBytes` / `authInfoBytes` before signing, the same as for any `signDirect` request. The ML-DSA-87 signature covers the fee.
- When a dApp sends a body that already carries a PQC layer, check it with `assertPqLayerMatchesRegisteredKey` (from `@qorechain/qoresign/network`) before adding your classical signature; a layer that does not verify protects nothing.
- Register the key once per account with `buildRegisterPqKeyMessage`, signed in `classicalOnly` mode (see [`examples/register-and-send`](../../examples/register-and-send)).
- After broadcast, read the committed transaction back and call `evaluateLayerState`; `downgraded` means the layer did not reach the chain.

## Option B: the dApp holds the post-quantum key (`@qorechain/wallet-adapter`)

When the wallet cannot be changed, a dApp can use [`@qorechain/wallet-adapter`](https://www.npmjs.com/package/@qorechain/wallet-adapter): it adds the ML-DSA-87 layer to the body and then asks the unchanged wallet for an ordinary `signDirect` signature. The post-quantum key then lives with the dApp or a companion signer, not in the wallet. QoreSign and the adapter produce the same bytes for the same keys.

## Chain registration for Keplr

Suggest the chain with `experimentalSuggestChain` using the published chain descriptors: chain ids `qorechain-vladi` (mainnet) and `qorechain-diana` (testnet), bech32 prefix `qor`, coin type `118`, fee denom `uqor` with 6 decimals and a minimum gas price of `0.1`. Public endpoints: `https://rpc.qore.host` and `https://api.qore.host` (mainnet), `https://rpc-testnet.qore.host` and `https://api-testnet.qore.host` (testnet).
