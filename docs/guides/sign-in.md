# Sign In With QoreChain: server verification

SIWQ is an EIP-4361-style sign-in message signed by the account's secp256k1 key (ADR-36) and by its ML-DSA-87 key. Format: [spec/siwq-v1.md](../../spec/siwq-v1.md).

## Flow

1. The server issues a single-use nonce for the session.
2. The client builds the message with `createSiwqMessage` and the wallet signs it with `signSiwq` (or produces the classical part with `signArbitrary` and the ML-DSA-87 part with `pqSign` over `siwqPqSignBytes(message)`).
3. The server verifies with `verifySiwqWithChain`, which checks the message, the nonce, the domain, the times, that the classical key controls the address, and the ML-DSA-87 signature against the key **registered on chain** for the address.

## TypeScript

```ts
import { verifySiwqWithChain } from "@qorechain/qoresign/network";

const fields = await verifySiwqWithChain({
  rest: "https://api.qore.host",
  address: body.address,
  message: body.message,
  signature: body.signature,
  domain: "app.example.com",       // the host the request came to
  nonce: session.nonce,            // single use; delete it now
  chainId: "qorechain-vladi",
});
// fields.address is signed in; fields.possessionProven tells whether the key was registered with a proof of possession
```

## Go

```go
import (
    qoresign "github.com/qorechain/qoresign/go"
    "github.com/qorechain/qoresign/go/network"
)

client := network.NewClient("https://api.qore.host")
result, err := client.VerifySiwqWithChain(ctx, address, qoresign.VerifySiwqOptions{
    Message: message, Signature: signature,
    Domain: "app.example.com", Nonce: nonce, ChainID: "qorechain-vladi",
})
// result.SiwqFields holds the verified fields; result.PossessionProven reports the key's proof of possession.
```

## Classical-only accounts

`verifySiwq` refuses a sign-in without the ML-DSA-87 part unless `requirePq: false` is passed. Accept classical-only sign-ins only if your service does not need the post-quantum guarantee.
