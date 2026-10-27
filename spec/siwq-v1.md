# Sign In With QoreChain (SIWQ), version 1

Status: stable for version 1 of the message format.

SIWQ lets a QoreChain account prove control of its keys to an off-chain service. The message follows the layout of [EIP-4361](https://eips.ethereum.org/EIPS/eip-4361) and Sign In With Solana, adapted to QoreChain addresses and chain ids. The signature has two parts: an ADR-36 secp256k1 signature, which any Keplr-compatible wallet can produce with `signArbitrary`, and an ML-DSA-87 (FIPS 204) signature by the account's registered post-quantum key.

## Message

```
${scheme://}${domain} wants you to sign in with your QoreChain account:
${address}

${statement}

URI: ${uri}
Version: 1
Chain ID: ${chain-id}
Nonce: ${nonce}
Issued At: ${issued-at}
Expiration Time: ${expiration-time}
Not Before: ${not-before}
Request ID: ${request-id}
Resources:
- ${resources[0]}
- ${resources[1]}
...
```

- Lines are separated by a single `\n`; there is no trailing newline.
- `scheme://` is optional. `domain` is the RFC 3986 authority of the requesting site (host and optional port).
- `address` is the `qor1` bech32 form of the account.
- The statement line is optional. Without it the address is followed by two empty lines, as in EIP-4361.
- `Version` is `1`. `Chain ID` is a QoreChain chain id such as `qorechain-vladi`.
- `Nonce` is at least 8 alphanumeric characters chosen by the server, single use.
- Timestamps are RFC 3339 / ISO 8601.
- `Expiration Time`, `Not Before`, `Request ID` and `Resources` are optional and appear in this order.

A verifier must re-render the parsed fields and refuse a message that does not match byte for byte.

## Signatures

```json
{
  "signatureType": "ml-dsa-87-hybrid",
  "classical": { "keyType": "secp256k1", "publicKey": "<base64>", "signature": "<base64>" },
  "pq": { "algorithmId": 1, "signature": "<base64>" }
}
```

### Classical part (ADR-36)

The account's secp256k1 key signs the amino JSON sign document below, serialized with sorted keys and no whitespace, where `data` is the base64 of the UTF-8 message and `signer` the `qor1` address:

```json
{"account_number":"0","chain_id":"","fee":{"amount":[],"gas":"0"},"memo":"","msgs":[{"type":"sign/MsgSignData","value":{"data":"...","signer":"qor1..."}}],"sequence":"0"}
```

The digest is SHA-256 for `secp256k1` accounts and KECCAK-256 for `eth_secp256k1` accounts; the signature is 64 bytes `r || s`, low-S. `publicKey` is the 33-byte compressed key, which must derive to `address` under `keyType`.

### Post-quantum part

```
pq.signature = ML-DSA-87.Sign(sk, UTF-8("qorechain-siwq-v1|" + message))
```

The domain prefix keeps a sign-in signature from being usable as a transaction signature and the other way round.

`signatureType` is `secp256k1` when the `pq` part is absent. Verifiers should refuse such sign-ins unless they explicitly accept classical-only accounts.

## Verification

A verifier must check, in this order:

1. the message parses and is in canonical form;
2. `domain` equals the domain the request came from;
3. `nonce` equals the nonce the server issued for this session, and the nonce has not been used before;
4. `Chain ID` is the expected network;
5. `Expiration Time` is in the future, and `Not Before` and `Issued At` are not in the future (allowing a small clock skew);
6. the classical public key derives to `address` and the ADR-36 signature verifies;
7. the ML-DSA-87 signature verifies under the public key **registered on chain** for `address` (`/qorechain/pqc/v1/account/{address}`), not under a key supplied by the client.

## Test vectors

`vectors/qoresign-v1.json`, field `siwq`.
