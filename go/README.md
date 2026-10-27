# QoreSign for Go

Hybrid secp256k1 + ML-DSA-87 (FIPS 204) signing and verification for QoreChain,
and Sign In With QoreChain (SIWQ). The Go module follows the TypeScript reference
and reproduces every byte of the shared vectors in `../vectors/qoresign-v1.json`.

```sh
go get github.com/qorechain/qoresign/go
```

- `github.com/qorechain/qoresign/go`: keys, hybrid transaction signing and
  verification, key registration, SIWQ. Works offline.
- `github.com/qorechain/qoresign/go/network`: optional REST helpers (registered
  key lookup, sign-bytes version, simulation, broadcast).

## Lanes today

| Lane   | Support |
| ------ | ------- |
| native | Hybrid ML-DSA-87 (FIPS 204) + secp256k1 signature; the network requires it by default. |
| EVM    | Quantum-ready only: Ethereum transactions carry no PQC layer; an account with a registered ML-DSA-87 key can open a bounded EVM authorization window from the native lane. |
| SVM    | Not available on the network yet. |

## Sign and verify a transaction

```go
classical, _ := qoresign.DeriveClassicalKey(mnemonic, qoresign.DeriveClassicalOptions{})
account, _ := qoresign.AddressFromPublicKey(classical.PublicKey, qoresign.Secp256k1)
pq, _ := qoresign.DeriveCanonicalPqKey(mnemonic, account.Bech32)

signed, err := qoresign.SignHybrid(qoresign.SignHybridArgs{
	ChainID:       "qorechain-diana",
	AccountNumber: accountNumber,
	BodyBytes:     bodyBytes,     // encoded TxBody
	AuthInfoBytes: authInfoBytes, // encoded AuthInfo (SIGN_MODE_DIRECT)
	ClassicalKey:  classical,
	PqKey:         &pq,
})
if err != nil {
	return err
}

res, err := qoresign.VerifyHybridTx(qoresign.VerifyHybridTxArgs{
	TxBytes:            signed.TxBytes,
	ChainID:            "qorechain-diana",
	AccountNumber:      accountNumber,
	ClassicalPublicKey: classical.PublicKey,
	PqPublicKey:        pq.PublicKey,
})
// res.Valid is true when both signatures verify.
```

Signatures are deterministic by default; set `Hedged: true` for FIPS 204 hedged
signing (the network accepts both).

## Verify a sign-in on the server

```go
client := network.NewClient("https://api-testnet.qore.host")

var sig qoresign.SiwqSignature
if err := json.Unmarshal(signatureJSON, &sig); err != nil {
	return err
}
result, err := client.VerifySiwqWithChain(ctx, address, qoresign.VerifySiwqOptions{
	Message:   message,
	Signature: sig,
	Domain:    "app.example.com", // the host the request came to
	Nonce:     issuedNonce,       // the nonce your server issued
	ChainID:   "qorechain-diana",
})
if qoresign.IsCode(err, qoresign.CodeSiwqExpired) {
	// ask the user to sign in again
}
// result.Address signed in; result.PossessionProven reports how the key was registered.
```

`qoresign.VerifySiwq` does the same checks offline when you already hold the
account's registered ML-DSA-87 public key. A classical-only sign-in is refused
unless `RequirePq` points to `false`.

## Errors

Every intentional error is a `*qoresign.Error` with a stable `Code` (the same
strings as the other QoreSign implementations). Use `qoresign.IsCode(err, code)`.

## Tests

```sh
go test ./...
```

`live_test.go` runs against the qorechain-diana testnet only when
`QORE_LIVE_TEST=1` and `QORE_TEST_MNEMONIC` (a funded testnet account) are set.

## License

Apache-2.0
