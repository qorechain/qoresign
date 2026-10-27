# QoreSign for Python

Hybrid secp256k1 + ML-DSA-87 (FIPS 204) signing, verification and Sign In With
QoreChain (SIWQ) for Python 3.9+. The package wraps the Rust implementation
(`crates/qoresign`) through UniFFI, so its output is byte-identical to the
TypeScript, Rust, Go, Swift and Kotlin packages; all of them are checked
against `vectors/qoresign-v1.json`.

It is offline: key derivation, signing, verification, key registration
messages, message signing and SIWQ. Fetching account numbers and broadcasting
stay in your app.

## Lanes

| Lane   | Today                                                                    |
| ------ | ------------------------------------------------------------------------ |
| native | hybrid ML-DSA-87 (FIPS 204) signature plus secp256k1                     |
| EVM    | quantum-ready only: the account registers an ML-DSA-87 key and opens an authorization window from the native lane; EVM transactions carry no ML-DSA-87 signature |
| SVM    | not available (`LANE_NOT_AVAILABLE`)                                     |

## Install

```sh
pip install qorechain-qoresign
```

```python
import qoresign
```

Wheels: macOS 11+ (arm64, x86_64), Linux manylinux2014 (x86_64, aarch64) and
Windows (x86_64). One wheel per platform serves every Python 3 version: the
bindings call the native library through `ctypes`. Other platforms build from
the source distribution, which needs Rust 1.95.

## Example

```python
import qoresign as qs

# Public BIP-39 test phrase: never send funds to it.
mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

classical = qs.derive_classical_key(mnemonic, qs.ClassicalKeyType.SECP256K1)  # m/44'/118'/0'/0/0
account = qs.address_from_public_key(classical.public_key, qs.ClassicalKeyType.SECP256K1)
pq_key = qs.derive_canonical_pq_key(mnemonic, account.bech32)  # the key QoreChain wallets register

# body_bytes, auth_info_bytes and account_number come from the transaction you build.
signed = qs.sign_hybrid("qorechain-vladi", account_number, body_bytes, auth_info_bytes, classical, pq_key=pq_key)
# signed.tx_bytes is the encoded TxRaw, ready to broadcast.

result = qs.verify_hybrid_tx(
    signed.tx_bytes, "qorechain-vladi", account_number, classical.public_key,
    pq_public_key=pq_key.public_key,
)
assert result.valid and result.classical and result.pq.valid
```

Sign arbitrary data (spec/message-signing-v1.md):

```python
data = b"Approve export of report 2026-10"
sig = qs.sign_message("qorechain-vladi", account.bech32, data, classical, pq_key=pq_key)
as_json = qs.message_signature_to_json(sig)  # JSON shape shared by every implementation

# pq_public_key: the key registered on chain for the signer.
qs.verify_message(
    "qorechain-vladi", account.bech32, data,
    qs.message_signature_from_json(as_json), pq_public_key=pq_key.public_key,
)  # raises QoreSignError when the signature does not verify
```

Verify a sign-in on the server (spec/siwq-v1.md):

```python
fields = qs.verify_siwq(
    message,                               # the text the wallet signed
    qs.siwq_signature_from_json(sig_json), # the signature the wallet returned
    "app.example.com",                     # your domain
    nonce,                                 # the nonce you issued
    pq_public_key=registered_pq_key,       # the account's key registered on chain
    chain_id="qorechain-vladi",
)
print(fields.address)  # qor1...
```

A wallet creates the message with `create_siwq_message(qs.SiwqFields(...))`
and signs it with `sign_siwq(message, classical, pq_key=pq_key)`.

Errors are `QoreSignError`; `code` is the stable code shared by every
implementation:

```python
try:
    qs.derive_classical_key("not a phrase", qs.ClassicalKeyType.SECP256K1)
except qs.QoreSignError as e:
    print(e.code, e.detail)  # INVALID_MNEMONIC ...
```

Byte fields are `bytes`; records are plain classes with keyword-only
constructors and value equality. Optional arguments default to the same
values as the TypeScript package (v2 sign-bytes, deterministic ML-DSA-87,
hybrid mode). `verify_siwq(..., now_ms=...)` takes Unix milliseconds; `None`
reads the system clock. Format constants (`ML_DSA_87_SIGNATURE_LENGTH`,
`PQC_HYBRID_TYPE_URL`, ...) are module attributes.

## Build locally

Needs Rust 1.95 and Python 3.9+.

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -r python/requirements-dev.txt
scripts/build-python-wheels.sh                # this machine's wheel -> python/dist/
pip install --no-index --find-links python/dist qorechain-qoresign
pytest python/tests
```

`scripts/build-python-wheels.sh` takes a list of targets: `host`,
`macos-arm64`, `macos-x86_64`, `sdist`, and `check` (scans `python/dist` for
build-machine paths, which every build also does). The release workflow builds
the Linux and Windows wheels. `python/qoresign/_ffi/` is UniFFI output,
generated at build time.

## License

Apache-2.0
