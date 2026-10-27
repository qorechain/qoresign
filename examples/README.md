# Examples

| Example | Network | What it shows |
|---|---|---|
| [derive-and-verify](derive-and-verify) | none | derive keys, sign a hybrid transaction offline, verify it, tamper with it |
| [register-and-send](register-and-send) | `qorechain-diana` | register an account's ML-DSA-87 key with a proof of possession if needed, simulate, send a hybrid transaction, check the committed layer |
| [siwq-server](siwq-server) | `qorechain-diana` | Sign In With QoreChain: a small HTTP server issues nonces and verifies sign-ins against the key on chain |

Run from the repository root after `pnpm install && pnpm build`:

```bash
pnpm -C examples/derive-and-verify start
QORE_MNEMONIC="<your testnet mnemonic>" pnpm -C examples/register-and-send start
QORE_MNEMONIC="<your testnet mnemonic>" pnpm -C examples/siwq-server start
```

The network examples refuse to run against `qorechain-vladi` (mainnet). Use a testnet account you control; never put a mainnet mnemonic in a script or shell history.
