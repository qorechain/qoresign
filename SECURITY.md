# Security Policy

QoreSign signs transactions and verifies sign-ins, so we treat security reports for it with priority.

## Reporting a vulnerability

Please **do not** report vulnerabilities through public issues, discussions or pull requests. Email:

**security@qore.network**

Include, as far as you can: a description and the impact, steps to reproduce or a proof of concept, the affected package (TypeScript, Rust, Go, Swift or Kotlin) and version, and a suggested fix.

Qualifying reports are eligible for the QoreChain bug bounty; scope and rules are published at <https://www.qorechain.io/security>.

## What to expect

- We acknowledge your report and keep you informed while we investigate.
- We coordinate disclosure with you once a fix is released.

## Supported versions

QoreSign is pre-1.0. Security fixes go into the latest minor version of each package.

## Cryptography

QoreSign implements no cryptographic primitive itself. ML-DSA-87 comes from the `qorechain-pqc` bindings (over `@noble/post-quantum`, `fips204` and Cloudflare CIRCL); secp256k1, hashes and BIP-32/39 come from `@noble/curves`, `@noble/hashes`, `@scure/*`, RustCrypto crates and `decred/secp256k1`. Issues in those libraries should also be reported upstream.
