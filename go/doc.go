// SPDX-License-Identifier: Apache-2.0

// Package qoresign implements hybrid secp256k1 + ML-DSA-87 (FIPS 204)
// signing and verification for QoreChain, and Sign In With QoreChain (SIWQ).
//
// Everything in this package works offline. The network sub-package talks to
// a QoreChain REST endpoint.
package qoresign
