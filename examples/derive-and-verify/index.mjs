// SPDX-License-Identifier: Apache-2.0
// Derive keys, sign a hybrid transaction offline, verify it, then show that a
// changed fee breaks the ML-DSA-87 signature.
import {
  addressFromPublicKey,
  deriveCanonicalPqKey,
  deriveClassicalKey,
  signHybrid,
  verifyHybridTx,
  verifyPqLayer,
} from "@qorechain/qoresign";

// Public BIP-39 test phrase: never use it for funds.
const mnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const chainId = "qorechain-diana";

const classical = deriveClassicalKey({ mnemonic });
const address = addressFromPublicKey(classical.publicKey, "secp256k1").bech32;
const pq = deriveCanonicalPqKey({ mnemonic, address });
console.log("account     ", address);
console.log("ML-DSA-87 pk", `${pq.publicKey.length} bytes`);

// Minimal protobuf for the example: TxBody { memo } and AuthInfo { fee { gas_limit } }.
const enc = new TextEncoder();
const memo = enc.encode("hello from QoreChain");
const bodyBytes = Uint8Array.from([0x12, memo.length, ...memo]);
const authInfo = (gas) => Uint8Array.from([0x12, 0x03, 0x10, gas & 0x7f | 0x80, gas >> 7]);

const signed = signHybrid({
  chainId,
  accountNumber: 0,
  bodyBytes,
  authInfoBytes: authInfo(1000),
  classicalKey: classical,
  pqKey: pq,
});
console.log("tx bytes    ", signed.txBytes.length);

const check = verifyHybridTx({
  txBytes: signed.txBytes,
  chainId,
  accountNumber: 0,
  classicalPublicKey: classical.publicKey,
  pqPublicKey: pq.publicKey,
});
console.log("verified    ", check);

const tampered = verifyPqLayer({
  chainId,
  bodyBytes: signed.bodyBytes,
  authInfoBytes: authInfo(2000),
  pqPublicKey: pq.publicKey,
});
console.log("other fee   ", tampered);
