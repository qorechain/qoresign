// SPDX-License-Identifier: Apache-2.0
//
// Regenerates vectors/qoresign-v1.json from the TypeScript reference
// implementation. Every other language checks itself against this file.
// Run after `pnpm build`: node scripts/gen-vectors.mjs

import { writeFileSync } from "node:fs";
import { sha256 } from "@noble/hashes/sha2.js";
import * as qs from "../packages/ts/dist/index.js";

const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const CHAIN_ID = "qorechain-diana";
const hex = qs.toHex;

// Hand-encoded protobuf so the vectors do not depend on any codegen:
// TxBody { messages: [MsgSend], memo }
function field(n, payload) {
  return Uint8Array.from([...varint((n << 3) | 2), ...varint(payload.length), ...payload]);
}
function varint(v) {
  const out = [];
  do {
    let b = v & 0x7f;
    v = Math.floor(v / 128);
    if (v) b |= 0x80;
    out.push(b);
  } while (v);
  return out;
}
const enc = (s) => new TextEncoder().encode(s);
const cat = (...p) => Uint8Array.from(p.flatMap((x) => [...x]));

function msgSend(from, to, amount) {
  const coin = cat(field(1, enc("uqor")), field(2, enc(amount)));
  return cat(field(1, enc(from)), field(2, enc(to)), field(3, coin));
}
function txBody(messages, memo) {
  return cat(...messages.map((m) => field(1, qs.encodeAny(m))), memo ? field(2, enc(memo)) : new Uint8Array());
}
function authInfo(pubkey, sequence, feeAmount, gasLimit) {
  const pkAny = qs.encodeAny({ typeUrl: "/cosmos.crypto.secp256k1.PubKey", value: field(1, pubkey) });
  // ModeInfo { single { mode: SIGN_MODE_DIRECT (1) } }
  const modeInfo = field(1, Uint8Array.from([0x08, 0x01]));
  const signerInfo = cat(field(1, pkAny), field(2, modeInfo), sequence ? Uint8Array.from([0x18, ...varint(sequence)]) : []);
  const coin = cat(field(1, enc("uqor")), field(2, enc(feeAmount)));
  const fee = cat(field(1, coin), Uint8Array.from([0x10, ...varint(gasLimit)]));
  return cat(field(1, signerInfo), field(2, fee));
}

const classical = qs.deriveClassicalKey({ mnemonic: MNEMONIC });
const eth = qs.deriveClassicalKey({ mnemonic: MNEMONIC, type: "eth_secp256k1" });
const addr = qs.addressFromPublicKey(classical.publicKey, "secp256k1");
const ethAddr = qs.addressFromPublicKey(eth.publicKey, "eth_secp256k1");
const pq = qs.deriveCanonicalPqKey({ mnemonic: MNEMONIC, address: addr.bech32 });
const ethPq = qs.deriveCanonicalPqKey({ mnemonic: MNEMONIC, address: ethAddr.bech32 });

const bodyBytes = txBody([{ typeUrl: "/cosmos.bank.v1beta1.MsgSend", value: msgSend(addr.bech32, addr.bech32, "1") }], "qoresign vector");
const authInfoBytes = authInfo(classical.publicKey, 3, "50000", 500000);

const pk = (k) => ({ publicKey: hex(k.publicKey), publicKeySha256: hex(sha256(k.publicKey)) });

const tx = (version) => {
  const signed = qs.signHybrid({
    chainId: CHAIN_ID,
    accountNumber: 7,
    bodyBytes,
    authInfoBytes,
    classicalKey: classical,
    pqKey: pq,
    signBytesVersion: version,
  });
  return {
    signBytesVersion: version,
    signBytes: hex(qs.hybridSignBytes({ chainId: CHAIN_ID, bodyBytes, authInfoBytes, signBytesVersion: version })),
    pqSignature: hex(signed.pqSignature),
    signedBodyBytes: hex(signed.bodyBytes),
    classicalSignature: hex(signed.classicalSignature),
    txBytes: hex(signed.txBytes),
  };
};

const siwqFields = {
  scheme: "https",
  domain: "app.example.com",
  address: addr.bech32,
  statement: "Sign in to the example app.",
  uri: "https://app.example.com/login",
  chainId: CHAIN_ID,
  nonce: "a1b2c3d4e5",
  issuedAt: "2026-10-27T10:00:00Z",
  expirationTime: "2026-10-27T10:10:00Z",
  resources: ["https://app.example.com/terms"],
};
const siwqMessage = qs.createSiwqMessage(siwqFields);
const register = qs.buildRegisterPqKeyMessage({ chainId: CHAIN_ID, account: addr.bech32, pqKey: pq, classicalPublicKey: classical.publicKey });

const hdPaths = ["m/44'/118'/0'/0'/0'", "m/44'/118'/1'/0'/0'", "m/44'/60'/0'/0'/0'"];

const vectors = {
  format: "qoresign-vectors-v1",
  description:
    "Test vectors for QoreSign. Every key here is derived from the public BIP-39 test mnemonic and must never hold funds. ML-DSA-87 signatures are deterministic (FIPS 204, rnd = 32 zero bytes).",
  mnemonic: MNEMONIC,
  chainId: CHAIN_ID,
  accounts: {
    secp256k1: {
      path: "m/44'/118'/0'/0/0",
      privateKey: hex(classical.privateKey),
      publicKey: hex(classical.publicKey),
      address: addr.bech32,
      hex: addr.hex,
    },
    eth_secp256k1: {
      path: "m/44'/60'/0'/0/0",
      privateKey: hex(eth.privateKey),
      publicKey: hex(eth.publicKey),
      address: ethAddr.bech32,
      hex: ethAddr.hex,
    },
  },
  canonical: [
    { address: addr.bech32, ...pk(pq) },
    { address: ethAddr.bech32, ...pk(ethPq) },
  ],
  hd: hdPaths.map((path) => ({ path, ...pk(qs.deriveHdPqKey({ mnemonic: MNEMONIC, path })) })),
  hdRejected: ["m/44'/118'/0'/0/0", "44'/118'/0'", "m/44'/x'"],
  hybridTx: {
    accountNumber: 7,
    bodyBytes: hex(bodyBytes),
    authInfoBytes: hex(authInfoBytes),
    cases: [tx("v2"), tx("v1")],
  },
  proofOfPossession: {
    account: addr.bech32,
    message: new TextDecoder().decode(qs.proofOfPossessionMessage({ chainId: CHAIN_ID, account: addr.bech32, publicKey: pq.publicKey })),
    signature: hex(qs.signProofOfPossession({ chainId: CHAIN_ID, account: addr.bech32, pqKey: pq })),
  },
  registerMessage: { typeUrl: register.typeUrl, value: hex(register.value) },
  siwq: {
    fields: siwqFields,
    message: siwqMessage,
    adr36SignBytes: hex(qs.adr36SignBytes(addr.bech32, enc(siwqMessage))),
    pqSignBytes: hex(qs.siwqPqSignBytes(siwqMessage)),
    signature: qs.signSiwq({ message: siwqMessage, classicalKey: classical, pqKey: pq }),
    verifyAt: "2026-10-27T10:01:00Z",
  },
};

writeFileSync(new URL("../vectors/qoresign-v1.json", import.meta.url), JSON.stringify(vectors, null, 2) + "\n");
console.log("wrote vectors/qoresign-v1.json");
