// SPDX-License-Identifier: Apache-2.0
//
// Signing arbitrary messages (the `signArbitrary` of Keplr-compatible
// wallets): ADR-36 with the classical key, plus ML-DSA-87 over a
// domain-separated encoding. Format: spec/message-signing-v1.md.

import { base64 } from "@scure/base";
import { concat } from "./proto.js";
import { utf8Encode } from "./bytes.js";
import { QoreSignError } from "./errors.js";
import {
  ALGORITHM_ML_DSA_87,
  classicalKeyTypeFor,
  parseAddress,
  type ClassicalKey,
  type ClassicalKeyType,
  type PqKeyPair,
} from "./keys.js";
import { classicalSign, classicalVerify, pqSign, pqVerify } from "./sign.js";
import { adr36SignBytes } from "./siwq.js";

/** Domain prefix of the ML-DSA-87 part of a message signature. */
export const MESSAGE_PQ_DOMAIN = "qorechain-msg-v1|";

/**
 * Prefixes reserved for other ML-DSA-87 signatures on QoreChain. Every
 * off-chain signature QoreSign makes starts with its own domain, so it can
 * never be mistaken for one of these.
 */
export const RESERVED_PQ_DOMAINS: readonly string[] = Object.freeze([
  "qorechain-pqc-hybrid-v2",
  "qorechain-pqc-pop-v1|",
  "qorechain:pqc:recovery:v1",
  "qorechain-svm-auth-v2",
  "qorechain-siwq-v1|",
  MESSAGE_PQ_DOMAIN,
]);

function toBytes(data: Uint8Array | string): Uint8Array {
  return typeof data === "string" ? utf8Encode(data) : data;
}

function checkChainId(chainId: string): void {
  if (!/^[A-Za-z0-9._-]+$/.test(chainId)) {
    throw new QoreSignError("INVALID_ARGUMENT", `invalid chain id ${JSON.stringify(chainId)}`);
  }
}

/** The bytes the ML-DSA-87 key signs: `"qorechain-msg-v1|" + chainId + "|"` followed by the message. */
export function messagePqSignBytes(chainId: string, data: Uint8Array | string): Uint8Array {
  checkChainId(chainId);
  return concat(utf8Encode(`${MESSAGE_PQ_DOMAIN}${chainId}|`), toBytes(data));
}

export interface MessageSignature {
  /** `ml-dsa-87-hybrid` for both parts; `secp256k1` for a classical-only signature. */
  signatureType: "ml-dsa-87-hybrid" | "secp256k1";
  classical: {
    keyType: ClassicalKeyType;
    /** Base64 compressed public key. */
    publicKey: string;
    /** Base64 64-byte signature over the ADR-36 sign document of the message. */
    signature: string;
  };
  pq?: {
    algorithmId: number;
    /** Base64 ML-DSA-87 signature over {@link messagePqSignBytes}. */
    signature: string;
  };
}

/** Sign an arbitrary message with the account's keys. */
export function signMessage(args: {
  chainId: string;
  /** The `qor1` account signing. */
  signer: string;
  data: Uint8Array | string;
  classicalKey: ClassicalKey;
  pqKey?: Pick<PqKeyPair, "secretKey">;
  hedged?: boolean;
}): MessageSignature {
  const signer = parseAddress(args.signer).bech32;
  if (!classicalKeyTypeFor(args.classicalKey.publicKey, signer)) {
    throw new QoreSignError("ADDRESS_MISMATCH", `the classical key does not control ${signer}`);
  }
  const data = toBytes(args.data);
  const pqBytes = messagePqSignBytes(args.chainId, data);
  const classical = classicalSign(args.classicalKey, adr36SignBytes(signer, data));
  const out: MessageSignature = {
    signatureType: args.pqKey ? "ml-dsa-87-hybrid" : "secp256k1",
    classical: {
      keyType: args.classicalKey.type,
      publicKey: base64.encode(args.classicalKey.publicKey),
      signature: base64.encode(classical),
    },
  };
  if (args.pqKey) {
    out.pq = {
      algorithmId: ALGORITHM_ML_DSA_87,
      signature: base64.encode(pqSign(args.pqKey.secretKey, pqBytes, { hedged: args.hedged })),
    };
  }
  return out;
}

/**
 * Verify a message signature. Throws a {@link QoreSignError} unless the
 * classical key controls `signer`, its ADR-36 signature verifies and (unless
 * `requirePq` is false) the ML-DSA-87 signature verifies under `pqPublicKey`,
 * which should be the key registered on chain for `signer`.
 */
export function verifyMessage(args: {
  chainId: string;
  signer: string;
  data: Uint8Array | string;
  signature: MessageSignature;
  pqPublicKey?: Uint8Array;
  requirePq?: boolean;
}): void {
  const signer = parseAddress(args.signer).bech32;
  const data = toBytes(args.data);
  const pqBytes = messagePqSignBytes(args.chainId, data);
  const sig = args.signature;
  let pub: Uint8Array;
  let csig: Uint8Array;
  try {
    pub = base64.decode(sig.classical.publicKey);
    csig = base64.decode(sig.classical.signature);
  } catch {
    throw new QoreSignError("CLASSICAL_SIGNATURE_INVALID", "classical signature fields are not base64");
  }
  let owner: ClassicalKeyType | undefined;
  try {
    owner = classicalKeyTypeFor(pub, signer);
  } catch {
    owner = undefined;
  }
  if (owner === undefined || owner !== sig.classical.keyType) {
    throw new QoreSignError("ADDRESS_MISMATCH", `the classical key does not control ${signer}`);
  }
  if (!classicalVerify(owner, pub, adr36SignBytes(signer, data), csig)) {
    throw new QoreSignError("CLASSICAL_SIGNATURE_INVALID", "the classical signature does not verify");
  }
  if (!sig.pq) {
    if (args.requirePq ?? true) throw new QoreSignError("PQ_LAYER_MISSING", "the signature carries no ML-DSA-87 part");
    return;
  }
  if (sig.pq.algorithmId !== ALGORITHM_ML_DSA_87) {
    throw new QoreSignError("UNSUPPORTED_ALGORITHM", `unsupported algorithm ${sig.pq.algorithmId}`);
  }
  if (!args.pqPublicKey) throw new QoreSignError("KEY_NOT_REGISTERED", "pass the account's registered ML-DSA-87 public key");
  let pqSig: Uint8Array;
  try {
    pqSig = base64.decode(sig.pq.signature);
  } catch {
    throw new QoreSignError("PQ_SIGNATURE_INVALID", "ML-DSA-87 signature is not base64");
  }
  if (!pqVerify(args.pqPublicKey, pqBytes, pqSig)) {
    throw new QoreSignError("PQ_SIGNATURE_INVALID", "the ML-DSA-87 signature does not verify");
  }
}
