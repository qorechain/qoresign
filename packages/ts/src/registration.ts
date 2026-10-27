// SPDX-License-Identifier: Apache-2.0
//
// Registering an account's ML-DSA-87 key (MsgRegisterPQCKeyV2) with a proof
// of possession.

import { toHex, utf8Encode } from "./bytes.js";
import { QoreSignError } from "./errors.js";
import {
  ALGORITHM_ML_DSA_87,
  classicalKeyTypeFor,
  ML_DSA_87_PUBLIC_KEY_LENGTH,
  parseAddress,
  type PqKeyPair,
} from "./keys.js";
import { concat, lenField, stringField, varintField, type AnyMessage } from "./proto.js";
import { pqSign, pqVerify } from "./sign.js";

/** Domain of the proof-of-possession message. */
export const PROOF_OF_POSSESSION_DOMAIN = "qorechain-pqc-pop-v1";

export const MSG_REGISTER_PQC_KEY_V2_TYPE_URL = "/qorechain.pqc.v1.MsgRegisterPQCKeyV2";

/**
 * The message a key signs to prove possession:
 * `qorechain-pqc-pop-v1|<chain-id>|<algorithm-id>|<qor1 account>|<lowercase hex public key>`.
 */
export function proofOfPossessionMessage(args: {
  chainId: string;
  account: string;
  publicKey: Uint8Array;
  algorithmId?: number;
}): Uint8Array {
  if (!args.chainId) throw new QoreSignError("INVALID_ARGUMENT", "chainId is required");
  const account = parseAddress(args.account).bech32;
  const algorithmId = args.algorithmId ?? ALGORITHM_ML_DSA_87;
  return utf8Encode(
    `${PROOF_OF_POSSESSION_DOMAIN}|${args.chainId}|${algorithmId}|${account}|${toHex(args.publicKey)}`,
  );
}

export function signProofOfPossession(args: {
  chainId: string;
  account: string;
  pqKey: Pick<PqKeyPair, "publicKey" | "secretKey">;
  hedged?: boolean;
}): Uint8Array {
  const msg = proofOfPossessionMessage({ chainId: args.chainId, account: args.account, publicKey: args.pqKey.publicKey });
  return pqSign(args.pqKey.secretKey, msg, { hedged: args.hedged });
}

export function verifyProofOfPossession(args: {
  chainId: string;
  account: string;
  publicKey: Uint8Array;
  proof: Uint8Array;
}): boolean {
  return pqVerify(args.publicKey, proofOfPossessionMessage(args), args.proof);
}

/** A public key whose t1 part is all zero can be forged and is refused by the network. */
export function isDegeneratePqPublicKey(publicKey: Uint8Array): boolean {
  if (publicKey.length !== ML_DSA_87_PUBLIC_KEY_LENGTH) return false;
  for (let i = 32; i < publicKey.length; i++) if (publicKey[i] !== 0) return false;
  return true;
}

/**
 * Build `MsgRegisterPQCKeyV2` for `account`, with the proof of possession and
 * the compressed classical key the network checks against the address.
 * Sign the transaction that carries it in `classicalOnly` mode.
 */
export function buildRegisterPqKeyMessage(args: {
  chainId: string;
  account: string;
  pqKey: Pick<PqKeyPair, "publicKey" | "secretKey">;
  /** 33-byte compressed secp256k1 key of the account. */
  classicalPublicKey: Uint8Array;
  hedged?: boolean;
}): AnyMessage {
  const account = parseAddress(args.account).bech32;
  if (args.pqKey.publicKey.length !== ML_DSA_87_PUBLIC_KEY_LENGTH) {
    throw new QoreSignError("BAD_KEY_LENGTH", `ML-DSA-87 public key must be ${ML_DSA_87_PUBLIC_KEY_LENGTH} bytes`);
  }
  if (isDegeneratePqPublicKey(args.pqKey.publicKey)) {
    throw new QoreSignError("INVALID_ARGUMENT", "the public key's t1 part is all zero and would be forgeable");
  }
  if (!classicalKeyTypeFor(args.classicalPublicKey, account)) {
    throw new QoreSignError("ADDRESS_MISMATCH", `the classical public key does not control ${account}`);
  }
  const proof = signProofOfPossession({ chainId: args.chainId, account, pqKey: args.pqKey, hedged: args.hedged });
  const value = concat(
    stringField(1, account),
    lenField(2, args.pqKey.publicKey),
    varintField(3, ALGORITHM_ML_DSA_87),
    lenField(4, args.classicalPublicKey),
    stringField(5, "hybrid"),
    lenField(6, proof),
  );
  return { typeUrl: MSG_REGISTER_PQC_KEY_V2_TYPE_URL, value };
}
