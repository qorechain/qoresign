// SPDX-License-Identifier: Apache-2.0
//
// Local verification of hybrid transactions, the way the network checks them.

import { QoreSignError } from "./errors.js";
import { ALGORITHM_ML_DSA_87, type ClassicalKeyType } from "./keys.js";
import { decodeTxRaw, encodeSignDoc } from "./proto.js";
import {
  classicalVerify,
  hybridSignBytes,
  pqcLayers,
  pqVerify,
  type SignBytesVersion,
} from "./sign.js";

export interface VerifyPqLayerArgs {
  chainId: string;
  bodyBytes: Uint8Array;
  authInfoBytes: Uint8Array;
  /** The account's registered ML-DSA-87 public key. */
  pqPublicKey: Uint8Array;
  /** Default `"v2"`. `"either"` accepts a signature over v1 or v2 sign-bytes. */
  signBytesVersion?: SignBytesVersion | "either";
}

export interface PqLayerResult {
  valid: boolean;
  /** The sign-bytes version the signature verified under. */
  signBytesVersion?: SignBytesVersion;
  reason?: "missing" | "duplicated" | "unsupported_algorithm" | "embedded_key_mismatch" | "invalid_signature";
}

/**
 * Check the ML-DSA-87 layer of a body against a public key. A wallet should
 * run this before adding its classical signature to a body a dApp prepared:
 * a layer that does not verify protects nothing.
 */
export function verifyPqLayer(args: VerifyPqLayerArgs): PqLayerResult {
  const layers = pqcLayers(args.bodyBytes);
  if (layers.length === 0) return { valid: false, reason: "missing" };
  if (layers.length > 1) return { valid: false, reason: "duplicated" };
  const layer = layers[0]!;
  if (layer.algorithmId !== ALGORITHM_ML_DSA_87) return { valid: false, reason: "unsupported_algorithm" };
  if (layer.publicKey && layer.publicKey.length > 0) {
    const a = layer.publicKey;
    const b = args.pqPublicKey;
    if (a.length !== b.length || a.some((x, i) => x !== b[i])) return { valid: false, reason: "embedded_key_mismatch" };
  }
  const wanted = args.signBytesVersion ?? "v2";
  const versions: SignBytesVersion[] = wanted === "either" ? ["v2", "v1"] : [wanted];
  for (const version of versions) {
    const msg = hybridSignBytes({
      chainId: args.chainId,
      bodyBytes: args.bodyBytes,
      authInfoBytes: args.authInfoBytes,
      signBytesVersion: version,
    });
    if (pqVerify(args.pqPublicKey, msg, layer.signature)) return { valid: true, signBytesVersion: version };
  }
  return { valid: false, reason: "invalid_signature" };
}

export interface VerifyHybridTxArgs {
  /** Encoded `TxRaw`. */
  txBytes: Uint8Array;
  chainId: string;
  accountNumber: bigint | number;
  /** Compressed secp256k1 public key of the (single) signer. */
  classicalPublicKey: Uint8Array;
  classicalKeyType?: ClassicalKeyType;
  /** Registered ML-DSA-87 public key; omit to check the classical part only. */
  pqPublicKey?: Uint8Array;
  signBytesVersion?: SignBytesVersion | "either";
}

export interface HybridTxResult {
  /** True when every requested check passed. */
  valid: boolean;
  classical: boolean;
  /** `undefined` when no PQ key was supplied. */
  pq?: PqLayerResult;
}

/** Verify a single-signer hybrid transaction (both signatures). */
export function verifyHybridTx(args: VerifyHybridTxArgs): HybridTxResult {
  const tx = decodeTxRaw(args.txBytes);
  if (tx.signatures.length !== 1) {
    throw new QoreSignError("INVALID_ARGUMENT", `expected one signer, the transaction has ${tx.signatures.length}`);
  }
  const signDoc = encodeSignDoc({
    bodyBytes: tx.bodyBytes,
    authInfoBytes: tx.authInfoBytes,
    chainId: args.chainId,
    accountNumber: args.accountNumber,
  });
  const classical = classicalVerify(
    args.classicalKeyType ?? "secp256k1",
    args.classicalPublicKey,
    signDoc,
    tx.signatures[0]!,
  );
  if (!args.pqPublicKey) return { valid: classical, classical };
  const pq = verifyPqLayer({
    chainId: args.chainId,
    bodyBytes: tx.bodyBytes,
    authInfoBytes: tx.authInfoBytes,
    pqPublicKey: args.pqPublicKey,
    signBytesVersion: args.signBytesVersion,
  });
  return { valid: classical && pq.valid, classical, pq };
}
