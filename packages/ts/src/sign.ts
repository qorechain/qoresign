// SPDX-License-Identifier: Apache-2.0
//
// Hybrid transaction signing for QoreChain's native (Cosmos SDK) lane.
//
// A hybrid transaction carries two signatures:
//  1. an ML-DSA-87 signature over the hybrid sign-bytes, attached to the
//     TxBody as the `/qorechain.pqc.v1.PQCHybridSignature` extension option;
//  2. the usual secp256k1 SIGN_MODE_DIRECT signature over the FINAL body (the
//     one that carries the extension), in `TxRaw.signatures`.
//
// Hybrid sign-bytes, where B0 is the body WITHOUT the PQC extension and A the
// auth-info bytes:
//   v1: BE32(len B0) || B0 || BE32(len A) || A
//   v2: "qorechain-pqc-hybrid-v2" || BE64(len chainId) || chainId || v1
// Both public networks verify v2 since their v3.1.98/v3.2.0 upgrades; v1 is
// only needed to reproduce signatures from before those heights.

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { hybridSignBytes as pqcHybridSignBytes, mldsa87 } from "@qorechain/pqc";
import { requireLength } from "./bytes.js";
import { QoreSignError } from "./errors.js";
import {
  ALGORITHM_ML_DSA_87,
  ML_DSA_87_PUBLIC_KEY_LENGTH,
  ML_DSA_87_SECRET_KEY_LENGTH,
  ML_DSA_87_SIGNATURE_LENGTH,
  type ClassicalKey,
  type ClassicalKeyType,
  type PqKeyPair,
} from "./keys.js";
import {
  appendExtension,
  bodyExtensions,
  concat,
  decodeTxRaw,
  encodeSignDoc,
  encodeTxRaw,
  lenField,
  readFields,
  stripExtension,
  varintField,
  WIRE_LEN,
  WIRE_VARINT,
} from "./proto.js";

export type SignBytesVersion = "v1" | "v2";

/** Type URL of the PQC extension option. */
export const PQC_HYBRID_TYPE_URL = "/qorechain.pqc.v1.PQCHybridSignature";

/** Hybrid sign-bytes for `bodyBytes` (the PQC extension is removed first if present). */
export function hybridSignBytes(args: {
  chainId: string;
  bodyBytes: Uint8Array;
  authInfoBytes: Uint8Array;
  signBytesVersion?: SignBytesVersion;
}): Uint8Array {
  const version = args.signBytesVersion ?? "v2";
  if (version !== "v1" && version !== "v2") {
    throw new QoreSignError("SIGN_BYTES_VERSION_UNKNOWN", `unknown sign-bytes version ${JSON.stringify(version)}`);
  }
  if (!args.chainId) throw new QoreSignError("INVALID_ARGUMENT", "chainId is required");
  const b0 = stripExtension(args.bodyBytes, PQC_HYBRID_TYPE_URL);
  return pqcHybridSignBytes(version, args.chainId, b0, args.authInfoBytes);
}

/** `qorechain.pqc.v1.PQCHybridSignature`. */
export interface PqcHybridSignature {
  algorithmId: number;
  signature: Uint8Array;
  /** Present only when the key is embedded for registration on first use. */
  publicKey?: Uint8Array;
}

export function encodePqcHybridSignature(sig: PqcHybridSignature): Uint8Array {
  return concat(
    varintField(1, sig.algorithmId),
    lenField(2, sig.signature),
    sig.publicKey ? lenField(3, sig.publicKey) : new Uint8Array(),
  );
}

export function decodePqcHybridSignature(bytes: Uint8Array): PqcHybridSignature {
  const out: PqcHybridSignature = { algorithmId: 0, signature: new Uint8Array() };
  for (const f of readFields(bytes)) {
    if (f.field === 1 && f.wireType === WIRE_VARINT) out.algorithmId = Number(f.varint);
    else if (f.field === 2 && f.wireType === WIRE_LEN && f.bytes) out.signature = f.bytes;
    else if (f.field === 3 && f.wireType === WIRE_LEN && f.bytes) out.publicKey = f.bytes;
  }
  return out;
}

/** The PQC layers attached to a body (a valid transaction has exactly one). */
export function pqcLayers(bodyBytes: Uint8Array): PqcHybridSignature[] {
  return bodyExtensions(bodyBytes)
    .filter((a) => a.typeUrl === PQC_HYBRID_TYPE_URL)
    .map((a) => decodePqcHybridSignature(a.value));
}

/** ML-DSA-87 signature. Deterministic unless `hedged` (the chain accepts both). */
export function pqSign(secretKey: Uint8Array, message: Uint8Array, opts: { hedged?: boolean } = {}): Uint8Array {
  requireLength(secretKey, ML_DSA_87_SECRET_KEY_LENGTH, "ML-DSA-87 secret key");
  return mldsa87.sign(secretKey, message, { hedged: opts.hedged === true });
}

/** ML-DSA-87 verification. Never throws on malformed input. */
export function pqVerify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  if (publicKey.length !== ML_DSA_87_PUBLIC_KEY_LENGTH || signature.length !== ML_DSA_87_SIGNATURE_LENGTH) {
    return false;
  }
  return mldsa87.verify(publicKey, message, signature);
}

function digest(type: ClassicalKeyType, msg: Uint8Array): Uint8Array {
  return type === "eth_secp256k1" ? keccak_256(msg) : sha256(msg);
}

/** 64-byte (r || s, low-S) secp256k1 signature over the key type's digest of `message`. */
export function classicalSign(key: Pick<ClassicalKey, "type" | "privateKey">, message: Uint8Array): Uint8Array {
  requireLength(key.privateKey, 32, "secp256k1 private key");
  return secp256k1.sign(digest(key.type, message), key.privateKey, { prehash: false, lowS: true, format: "compact" });
}

/** Verify a 64-byte secp256k1 signature. Never throws on malformed input. */
export function classicalVerify(
  type: ClassicalKeyType,
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (signature.length !== 64) return false;
  try {
    return secp256k1.verify(signature, digest(type, message), publicKey, { prehash: false, lowS: true, format: "compact" });
  } catch {
    return false;
  }
}

export interface SignPqLayerArgs {
  chainId: string;
  /** Body bytes as the dApp built them; an existing PQC layer is replaced. */
  bodyBytes: Uint8Array;
  authInfoBytes: Uint8Array;
  pqKey: Pick<PqKeyPair, "secretKey" | "publicKey">;
  signBytesVersion?: SignBytesVersion;
  /** Embed the public key so the chain can register it on first use. */
  includePublicKey?: boolean;
  hedged?: boolean;
}

/**
 * Add the ML-DSA-87 layer to a transaction body. Use this when the classical
 * signature is produced elsewhere (for example by a Keplr-compatible wallet's
 * `signDirect`): the classical signer must sign the returned `bodyBytes`.
 */
export function signPqLayer(args: SignPqLayerArgs): { bodyBytes: Uint8Array; pqSignature: Uint8Array } {
  const b0 = stripExtension(args.bodyBytes, PQC_HYBRID_TYPE_URL);
  const message = hybridSignBytes({
    chainId: args.chainId,
    bodyBytes: b0,
    authInfoBytes: args.authInfoBytes,
    signBytesVersion: args.signBytesVersion,
  });
  const pqSignature = pqSign(args.pqKey.secretKey, message, { hedged: args.hedged });
  const ext = encodePqcHybridSignature({
    algorithmId: ALGORITHM_ML_DSA_87,
    signature: pqSignature,
    publicKey: args.includePublicKey ? args.pqKey.publicKey : undefined,
  });
  return { bodyBytes: appendExtension(b0, { typeUrl: PQC_HYBRID_TYPE_URL, value: ext }), pqSignature };
}

/**
 * `hybrid` (default): ML-DSA-87 layer plus secp256k1. `classicalOnly`: no PQC
 * layer, for the transaction that registers the account's PQC key.
 * `pqOnly` is not accepted by the network for ordinary accounts and throws.
 */
export type SigningMode = "hybrid" | "classicalOnly" | "pqOnly";

export interface SignHybridArgs {
  chainId: string;
  accountNumber: bigint | number;
  bodyBytes: Uint8Array;
  authInfoBytes: Uint8Array;
  classicalKey: Pick<ClassicalKey, "type" | "privateKey">;
  pqKey?: Pick<PqKeyPair, "secretKey" | "publicKey">;
  mode?: SigningMode;
  signBytesVersion?: SignBytesVersion;
  includePublicKey?: boolean;
  hedged?: boolean;
}

export interface SignedTx {
  /** Encoded `TxRaw`, ready to broadcast. */
  txBytes: Uint8Array;
  bodyBytes: Uint8Array;
  authInfoBytes: Uint8Array;
  classicalSignature: Uint8Array;
  pqSignature?: Uint8Array;
}

/** Sign a native-lane transaction with both keys. */
export function signHybrid(args: SignHybridArgs): SignedTx {
  const mode = args.mode ?? "hybrid";
  if (mode !== "hybrid" && mode !== "classicalOnly" && mode !== "pqOnly") {
    throw new QoreSignError("INVALID_ARGUMENT", `unknown signing mode ${JSON.stringify(mode)}`);
  }
  if (mode === "pqOnly") {
    throw new QoreSignError(
      "LANE_NOT_AVAILABLE",
      "PQ-only transactions are not accepted for ordinary accounts; use the hybrid mode",
    );
  }
  let bodyBytes = stripExtension(args.bodyBytes, PQC_HYBRID_TYPE_URL);
  let pqSignature: Uint8Array | undefined;
  if (mode === "hybrid") {
    if (!args.pqKey) throw new QoreSignError("INVALID_ARGUMENT", "hybrid mode needs pqKey");
    const layered = signPqLayer({ ...args, pqKey: args.pqKey, bodyBytes });
    bodyBytes = layered.bodyBytes;
    pqSignature = layered.pqSignature;
  }
  const signDoc = encodeSignDoc({
    bodyBytes,
    authInfoBytes: args.authInfoBytes,
    chainId: args.chainId,
    accountNumber: args.accountNumber,
  });
  const classicalSignature = classicalSign(args.classicalKey, signDoc);
  const txBytes = encodeTxRaw({ bodyBytes, authInfoBytes: args.authInfoBytes, signatures: [classicalSignature] });
  return { txBytes, bodyBytes, authInfoBytes: args.authInfoBytes, classicalSignature, pqSignature };
}

export { decodeTxRaw, encodeTxRaw, encodeSignDoc };
