// SPDX-License-Identifier: Apache-2.0
//
// @qorechain/qoresign: hybrid secp256k1 + ML-DSA-87 (FIPS 204) signing,
// verification and Sign In With QoreChain. Offline; network helpers live in
// `@qorechain/qoresign/network`.

export { QoreSignError, isQoreSignError, type QoreSignErrorCode } from "./errors.js";
export { toHex, fromHex, toBase64, fromBase64 } from "./bytes.js";
export {
  ACCOUNT_PREFIX,
  ALGORITHM_ML_DSA_87,
  CANONICAL_DERIVATION_DOMAIN,
  CLASSICAL_PATHS,
  HD_MASTER_KEY,
  ML_DSA_87_PUBLIC_KEY_LENGTH,
  ML_DSA_87_SECRET_KEY_LENGTH,
  ML_DSA_87_SEED_LENGTH,
  ML_DSA_87_SIGNATURE_LENGTH,
  addressFromBytes,
  addressFromPublicKey,
  classicalKeyFromPrivate,
  classicalKeyTypeFor,
  defaultHdPath,
  deriveCanonicalPqKey,
  deriveClassicalKey,
  deriveHdPqKey,
  parseAddress,
  pqKeyFromSeed,
  type AccountAddress,
  type ClassicalKey,
  type ClassicalKeyType,
  type PqKeyPair,
} from "./keys.js";
export {
  PQC_HYBRID_TYPE_URL,
  classicalSign,
  classicalVerify,
  decodePqcHybridSignature,
  decodeTxRaw,
  encodePqcHybridSignature,
  encodeSignDoc,
  encodeTxRaw,
  hybridSignBytes,
  pqcLayers,
  pqSign,
  pqVerify,
  signHybrid,
  signPqLayer,
  type PqcHybridSignature,
  type SignBytesVersion,
  type SignedTx,
  type SignHybridArgs,
  type SigningMode,
  type SignPqLayerArgs,
} from "./sign.js";
export {
  verifyHybridTx,
  verifyPqLayer,
  type HybridTxResult,
  type PqLayerResult,
  type VerifyHybridTxArgs,
  type VerifyPqLayerArgs,
} from "./verify.js";
export {
  MSG_REGISTER_PQC_KEY_V2_TYPE_URL,
  PROOF_OF_POSSESSION_DOMAIN,
  buildRegisterPqKeyMessage,
  isDegeneratePqPublicKey,
  proofOfPossessionMessage,
  signProofOfPossession,
  verifyProofOfPossession,
} from "./registration.js";
export {
  SIWQ_PQ_DOMAIN,
  adr36SignBytes,
  createSiwqMessage,
  parseSiwqMessage,
  signSiwq,
  siwqPqSignBytes,
  verifySiwq,
  type SiwqFields,
  type SiwqSignature,
  type VerifySiwqArgs,
} from "./siwq.js";
export {
  LANE_SUPPORT,
  assertHybridLane,
  decideLane,
  evaluateLayerState,
  type Lane,
  type LaneDecision,
  type LaneRequest,
  type LayerState,
} from "./lanes.js";
export {
  appendExtension,
  decodeAny,
  encodeAny,
  stripExtension,
  type AnyMessage,
  type TxRawParts,
} from "./proto.js";
