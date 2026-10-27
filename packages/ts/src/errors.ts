// SPDX-License-Identifier: Apache-2.0

/** Stable error codes. New codes may be added; existing ones never change meaning. */
export type QoreSignErrorCode =
  | "INVALID_ARGUMENT"
  | "INVALID_MNEMONIC"
  | "INVALID_ADDRESS"
  | "ADDRESS_MISMATCH"
  | "HD_NON_HARDENED"
  | "HD_INVALID_PATH"
  | "BAD_KEY_LENGTH"
  | "MALFORMED_PROTOBUF"
  | "SIGN_BYTES_VERSION_UNKNOWN"
  | "PQ_LAYER_MISSING"
  | "PQ_LAYER_DUPLICATED"
  | "PQ_SIGNATURE_INVALID"
  | "CLASSICAL_SIGNATURE_INVALID"
  | "UNSUPPORTED_ALGORITHM"
  | "SIWQ_MALFORMED"
  | "SIWQ_EXPIRED"
  | "SIWQ_NOT_YET_VALID"
  | "SIWQ_DOMAIN_MISMATCH"
  | "SIWQ_NONCE_MISMATCH"
  | "SIWQ_CHAIN_MISMATCH"
  | "KEY_NOT_REGISTERED"
  | "KEY_MISMATCH"
  | "LANE_NOT_AVAILABLE"
  | "NETWORK_UNAVAILABLE"
  | "SIMULATION_FAILED";

/** Every error QoreSign throws on purpose. */
export class QoreSignError extends Error {
  readonly code: QoreSignErrorCode;
  readonly details?: Record<string, unknown>;

  constructor(code: QoreSignErrorCode, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = "QoreSignError";
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

/**
 * True when `err` is a {@link QoreSignError}, optionally with the given code.
 * Checks the name and code rather than the prototype, so errors from another
 * copy of the package (or the other entry point's bundle) are recognized too.
 */
export function isQoreSignError(err: unknown, code?: QoreSignErrorCode): err is QoreSignError {
  if (!(err instanceof Error) || err.name !== "QoreSignError") return false;
  const c = (err as { code?: unknown }).code;
  return typeof c === "string" && (code === undefined || c === code);
}
