// SPDX-License-Identifier: Apache-2.0
//
// The sign-bytes version option of the checks against a registered key.

import { QoreSignError } from "./errors.js";
import type { SignBytesVersion } from "./sign.js";

/** How a check against the registered key picks the sign-bytes version. */
export interface PqLayerVersionOptions {
  /**
   * The one version the layer is checked against. Omitted, it is resolved
   * from the network (`resolveSignBytesVersion`).
   */
  signBytesVersion?: SignBytesVersion;
  /**
   * Accept a layer over v1 or v2 sign-bytes, whatever the network verifies.
   * For diagnostics only, never for trust decisions: v1 sign-bytes are not
   * bound to a chain id, and the network accepts exactly one version.
   */
  allowLegacyEither?: boolean;
}

/**
 * The version a check asks for: "either" when opted in, the given version, or
 * `undefined` to resolve it from the network. Throws on an invalid option.
 */
export function pqLayerVersionOption(opts: PqLayerVersionOptions): SignBytesVersion | "either" | undefined {
  if (opts.allowLegacyEither === true) return "either";
  const wanted = opts.signBytesVersion as string | undefined;
  if (wanted === "either") {
    throw new QoreSignError("INVALID_ARGUMENT", 'signBytesVersion "either" needs allowLegacyEither (diagnostics only)');
  }
  if (wanted !== undefined && wanted !== "v1" && wanted !== "v2") {
    throw new QoreSignError("INVALID_ARGUMENT", `unknown sign-bytes version ${JSON.stringify(wanted)}`);
  }
  return wanted;
}
