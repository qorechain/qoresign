// SPDX-License-Identifier: Apache-2.0

import { base64, hex } from "@scure/base";
import { QoreSignError } from "./errors.js";

export const utf8Encode = (s: string): Uint8Array => new TextEncoder().encode(s);

export function toHex(b: Uint8Array): string {
  return hex.encode(b);
}

export function fromHex(s: string): Uint8Array {
  const clean = s.startsWith("0x") || s.startsWith("0X") ? s.slice(2) : s;
  try {
    return hex.decode(clean.toLowerCase());
  } catch {
    throw new QoreSignError("INVALID_ARGUMENT", "invalid hex string");
  }
}

export function toBase64(b: Uint8Array): string {
  return base64.encode(b);
}

export function fromBase64(s: string): Uint8Array {
  try {
    return base64.decode(s);
  } catch {
    throw new QoreSignError("INVALID_ARGUMENT", "invalid base64 string");
  }
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export function requireLength(b: Uint8Array, len: number, what: string): void {
  if (!(b instanceof Uint8Array) || b.length !== len) {
    throw new QoreSignError(
      "BAD_KEY_LENGTH",
      `${what} must be ${len} bytes, got ${b instanceof Uint8Array ? b.length : typeof b}`,
    );
  }
}
