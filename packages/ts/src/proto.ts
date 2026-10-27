// SPDX-License-Identifier: Apache-2.0
//
// Minimal protobuf wire handling for the handful of Cosmos SDK messages
// QoreSign touches (TxRaw, TxBody, Any, SignDoc, PQCHybridSignature).
//
// The signer never re-encodes a message it did not build: TxBody bytes are
// edited at the top level only (one field appended or removed), so every other
// field keeps the exact bytes the caller supplied.

import { QoreSignError } from "./errors.js";

export const WIRE_VARINT = 0;
export const WIRE_FIXED64 = 1;
export const WIRE_LEN = 2;
export const WIRE_FIXED32 = 5;

/** One top-level field of an encoded message, with its raw bytes. */
export interface RawField {
  field: number;
  wireType: number;
  /** The complete encoding of this field (tag + payload). */
  raw: Uint8Array;
  /** Payload for length-delimited fields. */
  bytes?: Uint8Array;
  /** Value for varint fields. */
  varint?: bigint;
}

function readVarint(buf: Uint8Array, pos: number): [bigint, number] {
  let result = 0n;
  let shift = 0n;
  for (let i = 0; i < 10; i++) {
    if (pos >= buf.length) throw malformed("truncated varint");
    const b = buf[pos++]!;
    result |= BigInt(b & 0x7f) << shift;
    if ((b & 0x80) === 0) return [result, pos];
    shift += 7n;
  }
  throw malformed("varint longer than 10 bytes");
}

function malformed(detail: string): QoreSignError {
  return new QoreSignError("MALFORMED_PROTOBUF", `malformed protobuf: ${detail}`);
}

/** Split an encoded message into its top-level fields, in order. */
export function readFields(buf: Uint8Array): RawField[] {
  const out: RawField[] = [];
  let pos = 0;
  while (pos < buf.length) {
    const start = pos;
    const [tag, afterTag] = readVarint(buf, pos);
    pos = afterTag;
    const field = Number(tag >> 3n);
    const wireType = Number(tag & 7n);
    if (field === 0) throw malformed("field number 0");
    const entry: RawField = { field, wireType, raw: new Uint8Array() };
    switch (wireType) {
      case WIRE_VARINT: {
        const [v, next] = readVarint(buf, pos);
        entry.varint = v;
        pos = next;
        break;
      }
      case WIRE_FIXED64:
        pos += 8;
        break;
      case WIRE_FIXED32:
        pos += 4;
        break;
      case WIRE_LEN: {
        const [len, next] = readVarint(buf, pos);
        const end = next + Number(len);
        if (end > buf.length) throw malformed("length-delimited field runs past the end");
        entry.bytes = buf.subarray(next, end);
        pos = end;
        break;
      }
      default:
        throw malformed(`unsupported wire type ${wireType}`);
    }
    if (pos > buf.length) throw malformed("field runs past the end");
    entry.raw = buf.subarray(start, pos);
    out.push(entry);
  }
  return out;
}

export function encodeVarint(value: number | bigint): Uint8Array {
  let v = BigInt(value);
  if (v < 0n) throw new QoreSignError("INVALID_ARGUMENT", "negative varint");
  const out: number[] = [];
  do {
    let b = Number(v & 0x7fn);
    v >>= 7n;
    if (v !== 0n) b |= 0x80;
    out.push(b);
  } while (v !== 0n);
  return Uint8Array.from(out);
}

function tag(field: number, wireType: number): Uint8Array {
  return encodeVarint((BigInt(field) << 3n) | BigInt(wireType));
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Encode a length-delimited field. Empty payloads are omitted (proto3). */
export function lenField(field: number, payload: Uint8Array): Uint8Array {
  if (payload.length === 0) return new Uint8Array();
  return concat(tag(field, WIRE_LEN), encodeVarint(payload.length), payload);
}

/** Encode a varint field. Zero is omitted (proto3). */
export function varintField(field: number, value: number | bigint): Uint8Array {
  if (BigInt(value) === 0n) return new Uint8Array();
  return concat(tag(field, WIRE_VARINT), encodeVarint(value));
}

const utf8 = new TextEncoder();
const utf8d = new TextDecoder("utf-8", { fatal: true });

export function stringField(field: number, value: string): Uint8Array {
  return lenField(field, utf8.encode(value));
}

/** `google.protobuf.Any`. */
export interface AnyMessage {
  typeUrl: string;
  value: Uint8Array;
}

export function encodeAny(any: AnyMessage): Uint8Array {
  return concat(stringField(1, any.typeUrl), lenField(2, any.value));
}

export function decodeAny(buf: Uint8Array): AnyMessage {
  let typeUrl = "";
  let value: Uint8Array = new Uint8Array();
  for (const f of readFields(buf)) {
    if (f.field === 1 && f.bytes) typeUrl = decodeString(f.bytes);
    else if (f.field === 2 && f.bytes) value = f.bytes;
  }
  return { typeUrl, value };
}

export function decodeString(bytes: Uint8Array): string {
  try {
    return utf8d.decode(bytes);
  } catch {
    throw malformed("invalid UTF-8 in a string field");
  }
}

/** `cosmos.tx.v1beta1.TxRaw`. */
export interface TxRawParts {
  bodyBytes: Uint8Array;
  authInfoBytes: Uint8Array;
  signatures: Uint8Array[];
}

export function encodeTxRaw(tx: TxRawParts): Uint8Array {
  const sigs = tx.signatures.map((s) =>
    // repeated bytes keeps empty entries, so encode them explicitly
    concat(tag(3, WIRE_LEN), encodeVarint(s.length), s),
  );
  return concat(lenField(1, tx.bodyBytes), lenField(2, tx.authInfoBytes), ...sigs);
}

export function decodeTxRaw(buf: Uint8Array): TxRawParts {
  const out: TxRawParts = {
    bodyBytes: new Uint8Array(),
    authInfoBytes: new Uint8Array(),
    signatures: [],
  };
  for (const f of readFields(buf)) {
    if (f.wireType !== WIRE_LEN || !f.bytes) continue;
    if (f.field === 1) out.bodyBytes = f.bytes;
    else if (f.field === 2) out.authInfoBytes = f.bytes;
    else if (f.field === 3) out.signatures.push(f.bytes);
  }
  return out;
}

/** `cosmos.tx.v1beta1.SignDoc` (SIGN_MODE_DIRECT). */
export function encodeSignDoc(doc: {
  bodyBytes: Uint8Array;
  authInfoBytes: Uint8Array;
  chainId: string;
  accountNumber: bigint | number;
}): Uint8Array {
  return concat(
    lenField(1, doc.bodyBytes),
    lenField(2, doc.authInfoBytes),
    stringField(3, doc.chainId),
    varintField(4, doc.accountNumber),
  );
}

/** TxBody field numbers. */
export const TXBODY_EXTENSION_OPTIONS = 1023;
export const TXBODY_NON_CRITICAL_EXTENSION_OPTIONS = 2047;

/** Extension options (`Any`) carried by a TxBody, in order. */
export function bodyExtensions(bodyBytes: Uint8Array): AnyMessage[] {
  return readFields(bodyBytes)
    .filter((f) => f.field === TXBODY_EXTENSION_OPTIONS && f.wireType === WIRE_LEN && f.bytes)
    .map((f) => decodeAny(f.bytes!));
}

/** Remove every extension option whose type URL is `typeUrl`. */
export function stripExtension(bodyBytes: Uint8Array, typeUrl: string): Uint8Array {
  const kept = readFields(bodyBytes).filter(
    (f) =>
      !(
        f.field === TXBODY_EXTENSION_OPTIONS &&
        f.wireType === WIRE_LEN &&
        f.bytes &&
        decodeAny(f.bytes).typeUrl === typeUrl
      ),
  );
  return concat(...kept.map((f) => f.raw));
}

/**
 * Add an extension option in canonical field order: after the existing
 * extension options and before any non-critical extension options.
 */
export function appendExtension(bodyBytes: Uint8Array, any: AnyMessage): Uint8Array {
  const fields = readFields(bodyBytes);
  const encoded = lenField(TXBODY_EXTENSION_OPTIONS, encodeAny(any));
  const at = fields.findIndex((f) => f.field > TXBODY_EXTENSION_OPTIONS);
  const before = at === -1 ? fields : fields.slice(0, at);
  const after = at === -1 ? [] : fields.slice(at);
  return concat(...before.map((f) => f.raw), encoded, ...after.map((f) => f.raw));
}
