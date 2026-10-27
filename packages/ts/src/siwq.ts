// SPDX-License-Identifier: Apache-2.0
//
// Sign In With QoreChain (SIWQ): EIP-4361 / SIWS-style sign-in messages,
// signed with the account's classical key (ADR-36, so any Keplr-compatible
// wallet can produce that part) and with its ML-DSA-87 key.
// Format: spec/siwq-v1.md.

import { base64 } from "@scure/base";
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

/** Domain prefix of the ML-DSA-87 part of a SIWQ signature. */
export const SIWQ_PQ_DOMAIN = "qorechain-siwq-v1|";
const HEADER = " wants you to sign in with your QoreChain account:";

export interface SiwqFields {
  /** RFC 3986 authority requesting the sign-in, e.g. `app.example.com`. */
  domain: string;
  /** Optional scheme, e.g. `https`. */
  scheme?: string;
  /** `qor1...` account. */
  address: string;
  statement?: string;
  uri: string;
  version?: "1";
  /** Chain id, e.g. `qorechain-vladi`. */
  chainId: string;
  /** At least 8 alphanumeric characters, chosen by the server. */
  nonce: string;
  /** ISO 8601 timestamp. */
  issuedAt: string;
  expirationTime?: string;
  notBefore?: string;
  requestId?: string;
  resources?: string[];
}

function check(cond: boolean, msg: string): void {
  if (!cond) throw new QoreSignError("SIWQ_MALFORMED", msg);
}

const ISO = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

/** RFC 3339 timestamp with a real calendar date and time. */
function isTimestamp(s: string): boolean {
  const m = ISO.exec(s);
  if (!m) return false;
  const [y, mo, d, h, mi, se] = m.slice(1, 7).map(Number) as [number, number, number, number, number, number];
  if (mo < 1 || mo > 12 || h > 23 || mi > 59 || se > 59) return false;
  const daysInMonth = new Date(Date.UTC(y, mo, 0)).getUTCDate();
  return d >= 1 && d <= daysInMonth && !Number.isNaN(Date.parse(s));
}

function validate(f: SiwqFields): void {
  check(/^[^\s/]+$/.test(f.domain), "domain must be a host (and optional port) without spaces or slashes");
  check(f.scheme === undefined || /^[a-zA-Z][a-zA-Z0-9+.-]*$/.test(f.scheme), "invalid scheme");
  parseAddress(f.address);
  check(f.address.startsWith("qor1"), "address must be the bech32 qor1 form");
  check(f.statement === undefined || (f.statement !== "" && !f.statement.includes("\n")), "statement must be a non-empty single line");
  check(/^[a-zA-Z][a-zA-Z0-9+.-]*:\S+$/.test(f.uri), "uri must be an absolute URI");
  check((f.version ?? "1") === "1", "version must be 1");
  check(/^[A-Za-z0-9._-]+$/.test(f.chainId), "invalid chain id");
  check(/^[A-Za-z0-9]{8,}$/.test(f.nonce), "nonce must be at least 8 alphanumeric characters");
  check(isTimestamp(f.issuedAt), "issuedAt must be ISO 8601");
  check(f.expirationTime === undefined || isTimestamp(f.expirationTime), "expirationTime must be ISO 8601");
  check(f.notBefore === undefined || isTimestamp(f.notBefore), "notBefore must be ISO 8601");
  check(f.requestId === undefined || (f.requestId !== "" && !f.requestId.includes("\n")), "requestId must be a non-empty single line");
  for (const r of f.resources ?? []) check(/^[a-zA-Z][a-zA-Z0-9+.-]*:\S+$/.test(r), "resources must be URIs");
}

/** Render the sign-in message text. */
export function createSiwqMessage(fields: SiwqFields): string {
  validate(fields);
  const lines: string[] = [];
  lines.push(`${fields.scheme ? `${fields.scheme}://` : ""}${fields.domain}${HEADER}`);
  lines.push(fields.address);
  lines.push("");
  if (fields.statement !== undefined) lines.push(fields.statement);
  lines.push("");
  lines.push(`URI: ${fields.uri}`);
  lines.push(`Version: ${fields.version ?? "1"}`);
  lines.push(`Chain ID: ${fields.chainId}`);
  lines.push(`Nonce: ${fields.nonce}`);
  lines.push(`Issued At: ${fields.issuedAt}`);
  if (fields.expirationTime !== undefined) lines.push(`Expiration Time: ${fields.expirationTime}`);
  if (fields.notBefore !== undefined) lines.push(`Not Before: ${fields.notBefore}`);
  if (fields.requestId !== undefined) lines.push(`Request ID: ${fields.requestId}`);
  if (fields.resources && fields.resources.length > 0) {
    lines.push("Resources:");
    for (const r of fields.resources) lines.push(`- ${r}`);
  }
  return lines.join("\n");
}

/** Parse a sign-in message. The result re-renders to exactly the same text. */
export function parseSiwqMessage(text: string): SiwqFields {
  const lines = text.split("\n");
  let i = 0;
  const header = lines[i++] ?? "";
  check(header.endsWith(HEADER), "missing SIWQ header line");
  let origin = header.slice(0, -HEADER.length);
  let scheme: string | undefined;
  const sep = origin.indexOf("://");
  if (sep !== -1) {
    scheme = origin.slice(0, sep);
    origin = origin.slice(sep + 3);
  }
  const address = lines[i++] ?? "";
  check(lines[i++] === "", "expected an empty line after the address");
  let statement: string | undefined;
  if (lines[i] !== "") {
    statement = lines[i++];
  }
  check(lines[i++] === "", "expected an empty line before the fields");
  const take = (label: string, optional = false): string | undefined => {
    const line = lines[i];
    if (line !== undefined && line.startsWith(`${label}: `)) {
      i++;
      return line.slice(label.length + 2);
    }
    check(optional, `missing "${label}"`);
    return undefined;
  };
  const uri = take("URI")!;
  const version = take("Version")!;
  const chainId = take("Chain ID")!;
  const nonce = take("Nonce")!;
  const issuedAt = take("Issued At")!;
  const expirationTime = take("Expiration Time", true);
  const notBefore = take("Not Before", true);
  const requestId = take("Request ID", true);
  let resources: string[] | undefined;
  if (lines[i] === "Resources:") {
    i++;
    resources = [];
    while (i < lines.length && lines[i]!.startsWith("- ")) resources.push(lines[i++]!.slice(2));
  }
  check(i === lines.length, "unexpected trailing content");
  check(version === "1", "version must be 1");
  const fields: SiwqFields = { domain: origin, address, uri, version: "1", chainId, nonce, issuedAt };
  if (scheme !== undefined) fields.scheme = scheme;
  if (statement !== undefined) fields.statement = statement;
  if (expirationTime !== undefined) fields.expirationTime = expirationTime;
  if (notBefore !== undefined) fields.notBefore = notBefore;
  if (requestId !== undefined) fields.requestId = requestId;
  if (resources !== undefined) fields.resources = resources;
  validate(fields);
  check(createSiwqMessage(fields) === text, "message is not in canonical form");
  return fields;
}

/**
 * ADR-36 sign document for arbitrary data, as Keplr-compatible wallets build
 * it for `signArbitrary`, serialized with sorted keys and no whitespace.
 */
export function adr36SignBytes(signer: string, data: Uint8Array): Uint8Array {
  const doc =
    `{"account_number":"0","chain_id":"","fee":{"amount":[],"gas":"0"},"memo":"",` +
    `"msgs":[{"type":"sign/MsgSignData","value":{"data":"${base64.encode(data)}","signer":"${signer}"}}],` +
    `"sequence":"0"}`;
  return utf8Encode(doc);
}

/** The bytes the ML-DSA-87 key signs for a sign-in message. */
export function siwqPqSignBytes(message: string): Uint8Array {
  return utf8Encode(SIWQ_PQ_DOMAIN + message);
}

export interface SiwqSignature {
  /** `ml-dsa-87-hybrid` for both parts; `secp256k1` for a classical-only sign-in. */
  signatureType: "ml-dsa-87-hybrid" | "secp256k1";
  classical: {
    keyType: ClassicalKeyType;
    /** Base64 compressed public key. */
    publicKey: string;
    /** Base64 64-byte signature over the ADR-36 sign document. */
    signature: string;
  };
  pq?: {
    algorithmId: number;
    /** Base64 ML-DSA-87 signature over `"qorechain-siwq-v1|" + message`. */
    signature: string;
  };
}

/** Sign a sign-in message with the account's keys. */
export function signSiwq(args: {
  message: string;
  classicalKey: ClassicalKey;
  pqKey?: Pick<PqKeyPair, "secretKey">;
  hedged?: boolean;
}): SiwqSignature {
  const fields = parseSiwqMessage(args.message);
  if (!classicalKeyTypeFor(args.classicalKey.publicKey, fields.address)) {
    throw new QoreSignError("ADDRESS_MISMATCH", `the classical key does not control ${fields.address}`);
  }
  const classical = classicalSign(args.classicalKey, adr36SignBytes(fields.address, utf8Encode(args.message)));
  const out: SiwqSignature = {
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
      signature: base64.encode(pqSign(args.pqKey.secretKey, siwqPqSignBytes(args.message), { hedged: args.hedged })),
    };
  }
  return out;
}

export interface VerifySiwqArgs {
  message: string;
  signature: SiwqSignature;
  /** The domain the server expects (the request's host). */
  domain: string;
  /** The nonce the server issued for this sign-in. */
  nonce: string;
  /** Expected chain id; checked when set. */
  chainId?: string;
  /** The account's registered ML-DSA-87 public key. Required unless `requirePq` is false. */
  pqPublicKey?: Uint8Array;
  /** Default true: a classical-only sign-in is refused. */
  requirePq?: boolean;
  /** Defaults to the current time. */
  now?: Date;
  /** Allowed clock skew for `issuedAt` and `notBefore`, in seconds. Default 60. */
  clockSkewSeconds?: number;
}

/** Verify a sign-in. Returns the parsed fields; throws a {@link QoreSignError} otherwise. */
export function verifySiwq(args: VerifySiwqArgs): SiwqFields {
  const fields = parseSiwqMessage(args.message);
  if (fields.domain !== args.domain) {
    throw new QoreSignError("SIWQ_DOMAIN_MISMATCH", `message is for ${fields.domain}, expected ${args.domain}`);
  }
  if (fields.nonce !== args.nonce) throw new QoreSignError("SIWQ_NONCE_MISMATCH", "nonce does not match");
  if (args.chainId !== undefined && fields.chainId !== args.chainId) {
    throw new QoreSignError("SIWQ_CHAIN_MISMATCH", `message is for ${fields.chainId}, expected ${args.chainId}`);
  }
  const now = (args.now ?? new Date()).getTime();
  const skew = (args.clockSkewSeconds ?? 60) * 1000;
  if (fields.expirationTime !== undefined && Date.parse(fields.expirationTime) <= now) {
    throw new QoreSignError("SIWQ_EXPIRED", "the sign-in message has expired");
  }
  if (fields.notBefore !== undefined && Date.parse(fields.notBefore) > now + skew) {
    throw new QoreSignError("SIWQ_NOT_YET_VALID", "the sign-in message is not valid yet");
  }
  if (Date.parse(fields.issuedAt) > now + skew) {
    throw new QoreSignError("SIWQ_NOT_YET_VALID", "issuedAt is in the future");
  }

  const sig = args.signature;
  let classicalPub: Uint8Array;
  let classicalSig: Uint8Array;
  try {
    classicalPub = base64.decode(sig.classical.publicKey);
    classicalSig = base64.decode(sig.classical.signature);
  } catch {
    throw new QoreSignError("CLASSICAL_SIGNATURE_INVALID", "classical signature fields are not base64");
  }
  let owner: ClassicalKeyType | undefined;
  try {
    owner = classicalKeyTypeFor(classicalPub, fields.address);
  } catch {
    owner = undefined;
  }
  if (owner === undefined || owner !== sig.classical.keyType) {
    throw new QoreSignError("ADDRESS_MISMATCH", `the classical key does not control ${fields.address}`);
  }
  const adr36 = adr36SignBytes(fields.address, utf8Encode(args.message));
  if (!classicalVerify(owner, classicalPub, adr36, classicalSig)) {
    throw new QoreSignError("CLASSICAL_SIGNATURE_INVALID", "the classical signature does not verify");
  }

  const requirePq = args.requirePq ?? true;
  if (!sig.pq) {
    if (requirePq) throw new QoreSignError("PQ_LAYER_MISSING", "the sign-in carries no ML-DSA-87 signature");
    return fields;
  }
  if (sig.pq.algorithmId !== ALGORITHM_ML_DSA_87) {
    throw new QoreSignError("UNSUPPORTED_ALGORITHM", `unsupported algorithm ${sig.pq.algorithmId}`);
  }
  if (!args.pqPublicKey) {
    throw new QoreSignError("KEY_NOT_REGISTERED", "pass the account's registered ML-DSA-87 public key");
  }
  let pqSig: Uint8Array;
  try {
    pqSig = base64.decode(sig.pq.signature);
  } catch {
    throw new QoreSignError("PQ_SIGNATURE_INVALID", "ML-DSA-87 signature is not base64");
  }
  if (!pqVerify(args.pqPublicKey, siwqPqSignBytes(args.message), pqSig)) {
    throw new QoreSignError("PQ_SIGNATURE_INVALID", "the ML-DSA-87 signature does not verify");
  }
  return fields;
}
