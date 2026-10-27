// SPDX-License-Identifier: Apache-2.0
//
// Accounts, classical keys and ML-DSA-87 key derivation.

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { hmac } from "@noble/hashes/hmac.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { keccak_256, shake256 } from "@noble/hashes/sha3.js";
import { mldsa87 } from "@qorechain/pqc";
import { bech32 } from "@scure/base";
import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { equalBytes, fromHex, requireLength, toHex, utf8Encode } from "./bytes.js";
import { QoreSignError } from "./errors.js";

/** Bech32 prefix of QoreChain accounts. */
export const ACCOUNT_PREFIX = "qor";

/** ML-DSA-87 sizes (FIPS 204, Table 2). */
export const ML_DSA_87_PUBLIC_KEY_LENGTH = 2592;
export const ML_DSA_87_SECRET_KEY_LENGTH = 4896;
export const ML_DSA_87_SIGNATURE_LENGTH = 4627;
export const ML_DSA_87_SEED_LENGTH = 32;

/** Algorithm id of ML-DSA-87 in `qorechain.pqc.v1` (named Dilithium5 on chain). */
export const ALGORITHM_ML_DSA_87 = 1;

/**
 * How a classical key maps to an account:
 * - `secp256k1`: Cosmos SDK accounts, address = RIPEMD160(SHA256(compressed key)), SLIP-44 coin type 118.
 * - `eth_secp256k1`: eth-native accounts, address = last 20 bytes of KECCAK256(uncompressed key),
 *   the same 20 bytes behind the `qor1` and `0x` forms, coin type 60.
 */
export type ClassicalKeyType = "secp256k1" | "eth_secp256k1";

export interface ClassicalKey {
  type: ClassicalKeyType;
  /** 32-byte secp256k1 secret key. */
  privateKey: Uint8Array;
  /** 33-byte compressed public key. */
  publicKey: Uint8Array;
}

export interface PqKeyPair {
  algorithmId: typeof ALGORITHM_ML_DSA_87;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/** An account's address in both forms. */
export interface AccountAddress {
  /** Bech32 form, `qor1...`. */
  bech32: string;
  /** EIP-55 checksummed hex form of the same 20 bytes. */
  hex: string;
  /** The raw 20 address bytes. */
  bytes: Uint8Array;
}

/** Default HD paths of the classical key. */
export const CLASSICAL_PATHS: Record<ClassicalKeyType, (index: number) => string> = {
  secp256k1: (i) => `m/44'/118'/0'/0/${i}`,
  eth_secp256k1: (i) => `m/44'/60'/0'/0/${i}`,
};

function checksumHex(bytes: Uint8Array): string {
  const lower = toHex(bytes);
  const hash = toHex(keccak_256(utf8Encode(lower)));
  let out = "0x";
  for (let i = 0; i < lower.length; i++) {
    const c = lower[i]!;
    out += parseInt(hash[i]!, 16) >= 8 ? c.toUpperCase() : c;
  }
  return out;
}

/** Build both address forms from 20 address bytes. */
export function addressFromBytes(bytes: Uint8Array): AccountAddress {
  requireLength(bytes, 20, "address");
  return {
    bech32: bech32.encode(ACCOUNT_PREFIX, bech32.toWords(bytes)),
    hex: checksumHex(bytes),
    bytes: Uint8Array.from(bytes),
  };
}

/** Parse a `qor1...` or `0x...` address. */
export function parseAddress(address: string): AccountAddress {
  if (/^0x[0-9a-fA-F]{40}$/.test(address)) return addressFromBytes(fromHex(address));
  let decoded;
  try {
    decoded = bech32.decode(address as `${string}1${string}`);
  } catch {
    throw new QoreSignError("INVALID_ADDRESS", `not a QoreChain address: ${JSON.stringify(address)}`);
  }
  if (decoded.prefix !== ACCOUNT_PREFIX) {
    throw new QoreSignError("INVALID_ADDRESS", `expected the "${ACCOUNT_PREFIX}" prefix, got "${decoded.prefix}"`);
  }
  const bytes = Uint8Array.from(bech32.fromWords(decoded.words));
  if (bytes.length !== 20) {
    throw new QoreSignError("INVALID_ADDRESS", `account addresses are 20 bytes, got ${bytes.length}`);
  }
  return addressFromBytes(bytes);
}

/** The account a classical public key controls. */
export function addressFromPublicKey(publicKey: Uint8Array, type: ClassicalKeyType): AccountAddress {
  const point = secp256k1.Point.fromBytes(publicKey);
  if (type === "secp256k1") {
    return addressFromBytes(ripemd160(sha256(point.toBytes(true))));
  }
  return addressFromBytes(keccak_256(point.toBytes(false).subarray(1)).subarray(12));
}

/**
 * Which derivation a compressed public key uses for `address`, or `undefined`
 * when the key belongs to neither.
 */
export function classicalKeyTypeFor(publicKey: Uint8Array, address: string): ClassicalKeyType | undefined {
  const target = parseAddress(address).bytes;
  for (const type of ["secp256k1", "eth_secp256k1"] as const) {
    if (equalBytes(addressFromPublicKey(publicKey, type).bytes, target)) return type;
  }
  return undefined;
}

/**
 * The mnemonic is part of the canonical derivation input, so a different
 * spacing would silently give a different key. Only the canonical form
 * (lowercase words, single spaces, nothing around them) is accepted.
 */
function checkMnemonic(mnemonic: string): string {
  if (typeof mnemonic !== "string") throw new QoreSignError("INVALID_MNEMONIC", "mnemonic must be a string");
  const normalized = mnemonic.normalize("NFKD").trim().split(/\s+/).join(" ");
  if (normalized !== mnemonic) {
    throw new QoreSignError(
      "INVALID_MNEMONIC",
      "pass the mnemonic in canonical form: words separated by single spaces, no surrounding whitespace",
    );
  }
  if (!validateMnemonic(normalized, wordlist)) {
    throw new QoreSignError("INVALID_MNEMONIC", "the mnemonic is not a valid BIP-39 English phrase");
  }
  return normalized;
}

/** Derive the classical key at `path` (BIP-32/BIP-44) from a BIP-39 mnemonic. */
export function deriveClassicalKey(args: {
  mnemonic: string;
  type?: ClassicalKeyType;
  /** Account index on the default path; ignored when `path` is set. */
  index?: number;
  path?: string;
  passphrase?: string;
}): ClassicalKey {
  const type = args.type ?? "secp256k1";
  const seed = mnemonicToSeedSync(checkMnemonic(args.mnemonic), args.passphrase ?? "");
  const node = HDKey.fromMasterSeed(seed).derive(args.path ?? CLASSICAL_PATHS[type](args.index ?? 0));
  if (!node.privateKey) throw new QoreSignError("INVALID_ARGUMENT", "derivation produced no private key");
  return classicalKeyFromPrivate(node.privateKey, type);
}

/** Wrap an existing secp256k1 secret key. */
export function classicalKeyFromPrivate(privateKey: Uint8Array, type: ClassicalKeyType = "secp256k1"): ClassicalKey {
  requireLength(privateKey, 32, "secp256k1 private key");
  return { type, privateKey: Uint8Array.from(privateKey), publicKey: secp256k1.getPublicKey(privateKey, true) };
}

/** Key pair from a 32-byte ML-DSA-87 seed (FIPS 204 ML-DSA.KeyGen_internal). */
export function pqKeyFromSeed(seed: Uint8Array): PqKeyPair {
  requireLength(seed, ML_DSA_87_SEED_LENGTH, "ML-DSA-87 seed");
  const kp = mldsa87.keygen(seed);
  return { algorithmId: ALGORITHM_ML_DSA_87, publicKey: kp.publicKey, secretKey: kp.secretKey };
}

/** Domain of the canonical derivation. */
export const CANONICAL_DERIVATION_DOMAIN = "qorechain:pqc:v1";

/**
 * The canonical ML-DSA-87 key of an account: the seed is
 * `SHAKE256("qorechain:pqc:v1|" + bech32Address + "|" + mnemonic, 32 bytes)`.
 *
 * This is the key QoreChain wallets and the QoreChain SDK derive today, so a
 * wallet using it signs with the key that is already registered for the
 * account. The key is bound to the address: the same mnemonic gives a
 * different key for every account.
 */
export function deriveCanonicalPqKey(args: { mnemonic: string; address: string }): PqKeyPair {
  const mnemonic = checkMnemonic(args.mnemonic);
  const account = parseAddress(args.address).bech32;
  const seed = shake256(utf8Encode(`${CANONICAL_DERIVATION_DOMAIN}|${account}|${mnemonic}`), {
    dkLen: ML_DSA_87_SEED_LENGTH,
  });
  return pqKeyFromSeed(seed);
}

/** HMAC key of the hardened-only HD derivation (draft). */
export const HD_MASTER_KEY = "qorechain-mldsa87-seed";
const HARDENED = 0x80000000;

function parseHardenedPath(path: string): number[] {
  const parts = path.trim().split("/");
  if (parts[0] !== "m") throw new QoreSignError("HD_INVALID_PATH", `path must start with "m": ${path}`);
  return parts.slice(1).map((p) => {
    if (!/^\d+'$/.test(p)) {
      if (/^\d+$/.test(p)) {
        throw new QoreSignError(
          "HD_NON_HARDENED",
          `segment "${p}" is not hardened; ML-DSA has no public child derivation, so every segment must be hardened`,
        );
      }
      throw new QoreSignError("HD_INVALID_PATH", `invalid path segment "${p}"`);
    }
    const n = Number(p.slice(0, -1));
    if (!Number.isSafeInteger(n) || n >= HARDENED) {
      throw new QoreSignError("HD_INVALID_PATH", `path index out of range: ${p}`);
    }
    return n + HARDENED;
  });
}

function ser32(i: number): Uint8Array {
  return Uint8Array.of((i >>> 24) & 0xff, (i >>> 16) & 0xff, (i >>> 8) & 0xff, i & 0xff);
}

/**
 * DRAFT: hardened-only hierarchical derivation of ML-DSA-87 keys
 * (see `spec/hd-derivation-draft.md`). Opt-in; the format may change before
 * it is final.
 *
 * Uses the SLIP-10 construction with its own master key string:
 * `I = HMAC-SHA512("qorechain-mldsa87-seed", seed)`, then for each hardened
 * index `I = HMAC-SHA512(chainCode, 0x00 || k || ser32(i))`. The ML-DSA-87
 * seed is the final 32-byte `k`.
 *
 * Unlike {@link deriveCanonicalPqKey}, the key is not bound to an address: it
 * must be registered on chain for the account that will use it.
 */
export function deriveHdPqKey(args: { mnemonic?: string; seed?: Uint8Array; path: string; passphrase?: string }): PqKeyPair {
  let seed = args.seed;
  if (!seed) {
    if (args.mnemonic === undefined) throw new QoreSignError("INVALID_ARGUMENT", "a mnemonic or a seed is required");
    seed = mnemonicToSeedSync(checkMnemonic(args.mnemonic), args.passphrase ?? "");
  }
  if (seed.length < 16 || seed.length > 64) {
    throw new QoreSignError("INVALID_ARGUMENT", "seed must be 16 to 64 bytes");
  }
  const indexes = parseHardenedPath(args.path);
  let I = hmac(sha512, utf8Encode(HD_MASTER_KEY), seed);
  let k = I.slice(0, 32);
  let c = I.slice(32);
  for (const i of indexes) {
    I = hmac(sha512, c, Uint8Array.from([0, ...k, ...ser32(i)]));
    k = I.slice(0, 32);
    c = I.slice(32);
  }
  return pqKeyFromSeed(k);
}

/** Default draft HD path for account `index`. */
export function defaultHdPath(index = 0, coinType = 118): string {
  return `m/44'/${coinType}'/${index}'/0'/0'`;
}

export { toHex, fromHex };
