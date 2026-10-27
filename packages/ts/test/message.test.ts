// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import {
  QoreSignError,
  RESERVED_PQ_DOMAINS,
  addressFromPublicKey,
  defaultHdPath,
  deriveCanonicalPqKey,
  deriveClassicalKey,
  deriveHdPqKey,
  messagePqSignBytes,
  signMessage,
  toHex,
  verifyMessage,
} from "../src/index.js";

const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const classical = deriveClassicalKey({ mnemonic: MNEMONIC });
const signer = addressFromPublicKey(classical.publicKey, "secp256k1").bech32;
const pqKey = deriveCanonicalPqKey({ mnemonic: MNEMONIC, address: signer });
const chainId = "qorechain-diana";

function code(fn: () => unknown): string | undefined {
  try {
    fn();
  } catch (err) {
    return err instanceof QoreSignError ? err.code : String(err);
  }
  return undefined;
}

describe("message signing", () => {
  it("prefixes the domain and chain id before the message bytes", () => {
    const bytes = messagePqSignBytes(chainId, new Uint8Array([0x00, 0xff]));
    expect(toHex(bytes)).toBe(toHex(new TextEncoder().encode("qorechain-msg-v1|qorechain-diana|")) + "00ff");
    for (const reserved of RESERVED_PQ_DOMAINS.filter((d) => d !== "qorechain-msg-v1|")) {
      expect(new TextDecoder().decode(bytes).startsWith(reserved)).toBe(false);
    }
    expect(code(() => messagePqSignBytes("bad|chain", "x"))).toBe("INVALID_ARGUMENT");
  });

  it("signs and verifies strings and bytes", () => {
    const sig = signMessage({ chainId, signer, data: "hello", classicalKey: classical, pqKey });
    expect(sig.signatureType).toBe("ml-dsa-87-hybrid");
    expect(() => verifyMessage({ chainId, signer, data: "hello", signature: sig, pqPublicKey: pqKey.publicKey })).not.toThrow();
    const bin = signMessage({ chainId, signer, data: new Uint8Array([1, 2, 3]), classicalKey: classical, pqKey });
    expect(() => verifyMessage({ chainId, signer, data: new Uint8Array([1, 2, 3]), signature: bin, pqPublicKey: pqKey.publicKey })).not.toThrow();
  });

  it("refuses another chain, another message, another key, and a missing PQ part", () => {
    const sig = signMessage({ chainId, signer, data: "hello", classicalKey: classical, pqKey });
    const base = { chainId, signer, data: "hello", signature: sig, pqPublicKey: pqKey.publicKey };
    expect(code(() => verifyMessage({ ...base, chainId: "qorechain-vladi" }))).toBe("PQ_SIGNATURE_INVALID");
    expect(code(() => verifyMessage({ ...base, data: "hello!" }))).toBe("CLASSICAL_SIGNATURE_INVALID");
    const other = deriveHdPqKey({ mnemonic: MNEMONIC, path: defaultHdPath(0) });
    expect(code(() => verifyMessage({ ...base, pqPublicKey: other.publicKey }))).toBe("PQ_SIGNATURE_INVALID");
    const classicalOnly = signMessage({ chainId, signer, data: "hello", classicalKey: classical });
    expect(code(() => verifyMessage({ ...base, signature: classicalOnly }))).toBe("PQ_LAYER_MISSING");
    expect(() => verifyMessage({ ...base, signature: classicalOnly, requirePq: false })).not.toThrow();
    const eth = deriveClassicalKey({ mnemonic: MNEMONIC, type: "eth_secp256k1" });
    expect(code(() => signMessage({ chainId, signer, data: "x", classicalKey: eth }))).toBe("ADDRESS_MISMATCH");
  });

  it("a message signature is not a sign-in signature", () => {
    const sig = signMessage({ chainId, signer, data: "hello", classicalKey: classical, pqKey });
    const siwqBytes = new TextEncoder().encode("qorechain-siwq-v1|hello");
    expect(toHex(messagePqSignBytes(chainId, "hello"))).not.toBe(toHex(siwqBytes));
    expect(sig.pq?.algorithmId).toBe(1);
  });
});
