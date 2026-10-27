// SPDX-License-Identifier: Apache-2.0
import { makeSignDoc, serializeSignDoc } from "@cosmjs/amino";
import { describe, expect, it } from "vitest";
import {
  QoreSignError,
  addressFromPublicKey,
  adr36SignBytes,
  createSiwqMessage,
  deriveCanonicalPqKey,
  deriveClassicalKey,
  deriveHdPqKey,
  defaultHdPath,
  parseSiwqMessage,
  signSiwq,
  toBase64,
  toHex,
  utf8,
  verifySiwq,
  type SiwqFields,
} from "./helpers.js";

const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const classical = deriveClassicalKey({ mnemonic: MNEMONIC });
const address = addressFromPublicKey(classical.publicKey, "secp256k1").bech32;
const pqKey = deriveCanonicalPqKey({ mnemonic: MNEMONIC, address });

const fields: SiwqFields = {
  scheme: "https",
  domain: "app.example.com",
  address,
  statement: "Sign in to the example app.",
  uri: "https://app.example.com/login",
  chainId: "qorechain-diana",
  nonce: "a1b2c3d4e5",
  issuedAt: "2026-10-27T10:00:00Z",
  expirationTime: "2026-10-27T10:10:00Z",
  resources: ["https://app.example.com/terms"],
};
const now = new Date("2026-10-27T10:01:00Z");

function errCode(fn: () => unknown): string | undefined {
  try {
    fn();
  } catch (err) {
    return err instanceof QoreSignError ? err.code : String(err);
  }
  return undefined;
}

describe("message format", () => {
  it("renders the EIP-4361-style layout and round-trips", () => {
    const text = createSiwqMessage(fields);
    expect(text).toBe(
      [
        "https://app.example.com wants you to sign in with your QoreChain account:",
        address,
        "",
        "Sign in to the example app.",
        "",
        "URI: https://app.example.com/login",
        "Version: 1",
        "Chain ID: qorechain-diana",
        "Nonce: a1b2c3d4e5",
        "Issued At: 2026-10-27T10:00:00Z",
        "Expiration Time: 2026-10-27T10:10:00Z",
        "Resources:",
        "- https://app.example.com/terms",
      ].join("\n"),
    );
    expect(parseSiwqMessage(text)).toEqual({ ...fields, version: "1" });
  });

  it("handles a message without statement and optional fields", () => {
    const minimal = { ...fields, statement: undefined, expirationTime: undefined, resources: undefined, scheme: undefined };
    const text = createSiwqMessage(minimal);
    expect(text.split("\n").slice(0, 4)).toEqual([
      "app.example.com wants you to sign in with your QoreChain account:",
      address,
      "",
      "",
    ]);
    const parsed = parseSiwqMessage(text);
    expect(parsed.statement).toBeUndefined();
    expect(createSiwqMessage(parsed)).toBe(text);
  });

  it("rejects malformed input", () => {
    expect(errCode(() => createSiwqMessage({ ...fields, nonce: "short" }))).toBe("SIWQ_MALFORMED");
    expect(errCode(() => createSiwqMessage({ ...fields, statement: "two\nlines" }))).toBe("SIWQ_MALFORMED");
    expect(errCode(() => createSiwqMessage({ ...fields, issuedAt: "yesterday" }))).toBe("SIWQ_MALFORMED");
    expect(errCode(() => createSiwqMessage({ ...fields, expirationTime: "2026-02-30T10:00:00Z" }))).toBe("SIWQ_MALFORMED");
    expect(errCode(() => createSiwqMessage({ ...fields, issuedAt: "2026-10-27T24:00:00Z" }))).toBe("SIWQ_MALFORMED");
    expect(errCode(() => parseSiwqMessage(createSiwqMessage(fields) + "\nextra"))).toBe("SIWQ_MALFORMED");
  });
});

describe("ADR-36", () => {
  it("matches the amino sign document Keplr-compatible wallets sign", () => {
    const data = utf8("hello");
    const doc = makeSignDoc(
      [{ type: "sign/MsgSignData", value: { signer: address, data: toBase64(data) } }],
      { gas: "0", amount: [] },
      "",
      "",
      0,
      0,
    );
    expect(toHex(adr36SignBytes(address, data))).toBe(toHex(serializeSignDoc(doc)));
  });
});

describe("sign and verify", () => {
  const message = createSiwqMessage(fields);
  const signature = signSiwq({ message, classicalKey: classical, pqKey });

  it("verifies a hybrid sign-in", () => {
    expect(signature.signatureType).toBe("ml-dsa-87-hybrid");
    const out = verifySiwq({ message, signature, domain: "app.example.com", nonce: "a1b2c3d4e5", pqPublicKey: pqKey.publicKey, now });
    expect(out.address).toBe(address);
  });

  it("refuses the wrong domain, nonce, chain, time or key", () => {
    const base = { message, signature, domain: "app.example.com", nonce: "a1b2c3d4e5", pqPublicKey: pqKey.publicKey, now };
    expect(errCode(() => verifySiwq({ ...base, domain: "evil.example" }))).toBe("SIWQ_DOMAIN_MISMATCH");
    expect(errCode(() => verifySiwq({ ...base, nonce: "zzzzzzzzzz" }))).toBe("SIWQ_NONCE_MISMATCH");
    expect(errCode(() => verifySiwq({ ...base, chainId: "qorechain-vladi" }))).toBe("SIWQ_CHAIN_MISMATCH");
    expect(errCode(() => verifySiwq({ ...base, now: new Date("2026-10-27T10:10:00Z") }))).toBe("SIWQ_EXPIRED");
    expect(errCode(() => verifySiwq({ ...base, now: new Date("2026-10-27T09:00:00Z") }))).toBe("SIWQ_NOT_YET_VALID");
    const other = deriveHdPqKey({ mnemonic: MNEMONIC, path: defaultHdPath(0) });
    expect(errCode(() => verifySiwq({ ...base, pqPublicKey: other.publicKey }))).toBe("PQ_SIGNATURE_INVALID");
    expect(errCode(() => verifySiwq({ ...base, pqPublicKey: undefined }))).toBe("KEY_NOT_REGISTERED");
  });

  it("refuses an altered message or a key that does not own the address", () => {
    const base = { signature, domain: "app.example.com", nonce: "a1b2c3d4e5", pqPublicKey: pqKey.publicKey, now };
    const altered = message.replace("Sign in to the example app.", "Transfer everything.");
    expect(errCode(() => verifySiwq({ ...base, message: altered }))).toBe("CLASSICAL_SIGNATURE_INVALID");
    const eth = deriveClassicalKey({ mnemonic: MNEMONIC, type: "eth_secp256k1" });
    const forged = { ...signature, classical: { ...signature.classical, publicKey: toBase64(eth.publicKey) } };
    expect(errCode(() => verifySiwq({ ...base, message, signature: forged }))).toBe("ADDRESS_MISMATCH");
    expect(errCode(() => signSiwq({ message, classicalKey: eth }))).toBe("ADDRESS_MISMATCH");
  });

  it("classical-only sign-in is refused unless explicitly allowed", () => {
    const sig = signSiwq({ message, classicalKey: classical });
    expect(sig.signatureType).toBe("secp256k1");
    const base = { message, signature: sig, domain: "app.example.com", nonce: "a1b2c3d4e5", now };
    expect(errCode(() => verifySiwq(base))).toBe("PQ_LAYER_MISSING");
    expect(verifySiwq({ ...base, requirePq: false }).address).toBe(address);
  });

  it("works for eth-native accounts", () => {
    const eth = deriveClassicalKey({ mnemonic: MNEMONIC, type: "eth_secp256k1" });
    const ethAddr = addressFromPublicKey(eth.publicKey, "eth_secp256k1").bech32;
    const ethPq = deriveCanonicalPqKey({ mnemonic: MNEMONIC, address: ethAddr });
    const msg = createSiwqMessage({ ...fields, address: ethAddr });
    const sig = signSiwq({ message: msg, classicalKey: eth, pqKey: ethPq });
    expect(sig.classical.keyType).toBe("eth_secp256k1");
    expect(
      verifySiwq({ message: msg, signature: sig, domain: "app.example.com", nonce: "a1b2c3d4e5", pqPublicKey: ethPq.publicKey, now }).address,
    ).toBe(ethAddr);
  });
});
