// SPDX-License-Identifier: Apache-2.0
//
// The published vectors must keep matching the reference implementation.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  QoreSignError,
  adr36SignBytes,
  buildRegisterPqKeyMessage,
  createSiwqMessage,
  deriveCanonicalPqKey,
  deriveClassicalKey,
  deriveHdPqKey,
  fromHex,
  hybridSignBytes,
  messagePqSignBytes,
  parseSiwqMessage,
  parseSiwqTimestamp,
  signMessage,
  verifyMessage,
  proofOfPossessionMessage,
  signHybrid,
  signProofOfPossession,
  signSiwq,
  siwqPqSignBytes,
  toHex,
  verifySiwq,
  type SiwqFields,
} from "../src/index.js";

const v = JSON.parse(readFileSync(new URL("../../../vectors/qoresign-v1.json", import.meta.url), "utf8"));
const enc = (s: string) => new TextEncoder().encode(s);

describe("vectors/qoresign-v1.json", () => {
  const classical = deriveClassicalKey({ mnemonic: v.mnemonic });
  const pq = deriveCanonicalPqKey({ mnemonic: v.mnemonic, address: v.accounts.secp256k1.address });

  it("accounts", () => {
    const eth = deriveClassicalKey({ mnemonic: v.mnemonic, type: "eth_secp256k1" });
    expect(toHex(classical.privateKey)).toBe(v.accounts.secp256k1.privateKey);
    expect(toHex(classical.publicKey)).toBe(v.accounts.secp256k1.publicKey);
    expect(toHex(eth.publicKey)).toBe(v.accounts.eth_secp256k1.publicKey);
  });

  it("canonical and HD keys", () => {
    for (const c of v.canonical) {
      expect(toHex(deriveCanonicalPqKey({ mnemonic: v.mnemonic, address: c.address }).publicKey)).toBe(c.publicKey);
    }
    for (const h of v.hd) expect(toHex(deriveHdPqKey({ mnemonic: v.mnemonic, path: h.path }).publicKey)).toBe(h.publicKey);
    for (const p of v.hdRejected) expect(() => deriveHdPqKey({ mnemonic: v.mnemonic, path: p })).toThrow(QoreSignError);
  });

  it("hybrid transactions", () => {
    for (const c of v.hybridTx.cases) {
      const args = {
        chainId: v.chainId,
        bodyBytes: fromHex(v.hybridTx.bodyBytes),
        authInfoBytes: fromHex(v.hybridTx.authInfoBytes),
        signBytesVersion: c.signBytesVersion,
      };
      expect(toHex(hybridSignBytes(args))).toBe(c.signBytes);
      const signed = signHybrid({ ...args, accountNumber: v.hybridTx.accountNumber, classicalKey: classical, pqKey: pq });
      expect(toHex(signed.pqSignature!)).toBe(c.pqSignature);
      expect(toHex(signed.bodyBytes)).toBe(c.signedBodyBytes);
      expect(toHex(signed.classicalSignature)).toBe(c.classicalSignature);
      expect(toHex(signed.txBytes)).toBe(c.txBytes);
    }
  });

  it("registration", () => {
    const pop = v.proofOfPossession;
    expect(new TextDecoder().decode(proofOfPossessionMessage({ chainId: v.chainId, account: pop.account, publicKey: pq.publicKey }))).toBe(
      pop.message,
    );
    expect(toHex(signProofOfPossession({ chainId: v.chainId, account: pop.account, pqKey: pq }))).toBe(pop.signature);
    const msg = buildRegisterPqKeyMessage({ chainId: v.chainId, account: pop.account, pqKey: pq, classicalPublicKey: classical.publicKey });
    expect(msg.typeUrl).toBe(v.registerMessage.typeUrl);
    expect(toHex(msg.value)).toBe(v.registerMessage.value);
  });

  it("message signing", () => {
    for (const c of v.message.cases) {
      const data = fromHex(c.data);
      expect(toHex(adr36SignBytes(v.message.signer, data))).toBe(c.adr36SignBytes);
      expect(toHex(messagePqSignBytes(v.chainId, data))).toBe(c.pqSignBytes);
      expect(signMessage({ chainId: v.chainId, signer: v.message.signer, data, classicalKey: classical, pqKey: pq })).toEqual(c.signature);
      verifyMessage({ chainId: v.chainId, signer: v.message.signer, data, signature: c.signature, pqPublicKey: pq.publicKey });
    }
  });

  it("sign in", () => {
    const s = v.siwq;
    expect(createSiwqMessage(s.fields as SiwqFields)).toBe(s.message);
    expect(toHex(adr36SignBytes(s.fields.address, enc(s.message)))).toBe(s.adr36SignBytes);
    expect(toHex(siwqPqSignBytes(s.message))).toBe(s.pqSignBytes);
    expect(signSiwq({ message: s.message, classicalKey: classical, pqKey: pq })).toEqual(s.signature);
    expect(
      verifySiwq({
        message: s.message,
        signature: s.signature,
        domain: s.fields.domain,
        nonce: s.fields.nonce,
        pqPublicKey: pq.publicKey,
        now: new Date(s.verifyAt),
      }).address,
    ).toBe(s.fields.address);
  });
});

describe("vectors/siwq-timestamps-v1.json", () => {
  const t = JSON.parse(readFileSync(new URL("../../../vectors/siwq-timestamps-v1.json", import.meta.url), "utf8")) as {
    format: string;
    valid: { timestamp: string; unixMs: number }[];
    invalid: string[];
  };
  const classical = deriveClassicalKey({ mnemonic: v.mnemonic });
  const pq = deriveCanonicalPqKey({ mnemonic: v.mnemonic, address: v.accounts.secp256k1.address });
  const base = v.siwq.fields as SiwqFields;
  const issuedLine = `Issued At: ${base.issuedAt}`;
  const codeOf = (fn: () => unknown): string | undefined => {
    try {
      fn();
    } catch (err) {
      return err instanceof QoreSignError ? err.code : String(err);
    }
    return undefined;
  };

  it("has cases", () => {
    expect(t.format).toBe("qoresign-siwq-timestamps-v1");
    expect(t.valid.length).toBeGreaterThan(0);
    expect(t.invalid.length).toBeGreaterThan(0);
    expect(v.siwq.message).toContain(issuedLine);
  });

  it.each(t.valid)("accepts $timestamp", ({ timestamp, unixMs }) => {
    expect(parseSiwqTimestamp(timestamp)).toBe(unixMs);
    const msg = createSiwqMessage({ ...base, issuedAt: timestamp, expirationTime: timestamp, notBefore: timestamp });
    parseSiwqMessage(msg);
    signSiwq({ message: msg, classicalKey: classical, pqKey: pq });
  });

  it.each(t.invalid)("refuses %j everywhere", (ts) => {
    expect(parseSiwqTimestamp(ts)).toBeUndefined();
    expect(codeOf(() => createSiwqMessage({ ...base, issuedAt: ts }))).toBe("SIWQ_MALFORMED");
    expect(codeOf(() => createSiwqMessage({ ...base, expirationTime: ts }))).toBe("SIWQ_MALFORMED");
    expect(codeOf(() => createSiwqMessage({ ...base, expirationTime: undefined, notBefore: ts }))).toBe("SIWQ_MALFORMED");
    const msg = (v.siwq.message as string).replace(issuedLine, `Issued At: ${ts}`);
    expect(codeOf(() => parseSiwqMessage(msg))).toBe("SIWQ_MALFORMED");
    expect(codeOf(() => signSiwq({ message: msg, classicalKey: classical, pqKey: pq }))).toBe("SIWQ_MALFORMED");
    expect(
      codeOf(() =>
        verifySiwq({
          message: msg,
          signature: v.siwq.signature,
          domain: "app.example.com",
          nonce: "a1b2c3d4e5",
          pqPublicKey: pq.publicKey,
          now: new Date("2026-10-27T10:00:30Z"),
        }),
      ),
    ).toBe("SIWQ_MALFORMED");
  });
});
