// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { addressFromPublicKey, deriveCanonicalPqKey, deriveClassicalKey, signHybrid, toBase64, toHex } from "../src/index.js";
import { fetchEvmWindow, inspectTransaction, type FetchLike } from "../src/network.js";

const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const classical = deriveClassicalKey({ mnemonic: MNEMONIC });
const address = addressFromPublicKey(classical.publicKey, "secp256k1").bech32;
const pq = deriveCanonicalPqKey({ mnemonic: MNEMONIC, address });
const chainId = "qorechain-diana";

// TxBody { messages: [Any{ /cosmos.bank.v1beta1.MsgSend }], memo: "m" } and an AuthInfo with the signer's key.
const enc = (s: string) => new TextEncoder().encode(s);
const field = (n: number, b: Uint8Array) => Uint8Array.from([(n << 3) | 2, b.length, ...b]);
const any = (url: string, v: Uint8Array) => Uint8Array.from([...field(1, enc(url)), ...field(2, v)]);
const body = Uint8Array.from([...field(1, any("/cosmos.bank.v1beta1.MsgSend", enc("x"))), ...field(2, enc("m"))]);
const signerInfo = Uint8Array.from([
  ...field(1, any("/cosmos.crypto.secp256k1.PubKey", field(1, classical.publicKey))),
  ...field(2, Uint8Array.from([0x0a, 0x02, 0x08, 0x01])),
  0x18, 0x05,
]);
const coin = Uint8Array.from([...field(1, enc("uqor")), ...field(2, enc("20000"))]);
const authInfo = Uint8Array.from([...field(1, signerInfo), ...field(2, Uint8Array.from([...field(1, coin), 0x10, 0xc0, 0x9a, 0x0c]))]);

function server(txBytes: Uint8Array, registered = true): FetchLike {
  return async (url) => {
    const json = (status: number, b: unknown) => ({ ok: status < 400, status, json: async () => b });
    if (url.includes("/cosmos/tx/v1beta1/txs/")) {
      if (url.endsWith("0".repeat(64))) return json(404, { code: 5, message: "tx not found" });
      return json(200, { tx: {}, tx_response: { height: "42", code: 0, codespace: "" } });
    }
    if (url.endsWith("/cosmos/tx/v1beta1/encode")) return json(200, { tx_bytes: toBase64(txBytes) });
    if (url.includes("/account_info/")) return json(200, { info: { account_number: "7" } });
    if (url.includes("/qorechain/pqc/v1/account/"))
      return json(200, registered ? { found: true, account: { public_key: toBase64(pq.publicKey), algorithm_id: 1, possession_proven: true } } : { found: false });
    if (url.includes("/evm_window/"))
      return json(200, { found: true, live: true, opened_height: "10", expiry_height: "3610", max_txs: "10", used_txs: "1", max_value: "25000000", used_value: "0", remaining_blocks: "3000", remaining_txs: "9", remaining_value: "25000000", native_only: false, allowed_targets: ["0xabc"] });
    return json(404, {});
  };
}

describe("inspectTransaction", () => {
  const signed = signHybrid({ chainId, accountNumber: 7, bodyBytes: body, authInfoBytes: authInfo, classicalKey: classical, pqKey: pq });

  it("reports messages, signer, fee, a verified layer and the tier", async () => {
    const r = await inspectTransaction({ rest: "https://r", chainId, txhash: "ab".repeat(32), fetch: server(signed.txBytes) });
    expect(r?.messages.map((m) => m.typeUrl)).toEqual(["/cosmos.bank.v1beta1.MsgSend"]);
    expect(r?.memo).toBe("m");
    expect(r?.signer?.address).toBe(address);
    expect(r?.signer?.sequence).toBe(5n);
    expect(r?.fee).toEqual({ amount: [{ denom: "uqor", amount: "20000" }], gasLimit: 200000n });
    expect(r?.classicalSignatureValid).toBe(true);
    expect(r?.pqLayer).toEqual({ present: true, count: 1, algorithmId: 1, verified: true, signBytesVersion: "v2" });
    expect(r?.tier).toBe("pqc");
    expect(r?.height).toBe(42n);
  });

  it("flags a layer whose signer has no key now, and a transaction without a layer", async () => {
    const noKey = await inspectTransaction({ rest: "https://r", chainId, txhash: "ab".repeat(32), fetch: server(signed.txBytes, false) });
    expect(noKey?.pqLayer.verified).toBe(false);
    const classicalOnly = signHybrid({ chainId, accountNumber: 7, bodyBytes: body, authInfoBytes: authInfo, classicalKey: classical, mode: "classicalOnly" });
    const plain = await inspectTransaction({ rest: "https://r", chainId, txhash: "ab".repeat(32), fetch: server(classicalOnly.txBytes) });
    expect(plain?.pqLayer.present).toBe(false);
    expect(plain?.tier).toBe("shake");
  });

  it("returns undefined for an unknown hash and refuses a malformed one", async () => {
    expect(await inspectTransaction({ rest: "https://r", chainId, txhash: "0".repeat(64), fetch: server(signed.txBytes) })).toBeUndefined();
    await expect(inspectTransaction({ rest: "https://r", chainId, txhash: "xyz", fetch: server(signed.txBytes) })).rejects.toThrow(/64 hex/);
  });
});

describe("fetchEvmWindow", () => {
  it("parses the window", async () => {
    const w = await fetchEvmWindow({ rest: "https://r", address, fetch: server(new Uint8Array()) });
    expect(w).toMatchObject({ found: true, live: true, maxTxs: 10n, remainingTxs: 9n, allowedTargets: ["0xabc"] });
    expect(toHex(new Uint8Array())).toBe("");
  });
});
