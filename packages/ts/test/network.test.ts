// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import {
  assertPqLayerMatchesRegisteredKey,
  fetchPqKeyStatus,
  resolveSignBytesVersion,
  simulateTx,
  submitWithSignBytesFallback,
  suggestGasLimit,
  verifySiwqWithChain,
  type FetchLike,
} from "../src/network.js";
import {
  QoreSignError,
  addressFromPublicKey,
  createSiwqMessage,
  deriveCanonicalPqKey,
  deriveClassicalKey,
  signPqLayer,
  signSiwq,
  toBase64,
} from "../src/index.js";

const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const classical = deriveClassicalKey({ mnemonic: MNEMONIC });
const address = addressFromPublicKey(classical.publicKey, "secp256k1").bech32;
const pqKey = deriveCanonicalPqKey({ mnemonic: MNEMONIC, address });

type Route = (url: string, init?: { method?: string; body?: string }) => { status: number; body: unknown };

function mockFetch(route: Route, calls: string[] = []): FetchLike {
  return async (url, init) => {
    calls.push(`${init?.method ?? "GET"} ${url}`);
    const r = route(url, init);
    return { ok: r.status < 400, status: r.status, json: async () => r.body };
  };
}

const accountRoute: Route = (url) =>
  url.includes("/qorechain/pqc/v1/account/")
    ? {
        status: 200,
        body: {
          found: true,
          account: { public_key: toBase64(pqKey.publicKey), algorithm_id: 1, key_type: "hybrid", possession_proven: true },
        },
      }
    : { status: 404, body: {} };

async function code(p: Promise<unknown>): Promise<string | undefined> {
  try {
    await p;
  } catch (err) {
    return err instanceof QoreSignError ? err.code : String(err);
  }
  return undefined;
}

describe("key status", () => {
  it("reads a registered key", async () => {
    const s = await fetchPqKeyStatus({ rest: "https://rest.test/", address, fetch: mockFetch(accountRoute) });
    expect(s.registered).toBe(true);
    expect(s.possessionProven).toBe(true);
    expect(s.publicKey?.length).toBe(2592);
  });

  it("reports an unregistered account and a broken endpoint differently", async () => {
    const none = await fetchPqKeyStatus({ rest: "https://r", address, fetch: mockFetch(() => ({ status: 200, body: { found: false } })) });
    expect(none.registered).toBe(false);
    expect(await code(fetchPqKeyStatus({ rest: "https://r", address, fetch: mockFetch(() => ({ status: 500, body: {} })) }))).toBe(
      "NETWORK_UNAVAILABLE",
    );
  });
});

describe("sign-bytes version", () => {
  it("v2 once an upgrade that switched it is applied, v1 before on the legacy networks", async () => {
    const applied = (h: string): FetchLike => mockFetch((url) => ({ status: 200, body: { height: url.endsWith("v3.2.0") ? h : "0" } }));
    expect(await resolveSignBytesVersion({ rest: "https://r", chainId: "qorechain-vladi", fetch: applied("2981742") })).toBe("v2");
    expect(await resolveSignBytesVersion({ rest: "https://r", chainId: "qorechain-vladi", fetch: applied("0") })).toBe("v1");
    expect(await resolveSignBytesVersion({ rest: "https://r", chainId: "my-new-chain", fetch: applied("0") })).toBe("v2");
  });
});

describe("simulation", () => {
  const events = [
    { type: "coin_spent", attributes: [{ key: "spender", value: "qor1a" }, { key: "amount", value: "1500uqor" }] },
    { type: "coin_received", attributes: [{ key: "receiver", value: "qor1b" }, { key: "amount", value: "1000uqor" }] },
    { type: "coin_received", attributes: [{ key: "receiver", value: "qor1fee" }, { key: "amount", value: "500uqor" }] },
  ];

  it("returns gas, a suggested limit and balance deltas", async () => {
    const fetch = mockFetch((url) =>
      url.endsWith("/simulate")
        ? { status: 200, body: { gas_info: { gas_used: "166300" }, result: { events } } }
        : { status: 200, body: { height: "8890800" } },
    );
    const r = await simulateTx({ rest: "https://r", txBytes: new Uint8Array([1]), fetch });
    expect(r.gasUsed).toBe(166300n);
    expect(r.suggestedGasLimit).toBe(171626n);
    expect(r.balanceDeltas).toEqual({ qor1a: { uqor: -1500n }, qor1b: { uqor: 1000n }, qor1fee: { uqor: 500n } });
  });

  it("uses the wider margin on nodes before v3.2.5", () => {
    expect(suggestGasLimit(129_000n, false)).toBe(236_600n);
    expect(suggestGasLimit(166_300n, true)).toBe(171_626n);
  });

  it("a refused simulation is an error with the network's reason", async () => {
    const fetch = mockFetch(() => ({
      status: 400,
      body: { code: 2, message: "failed to execute message; codespace stakingtier code 12: nothing to claim" },
    }));
    try {
      await simulateTx({ rest: "https://r", txBytes: new Uint8Array([1]), fetch, exactSimulation: true });
      expect.unreachable();
    } catch (err) {
      expect((err as QoreSignError).code).toBe("SIMULATION_FAILED");
      expect((err as QoreSignError).details).toMatchObject({ codespace: "stakingtier", code: 12 });
    }
  });
});

describe("broadcast with sign-bytes fallback", () => {
  it("retries once with the other version after a pqc 21 refusal", async () => {
    const used: string[] = [];
    let n = 0;
    const fetch = mockFetch((url) => {
      if (!url.endsWith("/txs")) return { status: 200, body: { height: "0" } };
      n++;
      return n === 1
        ? { status: 200, body: { tx_response: { txhash: "", code: 21, codespace: "pqc", raw_log: "sign-bytes" } } }
        : { status: 200, body: { tx_response: { txhash: "ABC", code: 0, codespace: "" } } };
    });
    const res = await submitWithSignBytesFallback({
      rest: "https://r",
      chainId: "qorechain-vladi",
      signBytesVersion: "v1",
      fetch,
      sign: (v) => {
        used.push(v);
        return new Uint8Array([1]);
      },
    });
    expect(used).toEqual(["v1", "v2"]);
    expect(res).toMatchObject({ txhash: "ABC", code: 0, signBytesVersion: "v2" });
  });

  it("does not retry other refusals", async () => {
    const used: string[] = [];
    const fetch = mockFetch(() => ({ status: 200, body: { tx_response: { txhash: "", code: 5, codespace: "sdk", raw_log: "insufficient funds" } } }));
    const res = await submitWithSignBytesFallback({
      rest: "https://r",
      chainId: "qorechain-vladi",
      signBytesVersion: "v2",
      fetch,
      sign: (v) => (used.push(v), new Uint8Array([1])),
    });
    expect(used).toEqual(["v2"]);
    expect(res.code).toBe(5);
  });
});

describe("checks against the registered key", () => {
  it("accepts a layer made with the registered key and refuses a missing one", async () => {
    const body = new Uint8Array([0x12, 0x01, 0x6d]);
    const auth = new Uint8Array([0x12, 0x00]);
    const layered = signPqLayer({ chainId: "qorechain-diana", bodyBytes: body, authInfoBytes: auth, pqKey }).bodyBytes;
    const fetch = mockFetch(accountRoute);
    const ok = await assertPqLayerMatchesRegisteredKey({ rest: "https://r", fetch, chainId: "qorechain-diana", signer: address, bodyBytes: layered, authInfoBytes: auth });
    expect(ok.valid).toBe(true);
    expect(
      await code(assertPqLayerMatchesRegisteredKey({ rest: "https://r", fetch, chainId: "qorechain-diana", signer: address, bodyBytes: body, authInfoBytes: auth })),
    ).toBe("PQ_LAYER_MISSING");
    const none = mockFetch(() => ({ status: 200, body: { found: false } }));
    expect(
      await code(assertPqLayerMatchesRegisteredKey({ rest: "https://r", fetch: none, chainId: "qorechain-diana", signer: address, bodyBytes: layered, authInfoBytes: auth })),
    ).toBe("KEY_NOT_REGISTERED");
  });

  it("verifies a sign-in against the chain", async () => {
    const message = createSiwqMessage({
      domain: "app.example.com",
      address,
      uri: "https://app.example.com",
      chainId: "qorechain-diana",
      nonce: "noncenonce1",
      issuedAt: "2026-10-27T10:00:00Z",
    });
    const signature = signSiwq({ message, classicalKey: classical, pqKey });
    const out = await verifySiwqWithChain({
      rest: "https://r",
      fetch: mockFetch(accountRoute),
      address,
      message,
      signature,
      domain: "app.example.com",
      nonce: "noncenonce1",
      now: new Date("2026-10-27T10:00:30Z"),
    });
    expect(out.possessionProven).toBe(true);
  });
});
