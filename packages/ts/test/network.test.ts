// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import {
  PROTOCOL_FEATURES_PATH,
  SIGN_BYTES_V2_FEATURE,
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

/** The protocol feature answer with the sign-bytes v2 switch in the given state (undefined leaves it out). */
const features = (enabled?: unknown) => ({
  features: [
    { name: "pqc-time-proof", enabled: true, known: true, staged: false },
    ...(enabled === undefined ? [] : [{ name: SIGN_BYTES_V2_FEATURE, enabled, known: true, staged: false }]),
  ],
  height: "4200",
});

/** accountRoute on a network whose sign-bytes v2 switch is on. */
const v2Route: Route = (url, init) => (url.endsWith(PROTOCOL_FEATURES_PATH) ? { status: 200, body: features(true) } : accountRoute(url, init));

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

describe("sign-bytes version from the protocol feature switch", () => {
  // No upgrade plan applied, as on a fresh network that reuses a chain id.
  const noPlans = (feature: { status: number; body: unknown }): Route => (url) =>
    url.endsWith(PROTOCOL_FEATURES_PATH) ? feature : url.includes("applied_plan") ? { status: 200, body: { plan: null } } : { status: 404, body: {} };
  const plans = ["GET https://r/cosmos/upgrade/v1beta1/applied_plan/v3.2.0", "GET https://r/cosmos/upgrade/v1beta1/applied_plan/v3.1.98"];
  const featureCall = `GET https://r${PROTOCOL_FEATURES_PATH}`;

  it.each([
    ["an enabled switch on a legacy chain id with no plan applied", { status: 200, body: features(true) }, "v2", false],
    ["an enabled switch spelled as a string", { status: 200, body: features("true") }, "v2", false],
    ["a listed but disabled switch", { status: 200, body: features(false) }, "v1", false],
    ["a route that is not served (404)", { status: 404, body: { code: 5, message: "Not Implemented" } }, "v1", true],
    ["a route that is not implemented (501)", { status: 501, body: {} }, "v1", true],
    ["an answer without a feature list", { status: 200, body: { features: "x" } }, "v1", true],
    ["an invalid enabled value", { status: 200, body: features(7) }, "v1", true],
    ["a switch that is not listed", { status: 200, body: features() }, "v1", true],
  ] as const)("%s", async (_name, feature, want, fallback) => {
    const calls: string[] = [];
    const v = await resolveSignBytesVersion({ rest: "https://r", chainId: "qorechain-diana", fetch: mockFetch(noPlans(feature), calls) });
    expect(v).toBe(want);
    expect(calls).toEqual(fallback ? [featureCall, ...plans] : [featureCall]);
  });

  it("falls back on an unreadable answer and on a request that fails", async () => {
    const notJson: FetchLike = async (url) => ({
      ok: true,
      status: 200,
      json: async () => {
        if (url.endsWith(PROTOCOL_FEATURES_PATH)) throw new SyntaxError("not json");
        return { height: url.endsWith("v3.2.0") ? "2981742" : "0" };
      },
    });
    expect(await resolveSignBytesVersion({ rest: "https://r", chainId: "qorechain-vladi", fetch: notJson })).toBe("v2");
    const down: FetchLike = async (url) => {
      if (url.endsWith(PROTOCOL_FEATURES_PATH)) throw new TypeError("fetch failed");
      return { ok: true, status: 200, json: async () => ({ plan: null }) };
    };
    expect(await resolveSignBytesVersion({ rest: "https://r", chainId: "qorechain-diana", fetch: down })).toBe("v1");
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
    const fetch = mockFetch(v2Route);
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

  it("checks only the version the network verifies", async () => {
    const body = new Uint8Array([0x12, 0x01, 0x6d]);
    const auth = new Uint8Array([0x12, 0x00]);
    const v1 = signPqLayer({ chainId: "qorechain-diana", bodyBytes: body, authInfoBytes: auth, pqKey, signBytesVersion: "v1" }).bodyBytes;
    const args = { rest: "https://r", chainId: "qorechain-diana", signer: address, bodyBytes: v1, authInfoBytes: auth };

    let err: unknown;
    try {
      await assertPqLayerMatchesRegisteredKey({ ...args, fetch: mockFetch(v2Route) });
    } catch (e) {
      err = e;
    }
    expect((err as QoreSignError).code).toBe("PQ_SIGNATURE_INVALID");
    expect((err as QoreSignError).details).toMatchObject({ reason: "invalid_signature" });

    const legacy = await assertPqLayerMatchesRegisteredKey({ ...args, fetch: mockFetch(v2Route), allowLegacyEither: true });
    expect(legacy).toEqual({ valid: true, signBytesVersion: "v1" });

    // An explicit version is used as given, without asking the network.
    const calls: string[] = [];
    const explicit = await assertPqLayerMatchesRegisteredKey({ ...args, fetch: mockFetch(accountRoute, calls), signBytesVersion: "v1" });
    expect(explicit).toEqual({ valid: true, signBytesVersion: "v1" });
    expect(calls.every((c) => c.includes("/qorechain/pqc/v1/account/"))).toBe(true);
    expect(await code(assertPqLayerMatchesRegisteredKey({ ...args, fetch: mockFetch(accountRoute), signBytesVersion: "v2" }))).toBe(
      "PQ_SIGNATURE_INVALID",
    );
    expect(
      await code(
        assertPqLayerMatchesRegisteredKey({ ...args, fetch: mockFetch(v2Route), signBytesVersion: "either" as unknown as "v2" }),
      ),
    ).toBe("INVALID_ARGUMENT");

    // A network that verifies v1 (switch listed but off) accepts the v1 layer.
    const off: Route = (url, init) => (url.endsWith(PROTOCOL_FEATURES_PATH) ? { status: 200, body: features(false) } : accountRoute(url, init));
    expect(await assertPqLayerMatchesRegisteredKey({ ...args, fetch: mockFetch(off) })).toEqual({ valid: true, signBytesVersion: "v1" });
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
