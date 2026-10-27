// SPDX-License-Identifier: Apache-2.0
//
// `@qorechain/qoresign/network`: the parts that talk to a QoreChain REST
// endpoint (Cosmos SDK gateway). Everything here is optional; the core
// signs and verifies offline.

import { signBytesVersionForApplied, SIGN_BYTES_V2_UPGRADES } from "@qorechain/pqc";
import { fromBase64, toBase64 } from "./bytes.js";
import { QoreSignError } from "./errors.js";
import type { SignBytesVersion } from "./sign.js";
import { verifyMessage, type MessageSignature } from "./message.js";
import { verifySiwq, type SiwqFields, type VerifySiwqArgs } from "./siwq.js";
import { verifyPqLayer, type PqLayerResult } from "./verify.js";

export type FetchLike = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string },
) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

export interface RestOptions {
  /** REST endpoint, e.g. `https://api-testnet.qore.host`. */
  rest: string;
  fetch?: FetchLike;
}

function base(rest: string): string {
  if (!rest) throw new QoreSignError("INVALID_ARGUMENT", "a REST endpoint is required");
  return rest.replace(/\/+$/, "");
}

async function getJson(opts: RestOptions, path: string): Promise<{ status: number; body: Record<string, unknown> }> {
  // Called as f(...), never as a method of an object: a global fetch invoked with a
  // foreign `this` throws in browsers.
  const f: FetchLike = opts.fetch ?? ((url, init) => globalThis.fetch(url, init));
  const url = `${base(opts.rest)}${path}`;
  let res;
  try {
    res = await f(url);
  } catch (err) {
    throw new QoreSignError("NETWORK_UNAVAILABLE", `request to ${path} failed`, { cause: String(err) });
  }
  let body: Record<string, unknown> = {};
  try {
    body = (await res.json()) as Record<string, unknown>;
  } catch {
    if (res.ok) throw new QoreSignError("NETWORK_UNAVAILABLE", `${path} returned a non-JSON body`);
  }
  return { status: res.status, body };
}

/** The ML-DSA-87 key an account has registered on chain. */
export interface PqKeyStatus {
  registered: boolean;
  algorithmId?: number;
  publicKey?: Uint8Array;
  /** `hybrid`, `pqc_only` or `classical_only`. */
  keyType?: string;
  /** True when the key was registered with a proof of possession. */
  possessionProven?: boolean;
}

/** Read `/qorechain/pqc/v1/account/{address}`. */
export async function fetchPqKeyStatus(opts: RestOptions & { address: string }): Promise<PqKeyStatus> {
  const { status, body } = await getJson(opts, `/qorechain/pqc/v1/account/${encodeURIComponent(opts.address)}`);
  if (body.found === false || status === 404) return { registered: false };
  const acc = body.account as Record<string, unknown> | undefined;
  if (status >= 400 || body.found !== true || !acc) {
    throw new QoreSignError("NETWORK_UNAVAILABLE", `could not read the PQC key of ${opts.address} (HTTP ${status})`);
  }
  const pk = typeof acc.public_key === "string" && acc.public_key !== "" ? fromBase64(acc.public_key) : undefined;
  return {
    registered: pk !== undefined,
    algorithmId: Number(acc.algorithm_id),
    publicKey: pk,
    keyType: typeof acc.key_type === "string" ? acc.key_type : undefined,
    possessionProven: acc.possession_proven === true,
  };
}

/** Height at which an upgrade plan was applied, or 0n. */
export async function fetchAppliedPlanHeight(opts: RestOptions & { name: string }): Promise<bigint> {
  const { status, body } = await getJson(opts, `/cosmos/upgrade/v1beta1/applied_plan/${encodeURIComponent(opts.name)}`);
  if (status >= 400) throw new QoreSignError("NETWORK_UNAVAILABLE", `could not read applied plan ${opts.name}`);
  return BigInt(typeof body.height === "string" && body.height !== "" ? body.height : "0");
}

/** The hybrid sign-bytes version the network verifies now. */
export async function resolveSignBytesVersion(opts: RestOptions & { chainId: string }): Promise<SignBytesVersion> {
  const applied: Record<string, bigint> = {};
  for (const name of SIGN_BYTES_V2_UPGRADES) applied[name] = await fetchAppliedPlanHeight({ ...opts, name });
  return signBytesVersionForApplied(opts.chainId, applied);
}

/**
 * Check a dApp-prepared body's ML-DSA-87 layer against the key the signer has
 * registered on chain. Throws when the layer is missing, malformed or invalid,
 * when the account has no key, or when the key cannot be read.
 */
export async function assertPqLayerMatchesRegisteredKey(
  opts: RestOptions & { chainId: string; signer: string; bodyBytes: Uint8Array; authInfoBytes: Uint8Array },
): Promise<PqLayerResult> {
  const status = await fetchPqKeyStatus({ ...opts, address: opts.signer });
  if (!status.registered || !status.publicKey) {
    throw new QoreSignError("KEY_NOT_REGISTERED", `${opts.signer} has no ML-DSA-87 key on the network`);
  }
  const result = verifyPqLayer({
    chainId: opts.chainId,
    bodyBytes: opts.bodyBytes,
    authInfoBytes: opts.authInfoBytes,
    pqPublicKey: status.publicKey,
    signBytesVersion: "either",
  });
  if (!result.valid) {
    const code = result.reason === "missing" ? "PQ_LAYER_MISSING" : result.reason === "duplicated" ? "PQ_LAYER_DUPLICATED" : "PQ_SIGNATURE_INVALID";
    throw new QoreSignError(code, `the ML-DSA-87 layer is not valid for ${opts.signer} (${result.reason})`, {
      reason: result.reason,
    });
  }
  return result;
}

/** {@link verifySiwq} against the ML-DSA-87 key the account has registered on chain. */
export async function verifySiwqWithChain(
  args: Omit<VerifySiwqArgs, "pqPublicKey"> & RestOptions & { address: string },
): Promise<SiwqFields & { possessionProven: boolean }> {
  const status = await fetchPqKeyStatus({ rest: args.rest, fetch: args.fetch, address: args.address });
  if ((args.requirePq ?? true) && !status.registered) {
    throw new QoreSignError("KEY_NOT_REGISTERED", `${args.address} has no ML-DSA-87 key on the network`);
  }
  const fields = verifySiwq({ ...args, pqPublicKey: status.publicKey });
  if (fields.address !== args.address) {
    throw new QoreSignError("ADDRESS_MISMATCH", `the message is for ${fields.address}, not ${args.address}`);
  }
  return { ...fields, possessionProven: status.possessionProven === true };
}

/** {@link verifyMessage} against the ML-DSA-87 key the signer has registered on chain. */
export async function verifyMessageWithChain(
  opts: RestOptions & {
    chainId: string;
    signer: string;
    data: Uint8Array | string;
    signature: MessageSignature;
    requirePq?: boolean;
  },
): Promise<{ possessionProven: boolean }> {
  const status = await fetchPqKeyStatus({ rest: opts.rest, fetch: opts.fetch, address: opts.signer });
  if ((opts.requirePq ?? true) && !status.registered) {
    throw new QoreSignError("KEY_NOT_REGISTERED", `${opts.signer} has no ML-DSA-87 key on the network`);
  }
  verifyMessage({ ...opts, pqPublicKey: status.publicKey });
  return { possessionProven: status.possessionProven === true };
}

/** A refusal reported by the network. */
export interface ChainRefusal {
  code: number;
  codespace: string;
  log: string;
}

export type BalanceDeltas = Record<string, Record<string, bigint>>;

export interface SimulationResult {
  gasUsed: bigint;
  /** Gas limit to sign with (see {@link suggestGasLimit}). */
  suggestedGasLimit: bigint;
  /** Net balance change per address and denom, from `coin_spent` / `coin_received` events. */
  balanceDeltas: BalanceDeltas;
  events: { type: string; attributes: { key: string; value: string }[] }[];
}

/** Margin the network still needs on top of the simulated gas of a hybrid transaction. */
export const HYBRID_VERIFY_GAS = 40_000n;
export const LEGACY_GAS_MULTIPLIER_PERCENT = 140n;

/**
 * Gas limit for a simulated hybrid transaction.
 *
 * Nodes from v3.2.5 charge the ML-DSA-87 verification during simulation, so
 * the result only needs a small margin: `ceil(gasUsed * 1.02) + 2000`.
 * Older nodes leave part of it out of the simulation: `ceil((gasUsed + 40000) * 1.4)`.
 * On the native lane the fee is gas limit times price, so the tighter limit
 * is cheaper.
 */
export function suggestGasLimit(gasUsed: bigint, exactSimulation: boolean): bigint {
  if (exactSimulation) return (gasUsed * 102n + 99n) / 100n + 2000n;
  return ((gasUsed + HYBRID_VERIFY_GAS) * LEGACY_GAS_MULTIPLIER_PERCENT + 99n) / 100n;
}

/** Whether the node simulates the hybrid verification cost exactly (v3.2.5 and later). */
export async function hasExactSimulation(opts: RestOptions): Promise<boolean> {
  return (await fetchAppliedPlanHeight({ ...opts, name: "v3.2.5" })) > 0n;
}

function parseRefusal(body: Record<string, unknown>): ChainRefusal {
  const log = typeof body.message === "string" ? body.message : JSON.stringify(body);
  const m = /codespace[:= ]+(\w+)\s+code[:= ]+(\d+)/i.exec(log);
  return {
    code: m ? Number(m[2]) : Number(body.code ?? 0),
    codespace: m ? m[1]! : "",
    log,
  };
}

function balanceDeltas(events: SimulationResult["events"]): BalanceDeltas {
  const out: BalanceDeltas = {};
  const add = (addr: string, amounts: string, sign: 1n | -1n) => {
    for (const part of amounts.split(",")) {
      const m = /^(\d+)(.+)$/.exec(part.trim());
      if (!m) continue;
      const denom = m[2]!;
      out[addr] ??= {};
      out[addr]![denom] = (out[addr]![denom] ?? 0n) + sign * BigInt(m[1]!);
    }
  };
  for (const ev of events) {
    const attr = (k: string) => ev.attributes.find((a) => a.key === k)?.value;
    if (ev.type === "coin_spent") {
      const who = attr("spender");
      const amt = attr("amount");
      if (who && amt) add(who, amt, -1n);
    } else if (ev.type === "coin_received") {
      const who = attr("receiver");
      const amt = attr("amount");
      if (who && amt) add(who, amt, 1n);
    }
  }
  return out;
}

/**
 * Simulate a signed transaction. A failed simulation throws
 * `SIMULATION_FAILED` with the network's refusal in `details`; treat it as a
 * reason not to sign, never as a warning.
 */
export async function simulateTx(opts: RestOptions & { txBytes: Uint8Array; exactSimulation?: boolean }): Promise<SimulationResult> {
  const f: FetchLike = opts.fetch ?? ((url, init) => globalThis.fetch(url, init));
  const url = `${base(opts.rest)}/cosmos/tx/v1beta1/simulate`;
  let res;
  try {
    res = await f(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tx_bytes: toBase64(opts.txBytes) }),
    });
  } catch (err) {
    throw new QoreSignError("NETWORK_UNAVAILABLE", "simulation request failed", { cause: String(err) });
  }
  const body = ((await res.json().catch(() => ({}))) ?? {}) as Record<string, unknown>;
  if (!res.ok) {
    const refusal = parseRefusal(body);
    throw new QoreSignError("SIMULATION_FAILED", `simulation refused: ${refusal.log}`, { ...refusal });
  }
  const gasInfo = (body.gas_info ?? {}) as Record<string, unknown>;
  const gasUsed = BigInt(String(gasInfo.gas_used ?? "0"));
  const result = (body.result ?? {}) as Record<string, unknown>;
  const events = (Array.isArray(result.events) ? result.events : []) as SimulationResult["events"];
  const exact = opts.exactSimulation ?? (await hasExactSimulation(opts));
  return { gasUsed, suggestedGasLimit: suggestGasLimit(gasUsed, exact), balanceDeltas: balanceDeltas(events), events };
}

export interface BroadcastResult {
  txhash: string;
  code: number;
  codespace: string;
  log: string;
}

/** Broadcast (sync mode: returns after the mempool check). */
export async function broadcastTx(opts: RestOptions & { txBytes: Uint8Array }): Promise<BroadcastResult> {
  const f: FetchLike = opts.fetch ?? ((url, init) => globalThis.fetch(url, init));
  const url = `${base(opts.rest)}/cosmos/tx/v1beta1/txs`;
  let res;
  try {
    res = await f(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tx_bytes: toBase64(opts.txBytes), mode: "BROADCAST_MODE_SYNC" }),
    });
  } catch (err) {
    throw new QoreSignError("NETWORK_UNAVAILABLE", "broadcast request failed", { cause: String(err) });
  }
  const body = ((await res.json().catch(() => ({}))) ?? {}) as Record<string, unknown>;
  const tr = body.tx_response as Record<string, unknown> | undefined;
  if (!tr) {
    const refusal = parseRefusal(body);
    return { txhash: "", code: refusal.code || 1, codespace: refusal.codespace, log: refusal.log };
  }
  return {
    txhash: String(tr.txhash ?? ""),
    code: Number(tr.code ?? 0),
    codespace: String(tr.codespace ?? ""),
    log: String(tr.raw_log ?? ""),
  };
}

/** True for the refusal the network gives when the PQC layer was signed over the other sign-bytes version. */
export function isSignBytesRefusal(r: { code: number; codespace: string }): boolean {
  return r.codespace === "pqc" && r.code === 21;
}

/**
 * Broadcast a hybrid transaction, retrying once with the other sign-bytes
 * version when the network refuses the one used. `sign` is called with the
 * version to use and returns the encoded transaction (the sequence is
 * unchanged: a refusal at the mempool check does not consume it).
 */
export async function submitWithSignBytesFallback(
  opts: RestOptions & {
    chainId: string;
    sign: (version: SignBytesVersion) => Uint8Array | Promise<Uint8Array>;
    signBytesVersion?: SignBytesVersion;
  },
): Promise<BroadcastResult & { signBytesVersion: SignBytesVersion }> {
  const first = opts.signBytesVersion ?? (await resolveSignBytesVersion(opts));
  let version = first;
  let res = await broadcastTx({ ...opts, txBytes: await opts.sign(version) });
  if (res.code !== 0 && isSignBytesRefusal(res)) {
    version = first === "v1" ? "v2" : "v1";
    res = await broadcastTx({ ...opts, txBytes: await opts.sign(version) });
  }
  return { ...res, signBytesVersion: version };
}

/** Extension type URLs of a committed transaction, for {@link evaluateLayerState}. */
export async function fetchCommittedExtensionTypeUrls(opts: RestOptions & { txhash: string }): Promise<string[] | undefined> {
  const { status, body } = await getJson(opts, `/cosmos/tx/v1beta1/txs/${encodeURIComponent(opts.txhash)}`);
  if (status === 404) return undefined;
  if (status >= 400) throw new QoreSignError("NETWORK_UNAVAILABLE", `could not read transaction ${opts.txhash}`);
  const tx = body.tx as Record<string, unknown> | undefined;
  const bodyJson = tx?.body as Record<string, unknown> | undefined;
  const opts2 = bodyJson?.extension_options;
  if (!Array.isArray(opts2)) return [];
  return (opts2 as Record<string, unknown>[]).map((e) => String(e["@type"] ?? e.type_url ?? ""));
}

export { fetchEvmWindow, inspectTransaction, type EvmWindow, type InspectedTransaction, type TxSecurityTier } from "./inspect.js";
