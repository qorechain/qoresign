// SPDX-License-Identifier: Apache-2.0
//
// Reading a committed transaction back: its messages, signer, fee and the
// state of its ML-DSA-87 layer, plus an account's EVM authorization window.

import { fromBase64, toBase64 } from "./bytes.js";
import { QoreSignError } from "./errors.js";
import { addressFromPublicKey, type ClassicalKeyType } from "./keys.js";
import { fetchPqKeyStatus, type FetchLike, type RestOptions } from "./network.js";
import { decodeAny, decodeString, decodeTxRaw, encodeSignDoc, readFields, WIRE_LEN, WIRE_VARINT } from "./proto.js";
import { classicalVerify, pqcLayers } from "./sign.js";
import { verifyPqLayer, type PqLayerResult } from "./verify.js";

/**
 * How a transaction is protected, using the same classification as the public
 * QoreChain explorer:
 * - `pqc`: carries the ML-DSA-87 layer (hybrid signature);
 * - `enrollment`: registers an account's ML-DSA-87 key, which is signed with the classical key by design;
 * - `shake`: a native-lane transaction without the layer;
 * - `classical`: an EVM-lane transaction (secp256k1 only).
 */
export type TxSecurityTier = "pqc" | "enrollment" | "shake" | "classical";

const KEY_MANAGEMENT_TYPES = [
  "/qorechain.pqc.v1.MsgRegisterPQCKey",
  "/qorechain.pqc.v1.MsgRegisterPQCKeyV2",
  "/qorechain.pqc.v1.MsgRotatePQCKey",
];

export interface InspectedTransaction {
  txhash: string;
  chainId: string;
  height: bigint;
  /** 0 when the transaction succeeded. */
  code: number;
  codespace: string;
  memo: string;
  messages: { typeUrl: string; value: string }[];
  /** First signer, when the transaction carries signer infos (EVM-lane transactions do not). */
  signer?: { address: string; keyType: ClassicalKeyType; publicKey: string; sequence: bigint };
  fee: { amount: { denom: string; amount: string }[]; gasLimit: bigint; payer?: string; granter?: string };
  /** Classical signature check against the signer's current account number; undefined when not checkable. */
  classicalSignatureValid?: boolean;
  pqLayer: {
    present: boolean;
    count: number;
    algorithmId?: number;
    /** Verified against the key the signer has registered now (a later rotation makes this false). */
    verified?: boolean;
    signBytesVersion?: PqLayerResult["signBytesVersion"];
    reason?: string;
  };
  tier: TxSecurityTier;
}

function base(rest: string): string {
  if (!rest) throw new QoreSignError("INVALID_ARGUMENT", "a REST endpoint is required");
  return rest.replace(/\/+$/, "");
}

async function getJson(f: FetchLike, url: string): Promise<{ status: number; body: Record<string, unknown> }> {
  let res;
  try {
    res = await f(url);
  } catch (err) {
    throw new QoreSignError("NETWORK_UNAVAILABLE", "request failed", { cause: String(err) });
  }
  const body = ((await res.json().catch(() => ({}))) ?? {}) as Record<string, unknown>;
  return { status: res.status, body };
}

function parseFee(bytes: Uint8Array | undefined): InspectedTransaction["fee"] {
  const fee: InspectedTransaction["fee"] = { amount: [], gasLimit: 0n };
  if (!bytes) return fee;
  for (const f of readFields(bytes)) {
    if (f.field === 1 && f.wireType === WIRE_LEN && f.bytes) {
      let denom = "";
      let amount = "";
      for (const c of readFields(f.bytes)) {
        if (c.field === 1 && c.bytes) denom = decodeString(c.bytes);
        if (c.field === 2 && c.bytes) amount = decodeString(c.bytes);
      }
      fee.amount.push({ denom, amount });
    } else if (f.field === 2 && f.wireType === WIRE_VARINT) fee.gasLimit = f.varint ?? 0n;
    else if (f.field === 3 && f.bytes) fee.payer = decodeString(f.bytes);
    else if (f.field === 4 && f.bytes) fee.granter = decodeString(f.bytes);
  }
  return fee;
}

function parseSigner(authInfo: Uint8Array): { keyType: ClassicalKeyType; publicKey: Uint8Array; sequence: bigint } | undefined {
  for (const f of readFields(authInfo)) {
    if (f.field !== 1 || !f.bytes) continue;
    let pub: Uint8Array | undefined;
    let typeUrl = "";
    let sequence = 0n;
    for (const s of readFields(f.bytes)) {
      if (s.field === 1 && s.bytes) {
        const any = decodeAny(s.bytes);
        typeUrl = any.typeUrl;
        for (const k of readFields(any.value)) if (k.field === 1 && k.bytes) pub = k.bytes;
      } else if (s.field === 3 && s.wireType === WIRE_VARINT) sequence = s.varint ?? 0n;
    }
    if (!pub) return undefined;
    return { keyType: /ethsecp256k1/i.test(typeUrl) ? "eth_secp256k1" : "secp256k1", publicKey: pub, sequence };
  }
  return undefined;
}

/** Encoded transaction bytes for a hash: from an RPC node when given, else re-encoded by the REST gateway. */
async function fetchTxBytes(f: FetchLike, opts: { rest: string; rpc?: string; txhash: string; txJson: unknown }): Promise<Uint8Array> {
  if (opts.rpc) {
    const { status, body } = await getJson(f, `${opts.rpc.replace(/\/+$/, "")}/tx?hash=0x${opts.txhash}`);
    const tx = (body.result as Record<string, unknown> | undefined)?.tx;
    if (status < 400 && typeof tx === "string") return fromBase64(tx);
  }
  let res;
  try {
    res = await f(`${base(opts.rest)}/cosmos/tx/v1beta1/encode`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tx: opts.txJson }),
    });
  } catch (err) {
    throw new QoreSignError("NETWORK_UNAVAILABLE", "encode request failed", { cause: String(err) });
  }
  const body = ((await res.json().catch(() => ({}))) ?? {}) as Record<string, unknown>;
  if (!res.ok || typeof body.tx_bytes !== "string") {
    throw new QoreSignError("NETWORK_UNAVAILABLE", "could not obtain the transaction bytes");
  }
  return fromBase64(body.tx_bytes);
}

/**
 * Read a committed transaction and report its messages, signer, fee, the
 * state of its ML-DSA-87 layer and its security tier. Returns `undefined`
 * when the network does not know the hash. Pass `rpc` to read the exact
 * committed bytes from an RPC node; otherwise the REST gateway re-encodes them.
 */
export async function inspectTransaction(
  opts: RestOptions & { txhash: string; chainId: string; rpc?: string },
): Promise<InspectedTransaction | undefined> {
  const f: FetchLike = opts.fetch ?? ((url, init) => globalThis.fetch(url, init));
  const txhash = opts.txhash.replace(/^0x/i, "").toUpperCase();
  if (!/^[0-9A-F]{64}$/.test(txhash)) throw new QoreSignError("INVALID_ARGUMENT", "a transaction hash is 64 hex characters");
  const { status, body } = await getJson(f, `${base(opts.rest)}/cosmos/tx/v1beta1/txs/${txhash}`);
  if (status === 404 || (status >= 400 && /not found/i.test(String(body.message ?? "")))) return undefined;
  const tr = body.tx_response as Record<string, unknown> | undefined;
  if (status >= 400 || !tr) throw new QoreSignError("NETWORK_UNAVAILABLE", `could not read transaction ${txhash} (HTTP ${status})`);

  const txBytes = await fetchTxBytes(f, { rest: opts.rest, rpc: opts.rpc, txhash, txJson: body.tx });
  const raw = decodeTxRaw(txBytes);
  const messages: InspectedTransaction["messages"] = [];
  let memo = "";
  for (const field of readFields(raw.bodyBytes)) {
    if (field.field === 1 && field.bytes) {
      const any = decodeAny(field.bytes);
      messages.push({ typeUrl: any.typeUrl, value: toBase64(any.value) });
    } else if (field.field === 2 && field.bytes) memo = decodeString(field.bytes);
  }
  let feeBytes: Uint8Array | undefined;
  for (const field of readFields(raw.authInfoBytes)) if (field.field === 2 && field.bytes) feeBytes = field.bytes;

  const layers = pqcLayers(raw.bodyBytes);
  const out: InspectedTransaction = {
    txhash,
    chainId: opts.chainId,
    height: BigInt(String(tr.height ?? "0")),
    code: Number(tr.code ?? 0),
    codespace: String(tr.codespace ?? ""),
    memo,
    messages,
    fee: parseFee(feeBytes),
    pqLayer: { present: layers.length > 0, count: layers.length, algorithmId: layers[0]?.algorithmId },
    tier: "shake",
  };

  const isEvm = messages.some((m) => m.typeUrl.endsWith("MsgEthereumTx"));
  if (layers.length > 0) out.tier = "pqc";
  else if (messages.some((m) => KEY_MANAGEMENT_TYPES.includes(m.typeUrl))) out.tier = "enrollment";
  else if (isEvm) out.tier = "classical";

  const signer = parseSigner(raw.authInfoBytes);
  if (signer) {
    const address = addressFromPublicKey(signer.publicKey, signer.keyType).bech32;
    out.signer = { address, keyType: signer.keyType, publicKey: toBase64(signer.publicKey), sequence: signer.sequence };
    const info = await getJson(f, `${base(opts.rest)}/cosmos/auth/v1beta1/account_info/${address}`);
    const accountNumber = (info.body.info as Record<string, unknown> | undefined)?.account_number;
    if (info.status < 400 && accountNumber !== undefined && raw.signatures[0]) {
      const signDoc = encodeSignDoc({
        bodyBytes: raw.bodyBytes,
        authInfoBytes: raw.authInfoBytes,
        chainId: opts.chainId,
        accountNumber: BigInt(String(accountNumber)),
      });
      out.classicalSignatureValid = classicalVerify(signer.keyType, signer.publicKey, signDoc, raw.signatures[0]);
    }
    if (layers.length > 0) {
      const status = await fetchPqKeyStatus({ rest: opts.rest, fetch: opts.fetch, address });
      if (!status.registered || !status.publicKey) {
        out.pqLayer.verified = false;
        out.pqLayer.reason = "signer has no registered ML-DSA-87 key now";
      } else {
        const r = verifyPqLayer({
          chainId: opts.chainId,
          bodyBytes: raw.bodyBytes,
          authInfoBytes: raw.authInfoBytes,
          pqPublicKey: status.publicKey,
          signBytesVersion: "either",
        });
        out.pqLayer.verified = r.valid;
        if (r.signBytesVersion) out.pqLayer.signBytesVersion = r.signBytesVersion;
        if (r.reason) out.pqLayer.reason = r.reason;
      }
    }
  } else if (layers.length > 0) {
    out.pqLayer.reason = "the transaction has no signer info to check the layer against";
  }
  return out;
}

/** An account's EVM authorization window (`/qorechain/pqc/v1/evm_window/{address}`). */
export interface EvmWindow {
  found: boolean;
  live: boolean;
  openedHeight: bigint;
  expiryHeight: bigint;
  maxTxs: bigint;
  usedTxs: bigint;
  maxValue: string;
  usedValue: string;
  remainingBlocks: bigint;
  remainingTxs: bigint;
  remainingValue: string;
  nativeOnly: boolean;
  allowedTargets: string[];
}

export async function fetchEvmWindow(opts: RestOptions & { address: string }): Promise<EvmWindow> {
  const f: FetchLike = opts.fetch ?? ((url, init) => globalThis.fetch(url, init));
  const { status, body } = await getJson(f, `${base(opts.rest)}/qorechain/pqc/v1/evm_window/${encodeURIComponent(opts.address)}`);
  if (status >= 400) throw new QoreSignError("NETWORK_UNAVAILABLE", `could not read the EVM window of ${opts.address} (HTTP ${status})`);
  const big = (v: unknown) => BigInt(typeof v === "string" && v !== "" ? v : typeof v === "number" ? v : 0);
  const str = (v: unknown) => (typeof v === "string" ? v : "");
  return {
    found: body.found === true,
    live: body.live === true,
    openedHeight: big(body.opened_height),
    expiryHeight: big(body.expiry_height),
    maxTxs: big(body.max_txs),
    usedTxs: big(body.used_txs),
    maxValue: str(body.max_value),
    usedValue: str(body.used_value),
    remainingBlocks: big(body.remaining_blocks),
    remainingTxs: big(body.remaining_txs),
    remainingValue: str(body.remaining_value),
    nativeOnly: body.native_only === true,
    allowedTargets: Array.isArray(body.allowed_targets) ? body.allowed_targets.map(String) : [],
  };
}
