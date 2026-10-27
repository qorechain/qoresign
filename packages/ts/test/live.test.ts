// SPDX-License-Identifier: Apache-2.0
//
// End-to-end checks against the qorechain-diana testnet. Skipped unless
// QORE_LIVE_TEST=1 and QORE_TEST_MNEMONIC (a funded testnet account) are set.
// Never point this at mainnet.

import { encodeSecp256k1Pubkey } from "@cosmjs/amino";
import { encodePubkey, makeAuthInfoBytes } from "@cosmjs/proto-signing";
import { generateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { MsgSend } from "cosmjs-types/cosmos/bank/v1beta1/tx";
import { SignMode } from "cosmjs-types/cosmos/tx/signing/v1beta1/signing";
import { TxBody } from "cosmjs-types/cosmos/tx/v1beta1/tx";
import { describe, expect, it } from "vitest";
import {
  addressFromPublicKey,
  buildRegisterPqKeyMessage,
  createSiwqMessage,
  deriveCanonicalPqKey,
  deriveClassicalKey,
  evaluateLayerState,
  signHybrid,
  signSiwq,
  toHex,
  type ClassicalKey,
  type PqKeyPair,
} from "../src/index.js";
import {
  broadcastTx,
  fetchCommittedExtensionTypeUrls,
  fetchPqKeyStatus,
  simulateTx,
  submitWithSignBytesFallback,
  verifySiwqWithChain,
} from "../src/network.js";

const LIVE = process.env.QORE_LIVE_TEST === "1" && !!process.env.QORE_TEST_MNEMONIC;
const REST = process.env.QORE_REST ?? "https://api-testnet.qore.host";
const CHAIN_ID = process.env.QORE_CHAIN_ID ?? "qorechain-diana";
const GAS_PRICE = 1n; // 0.1 uqor per gas, expressed as tenths
if (LIVE && CHAIN_ID === "qorechain-vladi") throw new Error("live tests must not run on mainnet");

interface Account {
  address: string;
  classical: ClassicalKey;
  pq: PqKeyPair;
}

function account(mnemonic: string): Account {
  const classical = deriveClassicalKey({ mnemonic });
  const address = addressFromPublicKey(classical.publicKey, "secp256k1").bech32;
  return { address, classical, pq: deriveCanonicalPqKey({ mnemonic, address }) };
}

async function accountInfo(address: string): Promise<{ accountNumber: bigint; sequence: bigint }> {
  const res = await fetch(`${REST}/cosmos/auth/v1beta1/account_info/${address}`);
  const body = (await res.json()) as { info?: { account_number?: string; sequence?: string } };
  if (!body.info) throw new Error(`account ${address} not found`);
  return { accountNumber: BigInt(body.info.account_number ?? "0"), sequence: BigInt(body.info.sequence ?? "0") };
}

async function waitForTx(txhash: string): Promise<{ gasUsed: bigint; code: number }> {
  for (let i = 0; i < 40; i++) {
    const res = await fetch(`${REST}/cosmos/tx/v1beta1/txs/${txhash}`);
    if (res.ok) {
      const body = (await res.json()) as { tx_response: { gas_used: string; code: number } };
      return { gasUsed: BigInt(body.tx_response.gas_used), code: body.tx_response.code };
    }
    await new Promise((r) => setTimeout(r, 1500));
  }
  throw new Error(`transaction ${txhash} was not committed`);
}

function body(messages: { typeUrl: string; value: Uint8Array }[], memo: string): Uint8Array {
  return TxBody.encode(TxBody.fromPartial({ messages, memo })).finish();
}

function sendMsg(from: string, to: string, amount: string) {
  return {
    typeUrl: "/cosmos.bank.v1beta1.MsgSend",
    value: MsgSend.encode(MsgSend.fromPartial({ fromAddress: from, toAddress: to, amount: [{ denom: "uqor", amount }] })).finish(),
  };
}

function authInfo(acc: Account, sequence: bigint, gasLimit: bigint): Uint8Array {
  const fee = (gasLimit * GAS_PRICE + 9n) / 10n;
  return makeAuthInfoBytes(
    [{ pubkey: encodePubkey(encodeSecp256k1Pubkey(acc.classical.publicKey)), sequence }],
    [{ denom: "uqor", amount: fee.toString() }],
    Number(gasLimit),
    undefined,
    undefined,
    SignMode.SIGN_MODE_DIRECT,
  );
}

/** Simulate, then sign with the suggested gas limit and broadcast. */
async function send(acc: Account, bodyBytes: Uint8Array, mode: "hybrid" | "classicalOnly") {
  const { accountNumber, sequence } = await accountInfo(acc.address);
  const sign = (gas: bigint) =>
    signHybrid({
      chainId: CHAIN_ID,
      accountNumber,
      bodyBytes,
      authInfoBytes: authInfo(acc, sequence, gas),
      classicalKey: acc.classical,
      pqKey: acc.pq,
      mode,
    });
  const sim = await simulateTx({ rest: REST, txBytes: sign(400_000n).txBytes });
  const res =
    mode === "hybrid"
      ? await submitWithSignBytesFallback({ rest: REST, chainId: CHAIN_ID, sign: () => sign(sim.suggestedGasLimit).txBytes })
      : await broadcastTx({ rest: REST, txBytes: sign(sim.suggestedGasLimit).txBytes });
  expect(res.code, res.log).toBe(0);
  const committed = await waitForTx(res.txhash);
  expect(committed.code).toBe(0);
  return { txhash: res.txhash, sim, gasUsed: committed.gasUsed };
}

describe.skipIf(!LIVE)("qorechain-diana", () => {
  const funded = LIVE ? account(process.env.QORE_TEST_MNEMONIC!) : (undefined as unknown as Account);

  it("the canonical key is the one registered on chain", async () => {
    const status = await fetchPqKeyStatus({ rest: REST, address: funded.address });
    expect(status.registered).toBe(true);
    expect(toHex(status.publicKey!)).toBe(toHex(funded.pq.publicKey));
  });

  it("sends a hybrid transaction with a simulated gas limit", async () => {
    const { txhash, sim, gasUsed } = await send(funded, body([sendMsg(funded.address, funded.address, "1")], "qoresign live test"), "hybrid");
    expect(sim.suggestedGasLimit >= gasUsed).toBe(true);
    const urls = await fetchCommittedExtensionTypeUrls({ rest: REST, txhash });
    expect(evaluateLayerState({ lane: "native", onQoreChain: true, signedWithPqLayer: true, committedExtensionTypeUrls: urls })).toBe(
      "protected",
    );
    console.log(`hybrid send: simulated ${sim.gasUsed}, limit ${sim.suggestedGasLimit}, used ${gasUsed}`);
  }, 120_000);

  it("registers a new account's key with a proof of possession, then signs hybrid", async () => {
    const fresh = account(generateMnemonic(wordlist, 256));
    await send(funded, body([sendMsg(funded.address, fresh.address, "200000")], "qoresign live test: fund"), "hybrid");
    const msg = buildRegisterPqKeyMessage({
      chainId: CHAIN_ID,
      account: fresh.address,
      pqKey: fresh.pq,
      classicalPublicKey: fresh.classical.publicKey,
    });
    await send(fresh, TxBody.encode(TxBody.fromPartial({ messages: [msg] })).finish(), "classicalOnly");
    const status = await fetchPqKeyStatus({ rest: REST, address: fresh.address });
    expect(status.registered).toBe(true);
    expect(status.possessionProven).toBe(true);
    expect(toHex(status.publicKey!)).toBe(toHex(fresh.pq.publicKey));
    // return what is left, signed hybrid by the new account
    await send(fresh, body([sendMsg(fresh.address, funded.address, "100000")], "qoresign live test: return"), "hybrid");
  }, 240_000);

  it("verifies a sign-in against the key on chain", async () => {
    const message = createSiwqMessage({
      domain: "localhost:3000",
      address: funded.address,
      uri: "http://localhost:3000",
      chainId: CHAIN_ID,
      nonce: "livetest" + Date.now(),
      issuedAt: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
    });
    const signature = signSiwq({ message, classicalKey: funded.classical, pqKey: funded.pq });
    const fields = await verifySiwqWithChain({
      rest: REST,
      address: funded.address,
      message,
      signature,
      domain: "localhost:3000",
      nonce: message.match(/Nonce: (\S+)/)![1]!,
      chainId: CHAIN_ID,
    });
    expect(fields.possessionProven).toBe(true);
  }, 60_000);
});
