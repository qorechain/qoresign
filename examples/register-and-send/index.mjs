// SPDX-License-Identifier: Apache-2.0
// Register the account's ML-DSA-87 key if needed, then send 1 uqor to itself
// with a hybrid signature, on the qorechain-diana testnet.
//
//   QORE_MNEMONIC="<testnet mnemonic>" node index.mjs
import { encodeSecp256k1Pubkey } from "@cosmjs/amino";
import { encodePubkey, makeAuthInfoBytes } from "@cosmjs/proto-signing";
import { MsgSend } from "cosmjs-types/cosmos/bank/v1beta1/tx";
import { TxBody } from "cosmjs-types/cosmos/tx/v1beta1/tx";
import {
  addressFromPublicKey,
  buildRegisterPqKeyMessage,
  deriveCanonicalPqKey,
  deriveClassicalKey,
  evaluateLayerState,
  signHybrid,
  toHex,
} from "@qorechain/qoresign";
import {
  broadcastTx,
  fetchCommittedExtensionTypeUrls,
  fetchPqKeyStatus,
  simulateTx,
  submitWithSignBytesFallback,
} from "@qorechain/qoresign/network";

const REST = process.env.QORE_REST ?? "https://api-testnet.qore.host";
const CHAIN_ID = process.env.QORE_CHAIN_ID ?? "qorechain-diana";
if (CHAIN_ID === "qorechain-vladi") throw new Error("this example only runs on the testnet");
const mnemonic = process.env.QORE_MNEMONIC;
if (!mnemonic) throw new Error("set QORE_MNEMONIC to a funded testnet account");

const classical = deriveClassicalKey({ mnemonic });
const address = addressFromPublicKey(classical.publicKey, "secp256k1").bech32;
const pq = deriveCanonicalPqKey({ mnemonic, address });
console.log("account", address);

async function accountInfo() {
  const res = await fetch(`${REST}/cosmos/auth/v1beta1/account_info/${address}`);
  const { info } = await res.json();
  if (!info) throw new Error("account not found: fund it from the testnet faucet first");
  return { accountNumber: BigInt(info.account_number), sequence: BigInt(info.sequence ?? "0") };
}

function authInfo(sequence, gasLimit) {
  const fee = (gasLimit + 9n) / 10n; // minimum gas price 0.1 uqor
  return makeAuthInfoBytes(
    [{ pubkey: encodePubkey(encodeSecp256k1Pubkey(classical.publicKey)), sequence }],
    [{ denom: "uqor", amount: fee.toString() }],
    Number(gasLimit),
    undefined,
    undefined,
    1,
  );
}

async function waitForTx(txhash) {
  for (let i = 0; i < 40; i++) {
    const res = await fetch(`${REST}/cosmos/tx/v1beta1/txs/${txhash}`);
    if (res.ok) return (await res.json()).tx_response;
    await new Promise((r) => setTimeout(r, 1500));
  }
  throw new Error(`${txhash} was not committed`);
}

async function send(bodyBytes, mode) {
  const { accountNumber, sequence } = await accountInfo();
  const sign = (gas) =>
    signHybrid({ chainId: CHAIN_ID, accountNumber, bodyBytes, authInfoBytes: authInfo(sequence, gas), classicalKey: classical, pqKey: pq, mode });
  const sim = await simulateTx({ rest: REST, txBytes: sign(400000n).txBytes });
  console.log(`  simulated ${sim.gasUsed} gas, signing with limit ${sim.suggestedGasLimit}`);
  const res =
    mode === "hybrid"
      ? await submitWithSignBytesFallback({ rest: REST, chainId: CHAIN_ID, sign: () => sign(sim.suggestedGasLimit).txBytes })
      : await broadcastTx({ rest: REST, txBytes: sign(sim.suggestedGasLimit).txBytes });
  if (res.code !== 0) throw new Error(`refused: ${res.codespace} ${res.code} ${res.log}`);
  const tx = await waitForTx(res.txhash);
  console.log(`  committed ${res.txhash} at height ${tx.height}, gas used ${tx.gas_used}`);
  return res.txhash;
}

const status = await fetchPqKeyStatus({ rest: REST, address });
if (!status.registered) {
  console.log("registering the ML-DSA-87 key");
  const msg = buildRegisterPqKeyMessage({ chainId: CHAIN_ID, account: address, pqKey: pq, classicalPublicKey: classical.publicKey });
  await send(TxBody.encode(TxBody.fromPartial({ messages: [msg] })).finish(), "classicalOnly");
} else if (toHex(status.publicKey) !== toHex(pq.publicKey)) {
  throw new Error("the account has a different ML-DSA-87 key registered; this example uses the canonical derivation");
} else {
  console.log(`ML-DSA-87 key registered (proof of possession: ${status.possessionProven})`);
}

console.log("sending 1 uqor to self, hybrid-signed");
const body = TxBody.encode(
  TxBody.fromPartial({
    messages: [
      {
        typeUrl: "/cosmos.bank.v1beta1.MsgSend",
        value: MsgSend.encode({ fromAddress: address, toAddress: address, amount: [{ denom: "uqor", amount: "1" }] }).finish(),
      },
    ],
    memo: "qoresign example",
  }),
).finish();
const txhash = await send(body, "hybrid");
const urls = await fetchCommittedExtensionTypeUrls({ rest: REST, txhash });
console.log("layer state:", evaluateLayerState({ lane: "native", onQoreChain: true, signedWithPqLayer: true, committedExtensionTypeUrls: urls }));
