// SPDX-License-Identifier: Apache-2.0
import { DirectSecp256k1HdWallet, makeAuthInfoBytes, encodePubkey } from "@cosmjs/proto-signing";
import { encodeSecp256k1Pubkey } from "@cosmjs/amino";
import { buildHybridTx, derivePqcCanonical, qorechainRegistry, signProofOfPossession as sdkPop } from "@qorechain/sdk";
import { MsgSend } from "cosmjs-types/cosmos/bank/v1beta1/tx";
import { SignMode } from "cosmjs-types/cosmos/tx/signing/v1beta1/signing";
import { TxBody } from "cosmjs-types/cosmos/tx/v1beta1/tx";
import { bech32 } from "@scure/base";
import { describe, expect, it } from "vitest";
import {
  ALGORITHM_ML_DSA_87,
  PQC_HYBRID_TYPE_URL,
  QoreSignError,
  addressFromPublicKey,
  appendExtension,
  assertHybridLane,
  buildRegisterPqKeyMessage,
  classicalKeyTypeFor,
  decideLane,
  decodeAny,
  decodeTxRaw,
  defaultHdPath,
  deriveCanonicalPqKey,
  deriveClassicalKey,
  deriveHdPqKey,
  evaluateLayerState,
  hybridSignBytes,
  isDegeneratePqPublicKey,
  parseAddress,
  pqcLayers,
  signHybrid,
  signPqLayer,
  signProofOfPossession,
  stripExtension,
  toHex,
  verifyHybridTx,
  verifyPqLayer,
  verifyProofOfPossession,
} from "../src/index.js";

const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const CHAIN_ID = "qorechain-diana";

const classical = deriveClassicalKey({ mnemonic: MNEMONIC });
const account = addressFromPublicKey(classical.publicKey, "secp256k1");
const pqKey = deriveCanonicalPqKey({ mnemonic: MNEMONIC, address: account.bech32 });

function sendBody(memo = "qoresign test"): Uint8Array {
  return TxBody.encode(
    TxBody.fromPartial({
      messages: [
        {
          typeUrl: "/cosmos.bank.v1beta1.MsgSend",
          value: MsgSend.encode(
            MsgSend.fromPartial({
              fromAddress: account.bech32,
              toAddress: account.bech32,
              amount: [{ denom: "uqor", amount: "1" }],
            }),
          ).finish(),
        },
      ],
      memo,
    }),
  ).finish();
}

function authInfo(sequence = 3n): Uint8Array {
  return makeAuthInfoBytes(
    [{ pubkey: encodePubkey(encodeSecp256k1Pubkey(classical.publicKey)), sequence }],
    [{ denom: "uqor", amount: "50000" }],
    500_000,
    undefined,
    undefined,
    SignMode.SIGN_MODE_DIRECT,
  );
}

describe("accounts and derivation", () => {
  it("derives the well-known Cosmos test account under the qor prefix", () => {
    // m/44'/118'/0'/0/0 of the BIP-39 test mnemonic is cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4.
    const cosmos = bech32.decode("cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4");
    expect(toHex(account.bytes)).toBe(toHex(Uint8Array.from(bech32.fromWords(cosmos.words))));
    expect(account.bech32.startsWith("qor1")).toBe(true);
    expect(parseAddress(account.hex).bech32).toBe(account.bech32);
  });

  it("canonical ML-DSA-87 key equals the QoreChain SDK derivation", () => {
    const sdk = derivePqcCanonical(account.bech32, MNEMONIC);
    expect(toHex(pqKey.publicKey)).toBe(toHex(sdk.publicKey));
    // the 0x form of the same account resolves to the same key
    const viaHex = deriveCanonicalPqKey({ mnemonic: MNEMONIC, address: account.hex });
    expect(toHex(viaHex.publicKey)).toBe(toHex(pqKey.publicKey));
  });

  it("canonical keys are bound to the address", () => {
    const eth = deriveClassicalKey({ mnemonic: MNEMONIC, type: "eth_secp256k1" });
    const ethAddr = addressFromPublicKey(eth.publicKey, "eth_secp256k1");
    const other = deriveCanonicalPqKey({ mnemonic: MNEMONIC, address: ethAddr.bech32 });
    expect(toHex(other.publicKey)).not.toBe(toHex(pqKey.publicKey));
    expect(toHex(other.publicKey)).toBe(toHex(derivePqcCanonical(ethAddr.bech32, MNEMONIC).publicKey));
    expect(classicalKeyTypeFor(eth.publicKey, ethAddr.bech32)).toBe("eth_secp256k1");
    expect(classicalKeyTypeFor(classical.publicKey, account.bech32)).toBe("secp256k1");
  });

  it("refuses a non-canonical mnemonic instead of deriving a different key", () => {
    expect(() => deriveCanonicalPqKey({ mnemonic: ` ${MNEMONIC}`, address: account.bech32 })).toThrow(QoreSignError);
    expect(() => deriveCanonicalPqKey({ mnemonic: MNEMONIC.replace(" ", "  "), address: account.bech32 })).toThrow(
      /canonical form/,
    );
    expect(() => deriveCanonicalPqKey({ mnemonic: "abandon abandon", address: account.bech32 })).toThrow(/BIP-39/);
  });

  it("HD derivation is hardened-only and deterministic", () => {
    const a = deriveHdPqKey({ mnemonic: MNEMONIC, path: defaultHdPath(0) });
    const b = deriveHdPqKey({ mnemonic: MNEMONIC, path: defaultHdPath(0) });
    const c = deriveHdPqKey({ mnemonic: MNEMONIC, path: defaultHdPath(1) });
    expect(toHex(a.publicKey)).toBe(toHex(b.publicKey));
    expect(toHex(a.publicKey)).not.toBe(toHex(c.publicKey));
    expect(toHex(a.publicKey)).not.toBe(toHex(pqKey.publicKey));
    try {
      deriveHdPqKey({ mnemonic: MNEMONIC, path: "m/44'/118'/0'/0/0" });
      expect.unreachable();
    } catch (err) {
      expect((err as QoreSignError).code).toBe("HD_NON_HARDENED");
    }
    expect(() => deriveHdPqKey({ mnemonic: MNEMONIC, path: "44'/118'" })).toThrow(/start with "m"/);
  });
});

describe("protobuf body edits", () => {
  it("strip(append(body)) returns the original bytes and keeps canonical order", () => {
    const body = sendBody();
    const any = { typeUrl: PQC_HYBRID_TYPE_URL, value: new Uint8Array([8, 1]) };
    const withExt = appendExtension(body, any);
    expect(toHex(stripExtension(withExt, PQC_HYBRID_TYPE_URL))).toBe(toHex(body));
    // same bytes as a full re-encode by cosmjs-types
    const decoded = TxBody.decode(withExt);
    expect(toHex(TxBody.encode(decoded).finish())).toBe(toHex(withExt));
    expect(decodeAny(TxBody.encode(TxBody.fromPartial({ extensionOptions: [any] })).finish().subarray(3)).typeUrl).toBe(
      PQC_HYBRID_TYPE_URL,
    );
  });

  it("inserts before non-critical extension options", () => {
    const body = TxBody.encode(
      TxBody.fromPartial({ memo: "m", nonCriticalExtensionOptions: [{ typeUrl: "/x.Y", value: new Uint8Array([1]) }] }),
    ).finish();
    const any = { typeUrl: PQC_HYBRID_TYPE_URL, value: new Uint8Array([8, 1]) };
    const withExt = appendExtension(body, any);
    const viaCosmjs = TxBody.encode({ ...TxBody.decode(body), extensionOptions: [any] }).finish();
    expect(toHex(withExt)).toBe(toHex(viaCosmjs));
  });
});

describe("hybrid signing", () => {
  it("produces exactly the bytes the QoreChain SDK produces", async () => {
    const wallet = await DirectSecp256k1HdWallet.fromMnemonic(MNEMONIC, { prefix: "qor" });
    const msg = {
      typeUrl: "/cosmos.bank.v1beta1.MsgSend",
      value: { fromAddress: account.bech32, toAddress: account.bech32, amount: [{ denom: "uqor", amount: "1" }] },
    };
    const fee = { amount: [{ denom: "uqor", amount: "50000" }], gas: "500000" };
    const sdk = await buildHybridTx({
      registry: qorechainRegistry(),
      signer: wallet,
      pqcKeypair: derivePqcCanonical(account.bech32, MNEMONIC),
      messages: [msg],
      fee,
      memo: "qoresign test",
      chainId: CHAIN_ID,
      accountNumber: 7,
      sequence: 3,
      signBytesVersion: "v2",
    });
    const ours = signHybrid({
      chainId: CHAIN_ID,
      accountNumber: 7,
      bodyBytes: sendBody(),
      authInfoBytes: authInfo(3n),
      classicalKey: classical,
      pqKey,
      signBytesVersion: "v2",
    });
    expect(toHex(ours.txBytes)).toBe(toHex(sdk.txRawBytes));
  });

  it("verifies, and rejects tampering", () => {
    const signed = signHybrid({
      chainId: CHAIN_ID,
      accountNumber: 7,
      bodyBytes: sendBody(),
      authInfoBytes: authInfo(),
      classicalKey: classical,
      pqKey,
    });
    const ok = verifyHybridTx({
      txBytes: signed.txBytes,
      chainId: CHAIN_ID,
      accountNumber: 7,
      classicalPublicKey: classical.publicKey,
      pqPublicKey: pqKey.publicKey,
    });
    expect(ok).toEqual({ valid: true, classical: true, pq: { valid: true, signBytesVersion: "v2" } });

    const wrongChain = verifyHybridTx({
      txBytes: signed.txBytes,
      chainId: "qorechain-vladi",
      accountNumber: 7,
      classicalPublicKey: classical.publicKey,
      pqPublicKey: pqKey.publicKey,
    });
    expect(wrongChain.valid).toBe(false);
    expect(wrongChain.pq?.reason).toBe("invalid_signature");

    const other = deriveHdPqKey({ mnemonic: MNEMONIC, path: defaultHdPath(0) });
    const wrongKey = verifyPqLayer({
      chainId: CHAIN_ID,
      bodyBytes: signed.bodyBytes,
      authInfoBytes: signed.authInfoBytes,
      pqPublicKey: other.publicKey,
    });
    expect(wrongKey.valid).toBe(false);

    // a different fee (auth info) invalidates the PQ layer
    const feeSwap = verifyPqLayer({
      chainId: CHAIN_ID,
      bodyBytes: signed.bodyBytes,
      authInfoBytes: authInfo(4n),
      pqPublicKey: pqKey.publicKey,
    });
    expect(feeSwap.valid).toBe(false);
  });

  it("signPqLayer leaves the classical signature to another signer and is checked with either version", () => {
    const layered = signPqLayer({
      chainId: CHAIN_ID,
      bodyBytes: sendBody(),
      authInfoBytes: authInfo(),
      pqKey,
      signBytesVersion: "v1",
    });
    expect(pqcLayers(layered.bodyBytes)).toHaveLength(1);
    expect(verifyPqLayer({ chainId: CHAIN_ID, bodyBytes: layered.bodyBytes, authInfoBytes: authInfo(), pqPublicKey: pqKey.publicKey }).valid).toBe(false);
    expect(
      verifyPqLayer({
        chainId: CHAIN_ID,
        bodyBytes: layered.bodyBytes,
        authInfoBytes: authInfo(),
        pqPublicKey: pqKey.publicKey,
        signBytesVersion: "either",
      }),
    ).toEqual({ valid: true, signBytesVersion: "v1" });
    // re-layering replaces the old layer instead of adding a second one
    const again = signPqLayer({ chainId: CHAIN_ID, bodyBytes: layered.bodyBytes, authInfoBytes: authInfo(), pqKey });
    expect(pqcLayers(again.bodyBytes)).toHaveLength(1);
  });

  it("detects a missing or duplicated layer", () => {
    expect(verifyPqLayer({ chainId: CHAIN_ID, bodyBytes: sendBody(), authInfoBytes: authInfo(), pqPublicKey: pqKey.publicKey }).reason).toBe(
      "missing",
    );
    const one = signPqLayer({ chainId: CHAIN_ID, bodyBytes: sendBody(), authInfoBytes: authInfo(), pqKey }).bodyBytes;
    const dup = appendExtension(one, { typeUrl: PQC_HYBRID_TYPE_URL, value: new Uint8Array([8, 1]) });
    expect(verifyPqLayer({ chainId: CHAIN_ID, bodyBytes: dup, authInfoBytes: authInfo(), pqPublicKey: pqKey.publicKey }).reason).toBe(
      "duplicated",
    );
  });

  it("classicalOnly mode carries no layer; pqOnly is refused", () => {
    const signed = signHybrid({
      chainId: CHAIN_ID,
      accountNumber: 1,
      bodyBytes: sendBody(),
      authInfoBytes: authInfo(),
      classicalKey: classical,
      mode: "classicalOnly",
    });
    expect(pqcLayers(decodeTxRaw(signed.txBytes).bodyBytes)).toHaveLength(0);
    expect(() =>
      signHybrid({
        chainId: CHAIN_ID,
        accountNumber: 1,
        bodyBytes: sendBody(),
        authInfoBytes: authInfo(),
        classicalKey: classical,
        pqKey,
        mode: "pqOnly",
      }),
    ).toThrow(/PQ-only/);
  });

  it("sign-bytes ignore an existing layer", () => {
    const layered = signPqLayer({ chainId: CHAIN_ID, bodyBytes: sendBody(), authInfoBytes: authInfo(), pqKey }).bodyBytes;
    const a = hybridSignBytes({ chainId: CHAIN_ID, bodyBytes: layered, authInfoBytes: authInfo() });
    const b = hybridSignBytes({ chainId: CHAIN_ID, bodyBytes: sendBody(), authInfoBytes: authInfo() });
    expect(toHex(a)).toBe(toHex(b));
  });
});

describe("key registration", () => {
  it("proof of possession matches the QoreChain SDK", () => {
    const ours = signProofOfPossession({ chainId: CHAIN_ID, account: account.bech32, pqKey });
    const sdk = sdkPop({ chainId: CHAIN_ID, account: account.bech32, keypair: pqKey });
    expect(toHex(ours)).toBe(toHex(sdk));
    expect(verifyProofOfPossession({ chainId: CHAIN_ID, account: account.bech32, publicKey: pqKey.publicKey, proof: ours })).toBe(true);
    expect(verifyProofOfPossession({ chainId: "qorechain-vladi", account: account.bech32, publicKey: pqKey.publicKey, proof: ours })).toBe(false);
  });

  it("MsgRegisterPQCKeyV2 decodes with the chain's message type", () => {
    const any = buildRegisterPqKeyMessage({
      chainId: CHAIN_ID,
      account: account.bech32,
      pqKey,
      classicalPublicKey: classical.publicKey,
    });
    const msg = qorechainRegistry().decode(any) as {
      sender: string;
      publicKey: Uint8Array;
      algorithmId: number;
      ecdsaPubkey: Uint8Array;
      keyType: string;
      proofOfPossession: Uint8Array;
    };
    expect(msg.sender).toBe(account.bech32);
    expect(msg.algorithmId).toBe(ALGORITHM_ML_DSA_87);
    expect(msg.keyType).toBe("hybrid");
    expect(toHex(msg.ecdsaPubkey)).toBe(toHex(classical.publicKey));
    expect(toHex(msg.publicKey)).toBe(toHex(pqKey.publicKey));
    expect(
      verifyProofOfPossession({ chainId: CHAIN_ID, account: account.bech32, publicKey: msg.publicKey, proof: msg.proofOfPossession }),
    ).toBe(true);
  });

  it("refuses a classical key that does not control the account, and a forgeable key", () => {
    const eth = deriveClassicalKey({ mnemonic: MNEMONIC, type: "eth_secp256k1" });
    expect(() =>
      buildRegisterPqKeyMessage({ chainId: CHAIN_ID, account: account.bech32, pqKey, classicalPublicKey: eth.publicKey }),
    ).toThrow(/does not control/);
    const degenerate = new Uint8Array(2592);
    degenerate[0] = 1;
    expect(isDegeneratePqPublicKey(degenerate)).toBe(true);
    expect(() =>
      buildRegisterPqKeyMessage({
        chainId: CHAIN_ID,
        account: account.bech32,
        pqKey: { publicKey: degenerate, secretKey: pqKey.secretKey },
        classicalPublicKey: classical.publicKey,
      }),
    ).toThrow(/forgeable/);
  });
});

describe("lanes", () => {
  it("native is hybrid; EVM and SVM refuse a hybrid request", () => {
    expect(() => assertHybridLane("native")).not.toThrow();
    expect(() => assertHybridLane("evm")).toThrow(/per-lane PQC/);
    expect(() => assertHybridLane("svm")).toThrow(/not open/);
    expect(decideLane({ isQorTransfer: true })).toEqual({ lane: "native", leavesHybridDefault: false, reason: "default-native" });
    expect(decideLane({ isQorTransfer: true, dappRequiredLane: "evm" }).leavesHybridDefault).toBe(true);
  });

  it("layer state after broadcast", () => {
    expect(evaluateLayerState({ lane: "native", onQoreChain: true, signedWithPqLayer: true })).toBe("pending");
    expect(
      evaluateLayerState({ lane: "native", onQoreChain: true, signedWithPqLayer: true, committedExtensionTypeUrls: [PQC_HYBRID_TYPE_URL] }),
    ).toBe("protected");
    expect(evaluateLayerState({ lane: "native", onQoreChain: true, signedWithPqLayer: true, committedExtensionTypeUrls: [] })).toBe(
      "downgraded",
    );
    expect(evaluateLayerState({ lane: "evm", onQoreChain: true, signedWithPqLayer: false })).toBe("classical");
  });
});
