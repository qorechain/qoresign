// SPDX-License-Identifier: Apache-2.0
//
// Which lane a transfer uses, and what the PQC layer means on each.

import { QoreSignError } from "./errors.js";
import { PQC_HYBRID_TYPE_URL } from "./sign.js";

/** QoreChain's execution lanes. */
export type Lane = "native" | "evm" | "svm";

/**
 * What QoreSign can do on each lane today:
 * - `native`: hybrid secp256k1 + ML-DSA-87 signatures; the network requires them by default.
 * - `evm`: Ethereum transactions carry no PQC layer. An account with a registered ML-DSA-87
 *   key can open a bounded EVM authorization window from the native lane ("quantum-ready mode").
 * - `svm`: the lane is not open on the network yet.
 */
export const LANE_SUPPORT: Readonly<Record<Lane, "hybrid" | "quantum-ready" | "unavailable">> = Object.freeze({
  native: "hybrid",
  evm: "quantum-ready",
  svm: "unavailable",
});

/** Throws `LANE_NOT_AVAILABLE` when a hybrid signature is requested on a lane that cannot carry one. */
export function assertHybridLane(lane: Lane): void {
  if (LANE_SUPPORT[lane] === "hybrid") return;
  if (lane === "svm") {
    throw new QoreSignError("LANE_NOT_AVAILABLE", "the SVM lane is not open on the network yet");
  }
  throw new QoreSignError(
    "LANE_NOT_AVAILABLE",
    "EVM transactions carry no PQC layer until the network enables per-lane PQC; use the native lane, or open an EVM authorization window",
  );
}

export interface LaneRequest {
  /** True when the asset moved is native QOR on QoreChain. */
  isQorTransfer: boolean;
  /** A lane the user chose explicitly. */
  explicitLane?: Lane;
  /** A lane a connected dApp requires. */
  dappRequiredLane?: Lane;
}

export interface LaneDecision {
  lane: Lane;
  /** True when the transfer leaves the hybrid-signed native lane; show it to the user. */
  leavesHybridDefault: boolean;
  reason: "default-native" | "user-override" | "dapp-required";
}

/** Native QOR transfers default to the native lane, where they are hybrid-signed. */
export function decideLane(req: LaneRequest): LaneDecision {
  if (req.dappRequiredLane && req.dappRequiredLane !== "native") {
    return { lane: req.dappRequiredLane, leavesHybridDefault: true, reason: "dapp-required" };
  }
  if (req.explicitLane && req.explicitLane !== "native") {
    return { lane: req.explicitLane, leavesHybridDefault: true, reason: "user-override" };
  }
  return { lane: "native", leavesHybridDefault: false, reason: "default-native" };
}

/**
 * State of a broadcast transaction's PQC layer:
 * - `protected`: hybrid-signed and the committed transaction still carries the layer.
 * - `downgraded`: the committed transaction lacks the layer (stripped in transit, or never added).
 * - `classical`: a lane or network where the layer does not apply.
 * - `pending`: the committed transaction has not been read back yet.
 */
export type LayerState = "pending" | "protected" | "downgraded" | "classical";

export function evaluateLayerState(input: {
  lane: Lane;
  /** False for transfers on other networks. */
  onQoreChain: boolean;
  signedWithPqLayer: boolean;
  /** Extension type URLs of the committed transaction; `undefined` until it is read back. */
  committedExtensionTypeUrls?: readonly string[];
}): LayerState {
  if (!input.onQoreChain || input.lane !== "native") return "classical";
  if (!input.signedWithPqLayer) return "downgraded";
  if (input.committedExtensionTypeUrls === undefined) return "pending";
  return input.committedExtensionTypeUrls.includes(PQC_HYBRID_TYPE_URL) ? "protected" : "downgraded";
}
