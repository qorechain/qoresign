// SPDX-License-Identifier: Apache-2.0
//
// Which lane a transfer uses, and what the PQC layer means on each.

package qoresign

// Lane is one of QoreChain's execution lanes.
type Lane string

const (
	LaneNative Lane = "native"
	LaneEVM    Lane = "evm"
	LaneSVM    Lane = "svm"
)

// LaneSupportLevel is what QoreSign can do on a lane today.
type LaneSupportLevel string

const (
	// SupportHybrid: hybrid secp256k1 + ML-DSA-87 signatures; the network requires them by default.
	SupportHybrid LaneSupportLevel = "hybrid"
	// SupportQuantumReady: Ethereum transactions carry no PQC layer. An account with a
	// registered ML-DSA-87 key can open a bounded EVM authorization window from the
	// native lane ("quantum-ready mode").
	SupportQuantumReady LaneSupportLevel = "quantum-ready"
	// SupportUnavailable: the lane is not open on the network yet.
	SupportUnavailable LaneSupportLevel = "unavailable"
)

// LaneSupport returns what QoreSign can do on a lane: native is hybrid, EVM
// quantum-ready, SVM unavailable. Unknown lanes are unavailable.
func LaneSupport(lane Lane) LaneSupportLevel {
	switch lane {
	case LaneNative:
		return SupportHybrid
	case LaneEVM:
		return SupportQuantumReady
	default:
		return SupportUnavailable
	}
}

// AssertHybridLane returns LANE_NOT_AVAILABLE when a hybrid signature is
// requested on a lane that cannot carry one.
func AssertHybridLane(lane Lane) error {
	switch lane {
	case LaneNative:
		return nil
	case LaneEVM:
		return errorf(CodeLaneNotAvailable,
			"EVM transactions carry no PQC layer until the network enables per-lane PQC; use the native lane, or open an EVM authorization window")
	case LaneSVM:
		return errorf(CodeLaneNotAvailable, "the SVM lane is not open on the network yet")
	default:
		return errorf(CodeLaneNotAvailable, "unknown lane %q", string(lane))
	}
}

// LaneRequest describes a transfer whose lane is being chosen.
type LaneRequest struct {
	// IsQorTransfer is true when the asset moved is native QOR on QoreChain.
	IsQorTransfer bool
	// ExplicitLane is a lane the user chose explicitly.
	ExplicitLane Lane
	// DappRequiredLane is a lane a connected dApp requires.
	DappRequiredLane Lane
}

// Lane decision reasons.
const (
	LaneReasonDefaultNative = "default-native"
	LaneReasonUserOverride  = "user-override"
	LaneReasonDappRequired  = "dapp-required"
)

// LaneDecision is the outcome of DecideLane.
type LaneDecision struct {
	Lane Lane
	// LeavesHybridDefault is true when the transfer leaves the hybrid-signed native lane; show it to the user.
	LeavesHybridDefault bool
	Reason              string
}

// DecideLane picks the lane: native QOR transfers default to the native lane,
// where they are hybrid-signed.
func DecideLane(req LaneRequest) LaneDecision {
	if req.DappRequiredLane != "" && req.DappRequiredLane != LaneNative {
		return LaneDecision{Lane: req.DappRequiredLane, LeavesHybridDefault: true, Reason: LaneReasonDappRequired}
	}
	if req.ExplicitLane != "" && req.ExplicitLane != LaneNative {
		return LaneDecision{Lane: req.ExplicitLane, LeavesHybridDefault: true, Reason: LaneReasonUserOverride}
	}
	return LaneDecision{Lane: LaneNative, Reason: LaneReasonDefaultNative}
}

// LayerState is the state of a broadcast transaction's PQC layer.
type LayerState string

const (
	// LayerPending: the committed transaction has not been read back yet.
	LayerPending LayerState = "pending"
	// LayerProtected: hybrid-signed and the committed transaction still carries the layer.
	LayerProtected LayerState = "protected"
	// LayerDowngraded: the committed transaction lacks the layer (stripped in transit, or never added).
	LayerDowngraded LayerState = "downgraded"
	// LayerClassical: a lane or network where the layer does not apply.
	LayerClassical LayerState = "classical"
)

// LayerStateInput are the inputs of EvaluateLayerState.
type LayerStateInput struct {
	Lane Lane
	// OnQoreChain is false for transfers on other networks.
	OnQoreChain       bool
	SignedWithPqLayer bool
	// CommittedExtensionTypeURLs are the extension type URLs of the committed
	// transaction; nil until it is read back (a committed transaction without
	// extensions is a non-nil empty slice).
	CommittedExtensionTypeURLs []string
}

// EvaluateLayerState returns the state of a broadcast transaction's PQC layer.
func EvaluateLayerState(in LayerStateInput) LayerState {
	if !in.OnQoreChain || in.Lane != LaneNative {
		return LayerClassical
	}
	if !in.SignedWithPqLayer {
		return LayerDowngraded
	}
	if in.CommittedExtensionTypeURLs == nil {
		return LayerPending
	}
	for _, u := range in.CommittedExtensionTypeURLs {
		if u == PqcHybridTypeURL {
			return LayerProtected
		}
	}
	return LayerDowngraded
}
