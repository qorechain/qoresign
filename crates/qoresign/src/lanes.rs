// SPDX-License-Identifier: Apache-2.0
//
// Which lane a transfer uses, and what the PQC layer means on each.

use crate::errors::{Error, Result};
use crate::sign::PQC_HYBRID_TYPE_URL;

/// QoreChain's execution lanes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Lane {
    Native,
    Evm,
    Svm,
}

impl Lane {
    /// `"native"`, `"evm"` or `"svm"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Lane::Native => "native",
            Lane::Evm => "evm",
            Lane::Svm => "svm",
        }
    }

    /// What QoreSign can do on this lane today (see [`LANE_SUPPORT`]).
    pub fn support(&self) -> LaneSupport {
        match self {
            Lane::Native => LaneSupport::Hybrid,
            Lane::Evm => LaneSupport::QuantumReady,
            Lane::Svm => LaneSupport::Unavailable,
        }
    }
}

/// Level of PQC support on a lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LaneSupport {
    Hybrid,
    QuantumReady,
    Unavailable,
}

impl LaneSupport {
    /// `"hybrid"`, `"quantum-ready"` or `"unavailable"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            LaneSupport::Hybrid => "hybrid",
            LaneSupport::QuantumReady => "quantum-ready",
            LaneSupport::Unavailable => "unavailable",
        }
    }
}

/// What QoreSign can do on each lane today:
/// - `Native`: hybrid secp256k1 + ML-DSA-87 signatures; the network requires them by default.
/// - `Evm`: Ethereum transactions carry no PQC layer. An account with a registered ML-DSA-87
///   key can open a bounded EVM authorization window from the native lane ("quantum-ready mode").
/// - `Svm`: the lane is not open on the network yet.
pub const LANE_SUPPORT: [(Lane, LaneSupport); 3] = [
    (Lane::Native, LaneSupport::Hybrid),
    (Lane::Evm, LaneSupport::QuantumReady),
    (Lane::Svm, LaneSupport::Unavailable),
];

/// Fails with `LANE_NOT_AVAILABLE` when a hybrid signature is requested on a
/// lane that cannot carry one.
pub fn assert_hybrid_lane(lane: Lane) -> Result<()> {
    match lane.support() {
        LaneSupport::Hybrid => Ok(()),
        _ if lane == Lane::Svm => Err(Error::LaneNotAvailable(
            "the SVM lane is not open on the network yet".into(),
        )),
        _ => Err(Error::LaneNotAvailable(
            "EVM transactions carry no PQC layer until the network enables per-lane PQC; use the native lane, or open an EVM authorization window"
                .into(),
        )),
    }
}

/// Input of [`decide_lane`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LaneRequest {
    /// True when the asset moved is native QOR on QoreChain.
    pub is_qor_transfer: bool,
    /// A lane the user chose explicitly.
    pub explicit_lane: Option<Lane>,
    /// A lane a connected dApp requires.
    pub dapp_required_lane: Option<Lane>,
}

/// Why [`decide_lane`] picked a lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LaneReason {
    DefaultNative,
    UserOverride,
    DappRequired,
}

impl LaneReason {
    /// `"default-native"`, `"user-override"` or `"dapp-required"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            LaneReason::DefaultNative => "default-native",
            LaneReason::UserOverride => "user-override",
            LaneReason::DappRequired => "dapp-required",
        }
    }
}

/// Output of [`decide_lane`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaneDecision {
    pub lane: Lane,
    /// True when the transfer leaves the hybrid-signed native lane; show it to the user.
    pub leaves_hybrid_default: bool,
    pub reason: LaneReason,
}

/// Native QOR transfers default to the native lane, where they are hybrid-signed.
pub fn decide_lane(req: &LaneRequest) -> LaneDecision {
    if let Some(lane) = req.dapp_required_lane.filter(|l| *l != Lane::Native) {
        return LaneDecision {
            lane,
            leaves_hybrid_default: true,
            reason: LaneReason::DappRequired,
        };
    }
    if let Some(lane) = req.explicit_lane.filter(|l| *l != Lane::Native) {
        return LaneDecision {
            lane,
            leaves_hybrid_default: true,
            reason: LaneReason::UserOverride,
        };
    }
    LaneDecision {
        lane: Lane::Native,
        leaves_hybrid_default: false,
        reason: LaneReason::DefaultNative,
    }
}

/// State of a broadcast transaction's PQC layer:
/// - `Protected`: hybrid-signed and the committed transaction still carries the layer.
/// - `Downgraded`: the committed transaction lacks the layer (stripped in transit, or never added).
/// - `Classical`: a lane or network where the layer does not apply.
/// - `Pending`: the committed transaction has not been read back yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LayerState {
    Pending,
    Protected,
    Downgraded,
    Classical,
}

impl LayerState {
    /// `"pending"`, `"protected"`, `"downgraded"` or `"classical"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            LayerState::Pending => "pending",
            LayerState::Protected => "protected",
            LayerState::Downgraded => "downgraded",
            LayerState::Classical => "classical",
        }
    }
}

/// Input of [`evaluate_layer_state`].
#[derive(Clone, Copy, Debug)]
pub struct LayerStateInput<'a> {
    pub lane: Lane,
    /// False for transfers on other networks.
    pub on_qore_chain: bool,
    pub signed_with_pq_layer: bool,
    /// Extension type URLs of the committed transaction; `None` until it is read back.
    pub committed_extension_type_urls: Option<&'a [&'a str]>,
}

pub fn evaluate_layer_state(input: &LayerStateInput<'_>) -> LayerState {
    if !input.on_qore_chain || input.lane != Lane::Native {
        return LayerState::Classical;
    }
    if !input.signed_with_pq_layer {
        return LayerState::Downgraded;
    }
    match input.committed_extension_type_urls {
        None => LayerState::Pending,
        Some(urls) if urls.contains(&PQC_HYBRID_TYPE_URL) => LayerState::Protected,
        Some(_) => LayerState::Downgraded,
    }
}
