// SPDX-License-Identifier: Apache-2.0
//
// Stable error codes. New codes may be added; existing ones never change meaning.

/// Every error QoreSign returns on purpose. [`Error::code`] gives the stable
/// code shared with the other QoreSign implementations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("{0}")]
    InvalidArgument(String),
    #[error("{0}")]
    InvalidMnemonic(String),
    #[error("{0}")]
    InvalidAddress(String),
    #[error("{0}")]
    AddressMismatch(String),
    #[error("{0}")]
    HdNonHardened(String),
    #[error("{0}")]
    HdInvalidPath(String),
    #[error("{0}")]
    BadKeyLength(String),
    #[error("{0}")]
    MalformedProtobuf(String),
    #[error("{0}")]
    SignBytesVersionUnknown(String),
    #[error("{0}")]
    PqLayerMissing(String),
    #[error("{0}")]
    PqLayerDuplicated(String),
    #[error("{0}")]
    PqSignatureInvalid(String),
    #[error("{0}")]
    ClassicalSignatureInvalid(String),
    #[error("{0}")]
    UnsupportedAlgorithm(String),
    #[error("{0}")]
    SiwqMalformed(String),
    #[error("{0}")]
    SiwqExpired(String),
    #[error("{0}")]
    SiwqNotYetValid(String),
    #[error("{0}")]
    SiwqDomainMismatch(String),
    #[error("{0}")]
    SiwqNonceMismatch(String),
    #[error("{0}")]
    SiwqChainMismatch(String),
    #[error("{0}")]
    KeyNotRegistered(String),
    #[error("{0}")]
    KeyMismatch(String),
    #[error("{0}")]
    LaneNotAvailable(String),
    #[error("{0}")]
    NetworkUnavailable(String),
    #[error("{0}")]
    SimulationFailed(String),
}

impl Error {
    /// The stable SCREAMING_SNAKE code, identical across implementations.
    pub fn code(&self) -> &'static str {
        match self {
            Error::InvalidArgument(_) => "INVALID_ARGUMENT",
            Error::InvalidMnemonic(_) => "INVALID_MNEMONIC",
            Error::InvalidAddress(_) => "INVALID_ADDRESS",
            Error::AddressMismatch(_) => "ADDRESS_MISMATCH",
            Error::HdNonHardened(_) => "HD_NON_HARDENED",
            Error::HdInvalidPath(_) => "HD_INVALID_PATH",
            Error::BadKeyLength(_) => "BAD_KEY_LENGTH",
            Error::MalformedProtobuf(_) => "MALFORMED_PROTOBUF",
            Error::SignBytesVersionUnknown(_) => "SIGN_BYTES_VERSION_UNKNOWN",
            Error::PqLayerMissing(_) => "PQ_LAYER_MISSING",
            Error::PqLayerDuplicated(_) => "PQ_LAYER_DUPLICATED",
            Error::PqSignatureInvalid(_) => "PQ_SIGNATURE_INVALID",
            Error::ClassicalSignatureInvalid(_) => "CLASSICAL_SIGNATURE_INVALID",
            Error::UnsupportedAlgorithm(_) => "UNSUPPORTED_ALGORITHM",
            Error::SiwqMalformed(_) => "SIWQ_MALFORMED",
            Error::SiwqExpired(_) => "SIWQ_EXPIRED",
            Error::SiwqNotYetValid(_) => "SIWQ_NOT_YET_VALID",
            Error::SiwqDomainMismatch(_) => "SIWQ_DOMAIN_MISMATCH",
            Error::SiwqNonceMismatch(_) => "SIWQ_NONCE_MISMATCH",
            Error::SiwqChainMismatch(_) => "SIWQ_CHAIN_MISMATCH",
            Error::KeyNotRegistered(_) => "KEY_NOT_REGISTERED",
            Error::KeyMismatch(_) => "KEY_MISMATCH",
            Error::LaneNotAvailable(_) => "LANE_NOT_AVAILABLE",
            Error::NetworkUnavailable(_) => "NETWORK_UNAVAILABLE",
            Error::SimulationFailed(_) => "SIMULATION_FAILED",
        }
    }

    /// The human-readable message.
    pub fn message(&self) -> &str {
        match self {
            Error::InvalidArgument(m)
            | Error::InvalidMnemonic(m)
            | Error::InvalidAddress(m)
            | Error::AddressMismatch(m)
            | Error::HdNonHardened(m)
            | Error::HdInvalidPath(m)
            | Error::BadKeyLength(m)
            | Error::MalformedProtobuf(m)
            | Error::SignBytesVersionUnknown(m)
            | Error::PqLayerMissing(m)
            | Error::PqLayerDuplicated(m)
            | Error::PqSignatureInvalid(m)
            | Error::ClassicalSignatureInvalid(m)
            | Error::UnsupportedAlgorithm(m)
            | Error::SiwqMalformed(m)
            | Error::SiwqExpired(m)
            | Error::SiwqNotYetValid(m)
            | Error::SiwqDomainMismatch(m)
            | Error::SiwqNonceMismatch(m)
            | Error::SiwqChainMismatch(m)
            | Error::KeyNotRegistered(m)
            | Error::KeyMismatch(m)
            | Error::LaneNotAvailable(m)
            | Error::NetworkUnavailable(m)
            | Error::SimulationFailed(m) => m,
        }
    }
}

/// `Result` with the QoreSign [`Error`].
pub type Result<T> = core::result::Result<T, Error>;

pub(crate) fn require_length(b: &[u8], len: usize, what: &str) -> Result<()> {
    if b.len() != len {
        return Err(Error::BadKeyLength(format!(
            "{what} must be {len} bytes, got {}",
            b.len()
        )));
    }
    Ok(())
}
