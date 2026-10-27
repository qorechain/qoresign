// SPDX-License-Identifier: Apache-2.0
//
// Local verification of hybrid transactions, the way the network checks them.

use crate::errors::{Error, Result};
use crate::keys::{ClassicalKeyType, ALGORITHM_ML_DSA_87};
use crate::proto::{decode_tx_raw, encode_sign_doc};
use crate::sign::{classical_verify, hybrid_sign_bytes, pq_verify, pqc_layers, SignBytesVersion};

/// Which sign-bytes versions a verifier accepts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum VerifyVersion {
    V1,
    #[default]
    V2,
    /// A signature over v1 or v2 sign-bytes.
    Either,
}

impl VerifyVersion {
    fn versions(self) -> &'static [SignBytesVersion] {
        match self {
            VerifyVersion::V1 => &[SignBytesVersion::V1],
            VerifyVersion::V2 => &[SignBytesVersion::V2],
            VerifyVersion::Either => &[SignBytesVersion::V2, SignBytesVersion::V1],
        }
    }
}

/// Why a PQC layer did not verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PqLayerFailure {
    Missing,
    Duplicated,
    UnsupportedAlgorithm,
    EmbeddedKeyMismatch,
    InvalidSignature,
}

impl PqLayerFailure {
    /// `"missing"`, `"duplicated"`, `"unsupported_algorithm"`, `"embedded_key_mismatch"`
    /// or `"invalid_signature"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            PqLayerFailure::Missing => "missing",
            PqLayerFailure::Duplicated => "duplicated",
            PqLayerFailure::UnsupportedAlgorithm => "unsupported_algorithm",
            PqLayerFailure::EmbeddedKeyMismatch => "embedded_key_mismatch",
            PqLayerFailure::InvalidSignature => "invalid_signature",
        }
    }
}

/// Result of [`verify_pq_layer`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PqLayerResult {
    pub valid: bool,
    /// The sign-bytes version the signature verified under.
    pub sign_bytes_version: Option<SignBytesVersion>,
    pub reason: Option<PqLayerFailure>,
}

impl PqLayerResult {
    fn fail(reason: PqLayerFailure) -> Self {
        Self {
            valid: false,
            sign_bytes_version: None,
            reason: Some(reason),
        }
    }
}

/// Check the ML-DSA-87 layer of a body against the account's registered
/// public key. A wallet should run this before adding its classical signature
/// to a body a dApp prepared: a layer that does not verify protects nothing.
pub fn verify_pq_layer(
    chain_id: &str,
    body_bytes: &[u8],
    auth_info_bytes: &[u8],
    pq_public_key: &[u8],
    version: VerifyVersion,
) -> Result<PqLayerResult> {
    let layers = pqc_layers(body_bytes)?;
    let layer = match layers.as_slice() {
        [] => return Ok(PqLayerResult::fail(PqLayerFailure::Missing)),
        [one] => one,
        _ => return Ok(PqLayerResult::fail(PqLayerFailure::Duplicated)),
    };
    if layer.algorithm_id != ALGORITHM_ML_DSA_87 {
        return Ok(PqLayerResult::fail(PqLayerFailure::UnsupportedAlgorithm));
    }
    if let Some(embedded) = layer.public_key.as_deref() {
        if !embedded.is_empty() && embedded != pq_public_key {
            return Ok(PqLayerResult::fail(PqLayerFailure::EmbeddedKeyMismatch));
        }
    }
    for &v in version.versions() {
        let msg = hybrid_sign_bytes(chain_id, body_bytes, auth_info_bytes, v)?;
        if pq_verify(pq_public_key, &msg, &layer.signature) {
            return Ok(PqLayerResult {
                valid: true,
                sign_bytes_version: Some(v),
                reason: None,
            });
        }
    }
    Ok(PqLayerResult::fail(PqLayerFailure::InvalidSignature))
}

/// Input of [`verify_hybrid_tx`].
#[derive(Clone, Copy, Debug)]
pub struct VerifyHybridTxArgs<'a> {
    /// Encoded `TxRaw`.
    pub tx_bytes: &'a [u8],
    pub chain_id: &'a str,
    pub account_number: u64,
    /// Public key of the (single) signer.
    pub classical_public_key: &'a [u8],
    /// Default `Secp256k1`.
    pub classical_key_type: ClassicalKeyType,
    /// Registered ML-DSA-87 public key; `None` checks the classical part only.
    pub pq_public_key: Option<&'a [u8]>,
    pub version: VerifyVersion,
}

impl<'a> VerifyHybridTxArgs<'a> {
    /// Defaults: `Secp256k1`, v2 sign-bytes.
    pub fn new(
        tx_bytes: &'a [u8],
        chain_id: &'a str,
        account_number: u64,
        classical_public_key: &'a [u8],
        pq_public_key: Option<&'a [u8]>,
    ) -> Self {
        Self {
            tx_bytes,
            chain_id,
            account_number,
            classical_public_key,
            classical_key_type: ClassicalKeyType::Secp256k1,
            pq_public_key,
            version: VerifyVersion::V2,
        }
    }
}

/// Result of [`verify_hybrid_tx`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HybridTxResult {
    /// True when every requested check passed.
    pub valid: bool,
    pub classical: bool,
    /// `None` when no PQ key was supplied.
    pub pq: Option<PqLayerResult>,
}

/// Verify a single-signer hybrid transaction (both signatures).
pub fn verify_hybrid_tx(args: &VerifyHybridTxArgs<'_>) -> Result<HybridTxResult> {
    let tx = decode_tx_raw(args.tx_bytes)?;
    if tx.signatures.len() != 1 {
        return Err(Error::InvalidArgument(format!(
            "expected one signer, the transaction has {}",
            tx.signatures.len()
        )));
    }
    let sign_doc = encode_sign_doc(
        &tx.body_bytes,
        &tx.auth_info_bytes,
        args.chain_id,
        args.account_number,
    );
    let classical = classical_verify(
        args.classical_key_type,
        args.classical_public_key,
        &sign_doc,
        &tx.signatures[0],
    );
    let Some(pq_public_key) = args.pq_public_key else {
        return Ok(HybridTxResult {
            valid: classical,
            classical,
            pq: None,
        });
    };
    let pq = verify_pq_layer(
        args.chain_id,
        &tx.body_bytes,
        &tx.auth_info_bytes,
        pq_public_key,
        args.version,
    )?;
    Ok(HybridTxResult {
        valid: classical && pq.valid,
        classical,
        pq: Some(pq),
    })
}
