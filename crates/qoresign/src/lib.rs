// SPDX-License-Identifier: Apache-2.0
//
// qorechain-qoresign: hybrid secp256k1 + ML-DSA-87 (FIPS 204) signing,
// verification and Sign In With QoreChain. Offline only.

//! Hybrid secp256k1 + ML-DSA-87 (FIPS 204) signing, verification and Sign In
//! With QoreChain (SIWQ) for QoreChain accounts.
//!
//! This crate is offline: it derives keys, builds and checks signatures and
//! never talks to a network. Its output is byte-identical to the other
//! QoreSign implementations; `vectors/qoresign-v1.json` in the repository is
//! the shared contract.
//!
//! Lanes covered today: the native lane carries a hybrid ML-DSA-87 (FIPS 204)
//! signature; EVM transactions carry none ("quantum-ready" only); the SVM lane
//! is not available.
//!
//! ```
//! use qoresign::{address_from_public_key, derive_canonical_pq_key, derive_classical_key, sign_hybrid,
//!     verify_hybrid_tx, ClassicalKeyType, SignHybridArgs, VerifyHybridTxArgs};
//! # fn tx_body_bytes() -> Vec<u8> { vec![0x12, 0x04, b'm', b'e', b'm', b'o'] }
//! # fn auth_info_bytes() -> Vec<u8> { vec![0x12, 0x02, 0x10, 0x01] }
//! # fn main() -> Result<(), qoresign::Error> {
//!
//! // Public BIP-39 test mnemonic: never send funds to it.
//! let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
//! let classical = derive_classical_key(mnemonic, ClassicalKeyType::Secp256k1, 0)?;
//! let account = address_from_public_key(&classical.public_key, ClassicalKeyType::Secp256k1)?;
//! let pq = derive_canonical_pq_key(mnemonic, &account.bech32)?;
//!
//! // Encoded TxBody and AuthInfo, as your transaction builder produced them.
//! let (body, auth_info) = (tx_body_bytes(), auth_info_bytes());
//! let args = SignHybridArgs::new("qorechain-vladi", 7, &body, &auth_info, &classical, Some(&pq));
//! let signed = sign_hybrid(&args)?; // signed.tx_bytes is ready to broadcast
//!
//! let check = VerifyHybridTxArgs::new(&signed.tx_bytes, "qorechain-vladi", 7, &classical.public_key, Some(&pq.public_key));
//! assert!(verify_hybrid_tx(&check)?.valid);
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod errors;
pub mod keys;
pub mod lanes;
pub mod proto;
pub mod registration;
pub mod sign;
pub mod siwq;
pub mod verify;

pub use errors::{Error, Result};
pub use keys::{
    address_from_bytes, address_from_public_key, classical_key_from_private,
    classical_key_type_for, default_classical_path, default_hd_path, derive_canonical_pq_key,
    derive_classical_key, derive_classical_key_at, derive_hd_pq_key, derive_hd_pq_key_from_seed,
    parse_address, pq_key_from_seed, AccountAddress, ClassicalKey, ClassicalKeyType, PqKeyPair,
    ACCOUNT_PREFIX, ALGORITHM_ML_DSA_87, CANONICAL_DERIVATION_DOMAIN, HD_MASTER_KEY,
    ML_DSA_87_PUBLIC_KEY_LENGTH, ML_DSA_87_SECRET_KEY_LENGTH, ML_DSA_87_SEED_LENGTH,
    ML_DSA_87_SIGNATURE_LENGTH,
};
pub use lanes::{
    assert_hybrid_lane, decide_lane, evaluate_layer_state, Lane, LaneDecision, LaneReason,
    LaneRequest, LaneSupport, LayerState, LayerStateInput, LANE_SUPPORT,
};
pub use proto::{
    append_extension, decode_any, decode_tx_raw, encode_any, encode_sign_doc, encode_tx_raw,
    strip_extension, AnyMessage, TxRawParts,
};
pub use registration::{
    build_register_pq_key_message, is_degenerate_pq_public_key, proof_of_possession_message,
    sign_proof_of_possession, verify_proof_of_possession, MSG_REGISTER_PQC_KEY_V2_TYPE_URL,
    PROOF_OF_POSSESSION_DOMAIN,
};
pub use sign::{
    classical_sign, classical_verify, decode_pqc_hybrid_signature, encode_pqc_hybrid_signature,
    hybrid_sign_bytes, pq_sign, pq_verify, pqc_layers, sign_hybrid, sign_pq_layer, PqLayer,
    PqcHybridSignature, SignBytesVersion, SignHybridArgs, SignOptions, SignedTx, SigningMode,
    PQC_HYBRID_TYPE_URL,
};
pub use siwq::{
    adr36_sign_bytes, create_siwq_message, parse_siwq_message, parse_timestamp_ms, sign_siwq,
    siwq_pq_sign_bytes, verify_siwq, SiwqClassicalSignature, SiwqFields, SiwqPqSignature,
    SiwqSignature, SiwqSignatureType, VerifySiwqArgs, SIWQ_PQ_DOMAIN,
};
pub use verify::{
    verify_hybrid_tx, verify_pq_layer, HybridTxResult, PqLayerFailure, PqLayerResult,
    VerifyHybridTxArgs, VerifyVersion,
};
