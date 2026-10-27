// SPDX-License-Identifier: Apache-2.0
//
// Hybrid transaction signing for QoreChain's native (Cosmos SDK) lane.
//
// A hybrid transaction carries two signatures:
//  1. an ML-DSA-87 signature over the hybrid sign-bytes, attached to the
//     TxBody as the `/qorechain.pqc.v1.PQCHybridSignature` extension option;
//  2. the usual secp256k1 SIGN_MODE_DIRECT signature over the FINAL body (the
//     one that carries the extension), in `TxRaw.signatures`.
//
// Hybrid sign-bytes, where B0 is the body WITHOUT the PQC extension and A the
// auth-info bytes:
//   v1: BE32(len B0) || B0 || BE32(len A) || A
//   v2: "qorechain-pqc-hybrid-v2" || BE64(len chainId) || chainId || v1
// Both public networks verify v2 since their v3.1.98/v3.2.0 upgrades; v1 is
// only needed to reproduce signatures from before those heights.

use core::str::FromStr;

use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use qorechain_pqc::mldsa::ml_dsa_87;
use sha2::{Digest, Sha256};

use crate::errors::{require_length, Error, Result};
use crate::keys::{
    keccak256, ClassicalKey, ClassicalKeyType, PqKeyPair, ALGORITHM_ML_DSA_87,
    ML_DSA_87_PUBLIC_KEY_LENGTH, ML_DSA_87_SECRET_KEY_LENGTH, ML_DSA_87_SIGNATURE_LENGTH,
};
use crate::proto::{
    append_extension, body_extensions, encode_sign_doc, encode_tx_raw, len_field, read_fields,
    varint_field, AnyMessage, TxRawParts, WIRE_LEN, WIRE_VARINT,
};

/// Hybrid sign-bytes form.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum SignBytesVersion {
    V1,
    #[default]
    V2,
}

impl SignBytesVersion {
    /// `"v1"` or `"v2"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            SignBytesVersion::V1 => "v1",
            SignBytesVersion::V2 => "v2",
        }
    }
}

impl FromStr for SignBytesVersion {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "v1" => Ok(SignBytesVersion::V1),
            "v2" => Ok(SignBytesVersion::V2),
            _ => Err(Error::SignBytesVersionUnknown(format!(
                "unknown sign-bytes version {s:?}"
            ))),
        }
    }
}

/// Type URL of the PQC extension option.
pub const PQC_HYBRID_TYPE_URL: &str = "/qorechain.pqc.v1.PQCHybridSignature";

/// Hybrid sign-bytes for `body_bytes` (the PQC extension is removed first if present).
pub fn hybrid_sign_bytes(
    chain_id: &str,
    body_bytes: &[u8],
    auth_info_bytes: &[u8],
    version: SignBytesVersion,
) -> Result<Vec<u8>> {
    if chain_id.is_empty() {
        return Err(Error::InvalidArgument("chainId is required".into()));
    }
    let b0 = crate::proto::strip_extension(body_bytes, PQC_HYBRID_TYPE_URL)?;
    let v = match version {
        SignBytesVersion::V1 => qorechain_pqc::SignBytesVersion::V1,
        SignBytesVersion::V2 => qorechain_pqc::SignBytesVersion::V2,
    };
    Ok(qorechain_pqc::hybrid_sign_bytes(
        v,
        chain_id,
        &b0,
        auth_info_bytes,
    ))
}

/// `qorechain.pqc.v1.PQCHybridSignature`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PqcHybridSignature {
    pub algorithm_id: u32,
    pub signature: Vec<u8>,
    /// Present only when the key is embedded for registration on first use.
    pub public_key: Option<Vec<u8>>,
}

pub fn encode_pqc_hybrid_signature(sig: &PqcHybridSignature) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(sig.signature.len() + sig.public_key.as_ref().map_or(0, Vec::len) + 16);
    varint_field(1, u64::from(sig.algorithm_id), &mut out);
    len_field(2, &sig.signature, &mut out);
    if let Some(pk) = &sig.public_key {
        len_field(3, pk, &mut out);
    }
    out
}

pub fn decode_pqc_hybrid_signature(bytes: &[u8]) -> Result<PqcHybridSignature> {
    let mut out = PqcHybridSignature::default();
    for f in read_fields(bytes)? {
        match (f.field, f.wire_type) {
            // Ids that do not fit u32 are unsupported either way.
            (1, WIRE_VARINT) => {
                out.algorithm_id = u32::try_from(f.varint.unwrap_or(0)).unwrap_or(u32::MAX)
            }
            (2, WIRE_LEN) => out.signature = f.bytes.unwrap_or_default().to_vec(),
            (3, WIRE_LEN) => out.public_key = Some(f.bytes.unwrap_or_default().to_vec()),
            _ => {}
        }
    }
    Ok(out)
}

/// The PQC layers attached to a body (a valid transaction has exactly one).
pub fn pqc_layers(body_bytes: &[u8]) -> Result<Vec<PqcHybridSignature>> {
    body_extensions(body_bytes)?
        .iter()
        .filter(|a| a.type_url == PQC_HYBRID_TYPE_URL)
        .map(|a| decode_pqc_hybrid_signature(&a.value))
        .collect()
}

/// ML-DSA-87 signature. Deterministic unless `hedged` (the chain accepts both).
pub fn pq_sign(secret_key: &[u8], message: &[u8], hedged: bool) -> Result<Vec<u8>> {
    require_length(
        secret_key,
        ML_DSA_87_SECRET_KEY_LENGTH,
        "ML-DSA-87 secret key",
    )?;
    let sig = if hedged {
        ml_dsa_87::sign_hedged(secret_key, message)
    } else {
        ml_dsa_87::sign(secret_key, message)
    };
    sig.map_err(|e| Error::InvalidArgument(format!("ML-DSA-87 signing failed: {e}")))
}

/// ML-DSA-87 verification. Never panics; false on malformed input.
pub fn pq_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if public_key.len() != ML_DSA_87_PUBLIC_KEY_LENGTH
        || signature.len() != ML_DSA_87_SIGNATURE_LENGTH
    {
        return false;
    }
    ml_dsa_87::verify(public_key, message, signature)
}

fn digest(key_type: ClassicalKeyType, msg: &[u8]) -> [u8; 32] {
    match key_type {
        ClassicalKeyType::EthSecp256k1 => keccak256(msg),
        ClassicalKeyType::Secp256k1 => Sha256::digest(msg).into(),
    }
}

/// 64-byte (r || s, low-S) secp256k1 signature over the key type's digest of `message`.
pub fn classical_sign(
    key_type: ClassicalKeyType,
    private_key: &[u8],
    message: &[u8],
) -> Result<[u8; 64]> {
    require_length(private_key, 32, "secp256k1 private key")?;
    let sk = SigningKey::from_slice(private_key)
        .map_err(|_| Error::InvalidArgument("invalid secp256k1 private key".into()))?;
    let sig: Signature = sk
        .sign_prehash(&digest(key_type, message))
        .map_err(|_| Error::InvalidArgument("secp256k1 signing failed".into()))?;
    let sig = sig.normalize_s().unwrap_or(sig);
    Ok(sig.to_bytes().into())
}

/// Verify a 64-byte low-S secp256k1 signature. Never panics; false on malformed input.
pub fn classical_verify(
    key_type: ClassicalKeyType,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    if signature.len() != 64 {
        return false;
    }
    let Ok(vk) = VerifyingKey::from_sec1_bytes(public_key) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(signature) else {
        return false;
    };
    if sig.normalize_s().is_some() {
        return false;
    }
    vk.verify_prehash(&digest(key_type, message), &sig).is_ok()
}

/// Options shared by the signing functions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SignOptions {
    /// Default v2.
    pub sign_bytes_version: SignBytesVersion,
    /// Embed the public key so the chain can register it on first use.
    pub include_public_key: bool,
    /// Randomized ML-DSA-87 signing; deterministic when false.
    pub hedged: bool,
}

/// A body carrying the ML-DSA-87 layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqLayer {
    pub body_bytes: Vec<u8>,
    pub pq_signature: Vec<u8>,
}

/// Add the ML-DSA-87 layer to a transaction body (an existing PQC layer is
/// replaced). Use this when the classical signature is produced elsewhere (for
/// example by a Keplr-compatible wallet's `signDirect`): the classical signer
/// must sign the returned `body_bytes`.
pub fn sign_pq_layer(
    chain_id: &str,
    body_bytes: &[u8],
    auth_info_bytes: &[u8],
    pq_key: &PqKeyPair,
    options: &SignOptions,
) -> Result<PqLayer> {
    let b0 = crate::proto::strip_extension(body_bytes, PQC_HYBRID_TYPE_URL)?;
    let message = hybrid_sign_bytes(chain_id, &b0, auth_info_bytes, options.sign_bytes_version)?;
    let pq_signature = pq_sign(&pq_key.secret_key, &message, options.hedged)?;
    let ext = encode_pqc_hybrid_signature(&PqcHybridSignature {
        algorithm_id: ALGORITHM_ML_DSA_87,
        signature: pq_signature.clone(),
        public_key: options
            .include_public_key
            .then(|| pq_key.public_key.clone()),
    });
    let body_bytes = append_extension(
        &b0,
        &AnyMessage {
            type_url: PQC_HYBRID_TYPE_URL.to_owned(),
            value: ext,
        },
    )?;
    Ok(PqLayer {
        body_bytes,
        pq_signature,
    })
}

/// `Hybrid` (default): ML-DSA-87 layer plus secp256k1. `ClassicalOnly`: no PQC
/// layer, for the transaction that registers the account's PQC key.
/// `PqOnly` is not accepted by the network for ordinary accounts and fails.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum SigningMode {
    #[default]
    Hybrid,
    ClassicalOnly,
    PqOnly,
}

/// Input of [`sign_hybrid`].
#[derive(Clone, Copy, Debug)]
pub struct SignHybridArgs<'a> {
    pub chain_id: &'a str,
    pub account_number: u64,
    pub body_bytes: &'a [u8],
    pub auth_info_bytes: &'a [u8],
    pub classical_key: &'a ClassicalKey,
    /// Required in `Hybrid` mode.
    pub pq_key: Option<&'a PqKeyPair>,
    pub mode: SigningMode,
    pub options: SignOptions,
}

impl<'a> SignHybridArgs<'a> {
    /// Hybrid mode with default options.
    pub fn new(
        chain_id: &'a str,
        account_number: u64,
        body_bytes: &'a [u8],
        auth_info_bytes: &'a [u8],
        classical_key: &'a ClassicalKey,
        pq_key: Option<&'a PqKeyPair>,
    ) -> Self {
        Self {
            chain_id,
            account_number,
            body_bytes,
            auth_info_bytes,
            classical_key,
            pq_key,
            mode: SigningMode::Hybrid,
            options: SignOptions::default(),
        }
    }
}

/// A signed native-lane transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTx {
    /// Encoded `TxRaw`, ready to broadcast.
    pub tx_bytes: Vec<u8>,
    pub body_bytes: Vec<u8>,
    pub auth_info_bytes: Vec<u8>,
    pub classical_signature: [u8; 64],
    pub pq_signature: Option<Vec<u8>>,
}

/// Sign a native-lane transaction with both keys.
pub fn sign_hybrid(args: &SignHybridArgs<'_>) -> Result<SignedTx> {
    if args.mode == SigningMode::PqOnly {
        return Err(Error::LaneNotAvailable(
            "PQ-only transactions are not accepted for ordinary accounts; use the hybrid mode"
                .into(),
        ));
    }
    let mut body_bytes = crate::proto::strip_extension(args.body_bytes, PQC_HYBRID_TYPE_URL)?;
    let mut pq_signature = None;
    if args.mode == SigningMode::Hybrid {
        let pq_key = args
            .pq_key
            .ok_or_else(|| Error::InvalidArgument("hybrid mode needs pqKey".into()))?;
        let layered = sign_pq_layer(
            args.chain_id,
            &body_bytes,
            args.auth_info_bytes,
            pq_key,
            &args.options,
        )?;
        body_bytes = layered.body_bytes;
        pq_signature = Some(layered.pq_signature);
    }
    let sign_doc = encode_sign_doc(
        &body_bytes,
        args.auth_info_bytes,
        args.chain_id,
        args.account_number,
    );
    let classical_signature = classical_sign(
        args.classical_key.key_type,
        &args.classical_key.private_key,
        &sign_doc,
    )?;
    let tx_bytes = encode_tx_raw(&TxRawParts {
        body_bytes: body_bytes.clone(),
        auth_info_bytes: args.auth_info_bytes.to_vec(),
        signatures: vec![classical_signature.to_vec()],
    });
    Ok(SignedTx {
        tx_bytes,
        body_bytes,
        auth_info_bytes: args.auth_info_bytes.to_vec(),
        classical_signature,
        pq_signature,
    })
}
