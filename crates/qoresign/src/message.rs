// SPDX-License-Identifier: Apache-2.0
//
// Signing arbitrary messages (the `signArbitrary` of Keplr-compatible
// wallets): ADR-36 with the classical key, plus ML-DSA-87 over a
// domain-separated encoding. Format: spec/message-signing-v1.md.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::errors::{Error, Result};
use crate::keys::{
    classical_key_type_for, parse_address, ClassicalKey, ClassicalKeyType, PqKeyPair,
    ALGORITHM_ML_DSA_87,
};
use crate::sign::{classical_sign, classical_verify, pq_sign, pq_verify};
use crate::siwq::adr36_sign_bytes;

/// Domain prefix of the ML-DSA-87 part of a message signature.
pub const MESSAGE_PQ_DOMAIN: &str = "qorechain-msg-v1|";

/// Prefixes reserved for ML-DSA-87 signatures on QoreChain. Every off-chain
/// signature QoreSign makes starts with its own domain, so it can never be
/// mistaken for another one.
pub const RESERVED_PQ_DOMAINS: [&str; 6] = [
    "qorechain-pqc-hybrid-v2",
    "qorechain-pqc-pop-v1|",
    "qorechain:pqc:recovery:v1",
    "qorechain-svm-auth-v2",
    "qorechain-siwq-v1|",
    MESSAGE_PQ_DOMAIN,
];

fn check_chain_id(chain_id: &str) -> Result<()> {
    if chain_id.is_empty()
        || !chain_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(Error::InvalidArgument(format!(
            "invalid chain id {chain_id:?}"
        )));
    }
    Ok(())
}

/// The bytes the ML-DSA-87 key signs:
/// `"qorechain-msg-v1|" + chain_id + "|"` followed by the message.
pub fn message_pq_sign_bytes(chain_id: &str, data: &[u8]) -> Result<Vec<u8>> {
    check_chain_id(chain_id)?;
    let mut out = format!("{MESSAGE_PQ_DOMAIN}{chain_id}|").into_bytes();
    out.extend_from_slice(data);
    Ok(out)
}

/// `ml-dsa-87-hybrid` for both parts; `secp256k1` for a classical-only signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessageSignatureType {
    #[serde(rename = "ml-dsa-87-hybrid")]
    MlDsa87Hybrid,
    #[serde(rename = "secp256k1")]
    Secp256k1,
}

/// Classical part of a [`MessageSignature`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageClassicalSignature {
    pub key_type: ClassicalKeyType,
    /// Base64 compressed public key.
    pub public_key: String,
    /// Base64 64-byte signature over the ADR-36 sign document of the message.
    pub signature: String,
}

/// ML-DSA-87 part of a [`MessageSignature`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessagePqSignature {
    pub algorithm_id: u32,
    /// Base64 ML-DSA-87 signature over [`message_pq_sign_bytes`].
    pub signature: String,
}

/// A message signature, in the JSON shape shared by every implementation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageSignature {
    pub signature_type: MessageSignatureType,
    pub classical: MessageClassicalSignature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq: Option<MessagePqSignature>,
}

/// Sign an arbitrary message with the keys of `signer` (a `qor1` account).
/// Without `pq_key` the result is classical-only.
pub fn sign_message(
    chain_id: &str,
    signer: &str,
    data: &[u8],
    classical_key: &ClassicalKey,
    pq_key: Option<&PqKeyPair>,
    hedged: bool,
) -> Result<MessageSignature> {
    let signer = parse_address(signer)?.bech32;
    if classical_key_type_for(&classical_key.public_key, &signer)?.is_none() {
        return Err(Error::AddressMismatch(format!(
            "the classical key does not control {signer}"
        )));
    }
    let pq_bytes = message_pq_sign_bytes(chain_id, data)?;
    let classical = classical_sign(
        classical_key.key_type,
        &classical_key.private_key,
        &adr36_sign_bytes(&signer, data),
    )?;
    let pq = match pq_key {
        Some(k) => Some(MessagePqSignature {
            algorithm_id: ALGORITHM_ML_DSA_87,
            signature: B64.encode(pq_sign(&k.secret_key, &pq_bytes, hedged)?),
        }),
        None => None,
    };
    Ok(MessageSignature {
        signature_type: if pq.is_some() {
            MessageSignatureType::MlDsa87Hybrid
        } else {
            MessageSignatureType::Secp256k1
        },
        classical: MessageClassicalSignature {
            key_type: classical_key.key_type,
            public_key: B64.encode(classical_key.public_key),
            signature: B64.encode(classical),
        },
        pq,
    })
}

/// Input of [`verify_message`].
#[derive(Clone, Copy, Debug)]
pub struct VerifyMessageArgs<'a> {
    pub chain_id: &'a str,
    /// The `qor1` account that signed.
    pub signer: &'a str,
    pub data: &'a [u8],
    pub signature: &'a MessageSignature,
    /// The ML-DSA-87 public key registered on chain for `signer`. Required unless `require_pq` is false.
    pub pq_public_key: Option<&'a [u8]>,
    /// Default true: a classical-only signature is refused.
    pub require_pq: bool,
}

impl<'a> VerifyMessageArgs<'a> {
    /// Defaults: PQ part required.
    pub fn new(
        chain_id: &'a str,
        signer: &'a str,
        data: &'a [u8],
        signature: &'a MessageSignature,
        pq_public_key: Option<&'a [u8]>,
    ) -> Self {
        Self {
            chain_id,
            signer,
            data,
            signature,
            pq_public_key,
            require_pq: true,
        }
    }
}

fn decode_b64(s: &str) -> Option<Vec<u8>> {
    B64.decode(s).ok()
}

/// Verify a message signature. Fails unless the classical key controls
/// `signer`, its ADR-36 signature verifies and (unless `require_pq` is false)
/// the ML-DSA-87 signature verifies under `pq_public_key`.
pub fn verify_message(args: &VerifyMessageArgs<'_>) -> Result<()> {
    let signer = parse_address(args.signer)?.bech32;
    let pq_bytes = message_pq_sign_bytes(args.chain_id, args.data)?;
    let sig = args.signature;
    let (Some(classical_pub), Some(classical_sig)) = (
        decode_b64(&sig.classical.public_key),
        decode_b64(&sig.classical.signature),
    ) else {
        return Err(Error::ClassicalSignatureInvalid(
            "classical signature fields are not base64".into(),
        ));
    };
    let owner = classical_key_type_for(&classical_pub, &signer).unwrap_or(None);
    let Some(owner) = owner.filter(|o| *o == sig.classical.key_type) else {
        return Err(Error::AddressMismatch(format!(
            "the classical key does not control {signer}"
        )));
    };
    if !classical_verify(
        owner,
        &classical_pub,
        &adr36_sign_bytes(&signer, args.data),
        &classical_sig,
    ) {
        return Err(Error::ClassicalSignatureInvalid(
            "the classical signature does not verify".into(),
        ));
    }

    let Some(pq) = &sig.pq else {
        if args.require_pq {
            return Err(Error::PqLayerMissing(
                "the signature carries no ML-DSA-87 part".into(),
            ));
        }
        return Ok(());
    };
    if pq.algorithm_id != ALGORITHM_ML_DSA_87 {
        return Err(Error::UnsupportedAlgorithm(format!(
            "unsupported algorithm {}",
            pq.algorithm_id
        )));
    }
    let Some(pq_public_key) = args.pq_public_key else {
        return Err(Error::KeyNotRegistered(
            "pass the account's registered ML-DSA-87 public key".into(),
        ));
    };
    let Some(pq_sig) = decode_b64(&pq.signature) else {
        return Err(Error::PqSignatureInvalid(
            "ML-DSA-87 signature is not base64".into(),
        ));
    };
    if !pq_verify(pq_public_key, &pq_bytes, &pq_sig) {
        return Err(Error::PqSignatureInvalid(
            "the ML-DSA-87 signature does not verify".into(),
        ));
    }
    Ok(())
}
