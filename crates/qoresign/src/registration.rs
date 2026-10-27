// SPDX-License-Identifier: Apache-2.0
//
// Registering an account's ML-DSA-87 key (MsgRegisterPQCKeyV2) with a proof
// of possession.

use crate::errors::{Error, Result};
use crate::keys::{
    classical_key_type_for, parse_address, PqKeyPair, ALGORITHM_ML_DSA_87,
    ML_DSA_87_PUBLIC_KEY_LENGTH,
};
use crate::proto::{len_field, string_field, varint_field, AnyMessage};
use crate::sign::{pq_sign, pq_verify};

/// Domain of the proof-of-possession message.
pub const PROOF_OF_POSSESSION_DOMAIN: &str = "qorechain-pqc-pop-v1";

pub const MSG_REGISTER_PQC_KEY_V2_TYPE_URL: &str = "/qorechain.pqc.v1.MsgRegisterPQCKeyV2";

/// The message an ML-DSA-87 key signs to prove possession:
/// `qorechain-pqc-pop-v1|<chain-id>|1|<qor1 account>|<lowercase hex public key>`.
pub fn proof_of_possession_message(
    chain_id: &str,
    account: &str,
    public_key: &[u8],
) -> Result<Vec<u8>> {
    proof_of_possession_message_for(chain_id, account, public_key, ALGORITHM_ML_DSA_87)
}

/// [`proof_of_possession_message`] for an explicit algorithm id.
pub fn proof_of_possession_message_for(
    chain_id: &str,
    account: &str,
    public_key: &[u8],
    algorithm_id: u32,
) -> Result<Vec<u8>> {
    if chain_id.is_empty() {
        return Err(Error::InvalidArgument("chainId is required".into()));
    }
    let account = parse_address(account)?.bech32;
    Ok(format!(
        "{PROOF_OF_POSSESSION_DOMAIN}|{chain_id}|{algorithm_id}|{account}|{}",
        hex::encode(public_key)
    )
    .into_bytes())
}

pub fn sign_proof_of_possession(
    chain_id: &str,
    account: &str,
    pq_key: &PqKeyPair,
    hedged: bool,
) -> Result<Vec<u8>> {
    let msg = proof_of_possession_message(chain_id, account, &pq_key.public_key)?;
    pq_sign(&pq_key.secret_key, &msg, hedged)
}

pub fn verify_proof_of_possession(
    chain_id: &str,
    account: &str,
    public_key: &[u8],
    proof: &[u8],
) -> Result<bool> {
    let msg = proof_of_possession_message(chain_id, account, public_key)?;
    Ok(pq_verify(public_key, &msg, proof))
}

/// A public key whose t1 part is all zero can be forged and is refused by the network.
pub fn is_degenerate_pq_public_key(public_key: &[u8]) -> bool {
    public_key.len() == ML_DSA_87_PUBLIC_KEY_LENGTH && public_key[32..].iter().all(|&b| b == 0)
}

/// Build `MsgRegisterPQCKeyV2` for `account`, with the proof of possession and
/// the compressed classical key the network checks against the address.
/// Sign the transaction that carries it in `ClassicalOnly` mode.
pub fn build_register_pq_key_message(
    chain_id: &str,
    account: &str,
    pq_key: &PqKeyPair,
    classical_public_key: &[u8],
    hedged: bool,
) -> Result<AnyMessage> {
    let account = parse_address(account)?.bech32;
    if pq_key.public_key.len() != ML_DSA_87_PUBLIC_KEY_LENGTH {
        return Err(Error::BadKeyLength(format!(
            "ML-DSA-87 public key must be {ML_DSA_87_PUBLIC_KEY_LENGTH} bytes"
        )));
    }
    if is_degenerate_pq_public_key(&pq_key.public_key) {
        return Err(Error::InvalidArgument(
            "the public key's t1 part is all zero and would be forgeable".into(),
        ));
    }
    if classical_key_type_for(classical_public_key, &account)?.is_none() {
        return Err(Error::AddressMismatch(format!(
            "the classical public key does not control {account}"
        )));
    }
    let proof = sign_proof_of_possession(chain_id, &account, pq_key, hedged)?;
    let mut value = Vec::with_capacity(pq_key.public_key.len() + proof.len() + 128);
    string_field(1, &account, &mut value);
    len_field(2, &pq_key.public_key, &mut value);
    varint_field(3, u64::from(ALGORITHM_ML_DSA_87), &mut value);
    len_field(4, classical_public_key, &mut value);
    string_field(5, "hybrid", &mut value);
    len_field(6, &proof, &mut value);
    Ok(AnyMessage {
        type_url: MSG_REGISTER_PQC_KEY_V2_TYPE_URL.to_owned(),
        value,
    })
}
