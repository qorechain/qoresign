// SPDX-License-Identifier: Apache-2.0
//
// Accounts, classical keys and ML-DSA-87 key derivation.

use core::fmt;
use core::str::FromStr;

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32, Hrp};
use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use qorechain_pqc::mldsa::ml_dsa_87;
use ripemd::Ripemd160;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Keccak256, Shake256};

use crate::errors::{require_length, Error, Result};

/// Bech32 prefix of QoreChain accounts.
pub const ACCOUNT_PREFIX: &str = "qor";

/// ML-DSA-87 sizes (FIPS 204, Table 2).
pub const ML_DSA_87_PUBLIC_KEY_LENGTH: usize = 2592;
pub const ML_DSA_87_SECRET_KEY_LENGTH: usize = 4896;
pub const ML_DSA_87_SIGNATURE_LENGTH: usize = 4627;
pub const ML_DSA_87_SEED_LENGTH: usize = 32;

/// Algorithm id of ML-DSA-87 in `qorechain.pqc.v1` (named Dilithium5 on chain).
pub const ALGORITHM_ML_DSA_87: u32 = 1;

/// How a classical key maps to an account:
/// - `Secp256k1`: Cosmos SDK accounts, address = RIPEMD160(SHA256(compressed key)), SLIP-44 coin type 118.
/// - `EthSecp256k1`: eth-native accounts, address = last 20 bytes of KECCAK256(uncompressed key),
///   the same 20 bytes behind the `qor1` and `0x` forms, coin type 60.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClassicalKeyType {
    #[serde(rename = "secp256k1")]
    Secp256k1,
    #[serde(rename = "eth_secp256k1")]
    EthSecp256k1,
}

impl ClassicalKeyType {
    /// `"secp256k1"` or `"eth_secp256k1"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            ClassicalKeyType::Secp256k1 => "secp256k1",
            ClassicalKeyType::EthSecp256k1 => "eth_secp256k1",
        }
    }
}

impl FromStr for ClassicalKeyType {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "secp256k1" => Ok(ClassicalKeyType::Secp256k1),
            "eth_secp256k1" => Ok(ClassicalKeyType::EthSecp256k1),
            _ => Err(Error::InvalidArgument(format!(
                "unknown classical key type {s:?}"
            ))),
        }
    }
}

/// A secp256k1 key and the account derivation it is used with.
#[derive(Clone, PartialEq, Eq)]
pub struct ClassicalKey {
    pub key_type: ClassicalKeyType,
    /// 32-byte secp256k1 secret key.
    pub private_key: [u8; 32],
    /// 33-byte compressed public key.
    pub public_key: [u8; 33],
}

impl fmt::Debug for ClassicalKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClassicalKey")
            .field("key_type", &self.key_type)
            .field("public_key", &hex::encode(self.public_key))
            .finish_non_exhaustive()
    }
}

/// An ML-DSA-87 key pair.
#[derive(Clone, PartialEq, Eq)]
pub struct PqKeyPair {
    pub algorithm_id: u32,
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl fmt::Debug for PqKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PqKeyPair")
            .field("algorithm_id", &self.algorithm_id)
            .field("public_key_len", &self.public_key.len())
            .finish_non_exhaustive()
    }
}

/// An account's address in both forms.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AccountAddress {
    /// Bech32 form, `qor1...`.
    pub bech32: String,
    /// EIP-55 checksummed hex form of the same 20 bytes.
    pub hex: String,
    /// The raw 20 address bytes.
    pub bytes: [u8; 20],
}

/// Default HD path of the classical key: `m/44'/118'/0'/0/i` or `m/44'/60'/0'/0/i`.
pub fn default_classical_path(key_type: ClassicalKeyType, index: u32) -> String {
    match key_type {
        ClassicalKeyType::Secp256k1 => format!("m/44'/118'/0'/0/{index}"),
        ClassicalKeyType::EthSecp256k1 => format!("m/44'/60'/0'/0/{index}"),
    }
}

pub(crate) fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

fn checksum_hex(bytes: &[u8]) -> String {
    let lower = hex::encode(bytes);
    let hash = hex::encode(keccak256(lower.as_bytes()));
    let mut out = String::with_capacity(2 + lower.len());
    out.push_str("0x");
    for (c, h) in lower.chars().zip(hash.chars()) {
        let nibble = h.to_digit(16).unwrap_or(0);
        if nibble >= 8 {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Build both address forms from 20 address bytes.
pub fn address_from_bytes(bytes: &[u8]) -> Result<AccountAddress> {
    require_length(bytes, 20, "address")?;
    let mut raw = [0u8; 20];
    raw.copy_from_slice(bytes);
    let hrp = Hrp::parse(ACCOUNT_PREFIX).map_err(|e| Error::InvalidAddress(e.to_string()))?;
    let bech32 =
        bech32::encode::<Bech32>(hrp, &raw).map_err(|e| Error::InvalidAddress(e.to_string()))?;
    Ok(AccountAddress {
        bech32,
        hex: checksum_hex(&raw),
        bytes: raw,
    })
}

fn is_plain_hex_address(s: &str) -> bool {
    s.len() == 42 && s.starts_with("0x") && s.as_bytes()[2..].iter().all(u8::is_ascii_hexdigit)
}

/// Parse a `qor1...` or `0x...` address.
pub fn parse_address(address: &str) -> Result<AccountAddress> {
    if is_plain_hex_address(address) {
        let bytes = hex::decode(&address[2..])
            .map_err(|_| Error::InvalidArgument("invalid hex string".into()))?;
        return address_from_bytes(&bytes);
    }
    let not_address = || Error::InvalidAddress(format!("not a QoreChain address: {address:?}"));
    // Same limits as the reference decoder: at most 90 characters, one case.
    if address.len() > 90
        || (address != address.to_ascii_lowercase() && address != address.to_ascii_uppercase())
    {
        return Err(not_address());
    }
    let checked = CheckedHrpstring::new::<Bech32>(address).map_err(|_| not_address())?;
    let prefix = checked.hrp().to_lowercase();
    if prefix != ACCOUNT_PREFIX {
        return Err(Error::InvalidAddress(format!(
            "expected the \"{ACCOUNT_PREFIX}\" prefix, got \"{prefix}\""
        )));
    }
    checked
        .validate_segwit_padding()
        .map_err(|_| not_address())?;
    let bytes: Vec<u8> = checked.byte_iter().collect();
    if bytes.len() != 20 {
        return Err(Error::InvalidAddress(format!(
            "account addresses are 20 bytes, got {}",
            bytes.len()
        )));
    }
    address_from_bytes(&bytes)
}

fn parse_public_key(public_key: &[u8]) -> Result<k256::PublicKey> {
    k256::PublicKey::from_sec1_bytes(public_key)
        .map_err(|_| Error::InvalidArgument("invalid secp256k1 public key".into()))
}

/// The account a classical public key (33-byte compressed or 65-byte
/// uncompressed) controls.
pub fn address_from_public_key(
    public_key: &[u8],
    key_type: ClassicalKeyType,
) -> Result<AccountAddress> {
    let point = parse_public_key(public_key)?;
    match key_type {
        ClassicalKeyType::Secp256k1 => {
            let compressed = point.to_encoded_point(true);
            let sha = Sha256::digest(compressed.as_bytes());
            address_from_bytes(&Ripemd160::digest(sha))
        }
        ClassicalKeyType::EthSecp256k1 => {
            let uncompressed = point.to_encoded_point(false);
            let hash = keccak256(&uncompressed.as_bytes()[1..]);
            address_from_bytes(&hash[12..])
        }
    }
}

/// Which derivation a public key uses for `address`, or `None` when the key
/// belongs to neither.
pub fn classical_key_type_for(
    public_key: &[u8],
    address: &str,
) -> Result<Option<ClassicalKeyType>> {
    let target = parse_address(address)?.bytes;
    for key_type in [ClassicalKeyType::Secp256k1, ClassicalKeyType::EthSecp256k1] {
        if address_from_public_key(public_key, key_type)?.bytes == target {
            return Ok(Some(key_type));
        }
    }
    Ok(None)
}

/// The mnemonic is part of the canonical derivation input, so a different
/// spacing would silently give a different key. Only the canonical form
/// (lowercase words, single spaces, nothing around them) is accepted.
fn check_mnemonic(mnemonic: &str) -> Result<bip39::Mnemonic> {
    // English BIP-39 phrases are ASCII; anything else cannot be canonical.
    let normalized = mnemonic
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if !mnemonic.is_ascii() || normalized != mnemonic {
        return Err(Error::InvalidMnemonic(
            "pass the mnemonic in canonical form: words separated by single spaces, no surrounding whitespace"
                .into(),
        ));
    }
    bip39::Mnemonic::parse_in_normalized(bip39::Language::English, mnemonic).map_err(|_| {
        Error::InvalidMnemonic("the mnemonic is not a valid BIP-39 English phrase".into())
    })
}

fn mnemonic_seed(mnemonic: &str, passphrase: &str) -> Result<[u8; 64]> {
    Ok(check_mnemonic(mnemonic)?.to_seed(passphrase))
}

/// Derive the classical key on the default path for `index`.
pub fn derive_classical_key(
    mnemonic: &str,
    key_type: ClassicalKeyType,
    index: u32,
) -> Result<ClassicalKey> {
    derive_classical_key_at(
        mnemonic,
        key_type,
        &default_classical_path(key_type, index),
        "",
    )
}

/// Derive the classical key at `path` (BIP-32/BIP-44) from a BIP-39 mnemonic.
pub fn derive_classical_key_at(
    mnemonic: &str,
    key_type: ClassicalKeyType,
    path: &str,
    passphrase: &str,
) -> Result<ClassicalKey> {
    let seed = mnemonic_seed(mnemonic, passphrase)?;
    let path = bip32::DerivationPath::from_str(path)
        .map_err(|_| Error::InvalidArgument(format!("invalid derivation path {path:?}")))?;
    let node = bip32::XPrv::derive_from_path(seed, &path)
        .map_err(|_| Error::InvalidArgument("derivation produced no private key".into()))?;
    let private_key: [u8; 32] = node.private_key().to_bytes().into();
    classical_key_from_private(&private_key, key_type)
}

/// Wrap an existing secp256k1 secret key.
pub fn classical_key_from_private(
    private_key: &[u8],
    key_type: ClassicalKeyType,
) -> Result<ClassicalKey> {
    require_length(private_key, 32, "secp256k1 private key")?;
    let sk = k256::ecdsa::SigningKey::from_slice(private_key)
        .map_err(|_| Error::InvalidArgument("invalid secp256k1 private key".into()))?;
    let point = sk.verifying_key().to_encoded_point(true);
    let mut public_key = [0u8; 33];
    public_key.copy_from_slice(point.as_bytes());
    let mut raw = [0u8; 32];
    raw.copy_from_slice(private_key);
    Ok(ClassicalKey {
        key_type,
        private_key: raw,
        public_key,
    })
}

/// Key pair from a 32-byte ML-DSA-87 seed (FIPS 204 ML-DSA.KeyGen_internal).
pub fn pq_key_from_seed(seed: &[u8]) -> Result<PqKeyPair> {
    require_length(seed, ML_DSA_87_SEED_LENGTH, "ML-DSA-87 seed")?;
    let mut xi = [0u8; 32];
    xi.copy_from_slice(seed);
    let (public_key, secret_key) = ml_dsa_87::keygen_from_seed(&xi);
    Ok(PqKeyPair {
        algorithm_id: ALGORITHM_ML_DSA_87,
        public_key,
        secret_key,
    })
}

/// Domain of the canonical derivation.
pub const CANONICAL_DERIVATION_DOMAIN: &str = "qorechain:pqc:v1";

/// The canonical ML-DSA-87 key of an account: the seed is
/// `SHAKE256("qorechain:pqc:v1|" + bech32Address + "|" + mnemonic, 32 bytes)`.
///
/// This is the key QoreChain wallets and the QoreChain SDK derive today, so a
/// wallet using it signs with the key that is already registered for the
/// account. The key is bound to the address: the same mnemonic gives a
/// different key for every account.
pub fn derive_canonical_pq_key(mnemonic: &str, address: &str) -> Result<PqKeyPair> {
    check_mnemonic(mnemonic)?;
    let account = parse_address(address)?.bech32;
    let input = format!("{CANONICAL_DERIVATION_DOMAIN}|{account}|{mnemonic}");
    let mut h = Shake256::default();
    h.update(input.as_bytes());
    let mut seed = [0u8; ML_DSA_87_SEED_LENGTH];
    h.finalize_xof().read(&mut seed);
    pq_key_from_seed(&seed)
}

/// HMAC key of the hardened-only HD derivation (draft).
pub const HD_MASTER_KEY: &str = "qorechain-mldsa87-seed";
const HARDENED: u64 = 0x8000_0000;

fn parse_hardened_path(path: &str) -> Result<Vec<u32>> {
    let parts: Vec<&str> = path.trim().split('/').collect();
    if parts[0] != "m" {
        return Err(Error::HdInvalidPath(format!(
            "path must start with \"m\": {path}"
        )));
    }
    let is_digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    parts[1..]
        .iter()
        .map(|p| {
            let digits = match p.strip_suffix('\'') {
                Some(d) if is_digits(d) => d,
                _ if is_digits(p) => {
                    return Err(Error::HdNonHardened(format!(
                        "segment \"{p}\" is not hardened; ML-DSA has no public child derivation, so every segment must be hardened"
                    )))
                }
                _ => {
                    return Err(Error::HdInvalidPath(format!(
                        "invalid path segment \"{p}\""
                    )))
                }
            };
            match digits.parse::<u64>() {
                Ok(n) if n < HARDENED => Ok((n + HARDENED) as u32),
                _ => Err(Error::HdInvalidPath(format!(
                    "path index out of range: {p}"
                ))),
            }
        })
        .collect()
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    Mac::update(&mut mac, data);
    mac.finalize().into_bytes().into()
}

/// DRAFT: hardened-only hierarchical derivation of ML-DSA-87 keys
/// (see `spec/hd-derivation-draft.md`). Opt-in; the format may change before
/// it is final.
///
/// Uses the SLIP-10 construction with its own master key string:
/// `I = HMAC-SHA512("qorechain-mldsa87-seed", seed)`, then for each hardened
/// index `I = HMAC-SHA512(chainCode, 0x00 || k || ser32(i))`. The ML-DSA-87
/// seed is the final 32-byte `k`.
///
/// Unlike [`derive_canonical_pq_key`], the key is not bound to an address: it
/// must be registered on chain for the account that will use it.
pub fn derive_hd_pq_key(mnemonic: &str, path: &str, passphrase: &str) -> Result<PqKeyPair> {
    let seed = mnemonic_seed(mnemonic, passphrase)?;
    derive_hd_pq_key_from_seed(&seed, path)
}

/// [`derive_hd_pq_key`] from a 16 to 64 byte BIP-32 style seed.
pub fn derive_hd_pq_key_from_seed(seed: &[u8], path: &str) -> Result<PqKeyPair> {
    if seed.len() < 16 || seed.len() > 64 {
        return Err(Error::InvalidArgument("seed must be 16 to 64 bytes".into()));
    }
    let indexes = parse_hardened_path(path)?;
    let mut i = hmac_sha512(HD_MASTER_KEY.as_bytes(), seed);
    for index in indexes {
        let mut data = [0u8; 37];
        data[1..33].copy_from_slice(&i[..32]);
        data[33..].copy_from_slice(&index.to_be_bytes());
        i = hmac_sha512(&i[32..], &data);
    }
    pq_key_from_seed(&i[..32])
}

/// Default draft HD path for account `index`: `m/44'/<coin>'/<index>'/0'/0'`.
pub fn default_hd_path(index: u32, coin_type: u32) -> String {
    format!("m/44'/{coin_type}'/{index}'/0'/0'")
}
