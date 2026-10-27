// SPDX-License-Identifier: Apache-2.0
//
// UniFFI surface of QoreSign for the Swift, Kotlin and Python packages.
// Thin conversions over the `qoresign` crate; no logic of its own.

use qoresign as core;

uniffi::setup_scaffolding!();

// ---------------------------------------------------------------- errors

/// Every failure carries the stable code shared by all QoreSign
/// implementations (for example `INVALID_MNEMONIC`) and a human-readable
/// detail. (The field is not named `message`: that clashes with
/// `Throwable.message` in the Kotlin bindings.)
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum QoreSignError {
    #[error("{code}: {detail}")]
    Failure { code: String, detail: String },
}

impl From<core::Error> for QoreSignError {
    fn from(e: core::Error) -> Self {
        QoreSignError::Failure {
            code: e.code().to_owned(),
            detail: e.message().to_owned(),
        }
    }
}

type Result<T> = std::result::Result<T, QoreSignError>;

fn invalid_argument(message: &str) -> QoreSignError {
    QoreSignError::Failure {
        code: "INVALID_ARGUMENT".to_owned(),
        detail: message.to_owned(),
    }
}

// ---------------------------------------------------------------- keys

/// `Secp256k1`: Cosmos SDK account, coin type 118. `EthSecp256k1`: eth-native
/// account (same 20 bytes behind `qor1` and `0x`), coin type 60.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum ClassicalKeyType {
    Secp256k1,
    EthSecp256k1,
}

impl From<ClassicalKeyType> for core::ClassicalKeyType {
    fn from(t: ClassicalKeyType) -> Self {
        match t {
            ClassicalKeyType::Secp256k1 => core::ClassicalKeyType::Secp256k1,
            ClassicalKeyType::EthSecp256k1 => core::ClassicalKeyType::EthSecp256k1,
        }
    }
}

impl From<core::ClassicalKeyType> for ClassicalKeyType {
    fn from(t: core::ClassicalKeyType) -> Self {
        match t {
            core::ClassicalKeyType::Secp256k1 => ClassicalKeyType::Secp256k1,
            core::ClassicalKeyType::EthSecp256k1 => ClassicalKeyType::EthSecp256k1,
        }
    }
}

/// A secp256k1 key and the account derivation it is used with.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ClassicalKey {
    pub key_type: ClassicalKeyType,
    /// 32-byte secp256k1 secret key.
    pub private_key: Vec<u8>,
    /// 33-byte compressed public key.
    pub public_key: Vec<u8>,
}

impl From<core::ClassicalKey> for ClassicalKey {
    fn from(k: core::ClassicalKey) -> Self {
        ClassicalKey {
            key_type: k.key_type.into(),
            private_key: k.private_key.to_vec(),
            public_key: k.public_key.to_vec(),
        }
    }
}

impl ClassicalKey {
    fn to_core(&self) -> Result<core::ClassicalKey> {
        let k = core::classical_key_from_private(&self.private_key, self.key_type.into())?;
        if !self.public_key.is_empty() && self.public_key != k.public_key {
            return Err(invalid_argument("publicKey does not match privateKey"));
        }
        Ok(k)
    }
}

/// An ML-DSA-87 key pair.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PqKeyPair {
    pub algorithm_id: u32,
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl From<core::PqKeyPair> for PqKeyPair {
    fn from(k: core::PqKeyPair) -> Self {
        PqKeyPair {
            algorithm_id: k.algorithm_id,
            public_key: k.public_key,
            secret_key: k.secret_key,
        }
    }
}

impl From<PqKeyPair> for core::PqKeyPair {
    fn from(k: PqKeyPair) -> Self {
        core::PqKeyPair {
            algorithm_id: k.algorithm_id,
            public_key: k.public_key,
            secret_key: k.secret_key,
        }
    }
}

/// An account's address in both forms.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AccountAddress {
    /// Bech32 form, `qor1...`.
    pub bech32: String,
    /// EIP-55 checksummed hex form of the same 20 bytes.
    pub hex: String,
    /// The raw 20 address bytes.
    pub bytes: Vec<u8>,
}

impl From<core::AccountAddress> for AccountAddress {
    fn from(a: core::AccountAddress) -> Self {
        AccountAddress {
            bech32: a.bech32,
            hex: a.hex,
            bytes: a.bytes.to_vec(),
        }
    }
}

/// Derive the classical key from a BIP-39 mnemonic, at `path` when set,
/// otherwise on the default path for `index` (`m/44'/118'/0'/0/i` or
/// `m/44'/60'/0'/0/i`).
#[uniffi::export(default(index = 0, path = None, passphrase = ""))]
pub fn derive_classical_key(
    mnemonic: String,
    key_type: ClassicalKeyType,
    index: u32,
    path: Option<String>,
    passphrase: String,
) -> Result<ClassicalKey> {
    let path = path.unwrap_or_else(|| core::default_classical_path(key_type.into(), index));
    Ok(core::derive_classical_key_at(&mnemonic, key_type.into(), &path, &passphrase)?.into())
}

/// Wrap an existing 32-byte secp256k1 secret key.
#[uniffi::export]
pub fn classical_key_from_private(
    private_key: Vec<u8>,
    key_type: ClassicalKeyType,
) -> Result<ClassicalKey> {
    Ok(core::classical_key_from_private(&private_key, key_type.into())?.into())
}

/// Default HD path of the classical key for `index`.
#[uniffi::export(default(index = 0))]
pub fn default_classical_path(key_type: ClassicalKeyType, index: u32) -> String {
    core::default_classical_path(key_type.into(), index)
}

/// The account a classical public key (33-byte compressed or 65-byte uncompressed) controls.
#[uniffi::export]
pub fn address_from_public_key(
    public_key: Vec<u8>,
    key_type: ClassicalKeyType,
) -> Result<AccountAddress> {
    Ok(core::address_from_public_key(&public_key, key_type.into())?.into())
}

/// Both address forms from 20 address bytes.
#[uniffi::export]
pub fn address_from_bytes(bytes: Vec<u8>) -> Result<AccountAddress> {
    Ok(core::address_from_bytes(&bytes)?.into())
}

/// Parse a `qor1...` or `0x...` address.
#[uniffi::export]
pub fn parse_address(address: String) -> Result<AccountAddress> {
    Ok(core::parse_address(&address)?.into())
}

/// Which derivation a public key uses for `address`, or null when it controls neither.
#[uniffi::export]
pub fn classical_key_type_for(
    public_key: Vec<u8>,
    address: String,
) -> Result<Option<ClassicalKeyType>> {
    Ok(core::classical_key_type_for(&public_key, &address)?.map(Into::into))
}

/// The canonical ML-DSA-87 key of an account, as QoreChain wallets derive it:
/// seed = SHAKE256("qorechain:pqc:v1|" + bech32Address + "|" + mnemonic, 32 bytes).
#[uniffi::export]
pub fn derive_canonical_pq_key(mnemonic: String, address: String) -> Result<PqKeyPair> {
    Ok(core::derive_canonical_pq_key(&mnemonic, &address)?.into())
}

/// DRAFT hardened-only HD derivation of an ML-DSA-87 key. Not bound to an
/// address; the key must be registered for the account that uses it.
#[uniffi::export(default(passphrase = ""))]
pub fn derive_hd_pq_key(mnemonic: String, path: String, passphrase: String) -> Result<PqKeyPair> {
    Ok(core::derive_hd_pq_key(&mnemonic, &path, &passphrase)?.into())
}

/// DRAFT HD derivation from a 16 to 64 byte seed.
#[uniffi::export]
pub fn derive_hd_pq_key_from_seed(seed: Vec<u8>, path: String) -> Result<PqKeyPair> {
    Ok(core::derive_hd_pq_key_from_seed(&seed, &path)?.into())
}

/// Key pair from a 32-byte ML-DSA-87 seed (FIPS 204 ML-DSA.KeyGen_internal).
#[uniffi::export]
pub fn pq_key_from_seed(seed: Vec<u8>) -> Result<PqKeyPair> {
    Ok(core::pq_key_from_seed(&seed)?.into())
}

/// Default draft HD path for account `index`: `m/44'/<coin>'/<index>'/0'/0'`.
#[uniffi::export(default(index = 0, coin_type = 118))]
pub fn default_hd_path(index: u32, coin_type: u32) -> String {
    core::default_hd_path(index, coin_type)
}

// ---------------------------------------------------------------- signing

/// Hybrid sign-bytes form. Null arguments mean `V2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum SignBytesVersion {
    V1,
    V2,
}

impl From<SignBytesVersion> for core::SignBytesVersion {
    fn from(v: SignBytesVersion) -> Self {
        match v {
            SignBytesVersion::V1 => core::SignBytesVersion::V1,
            SignBytesVersion::V2 => core::SignBytesVersion::V2,
        }
    }
}

impl From<core::SignBytesVersion> for SignBytesVersion {
    fn from(v: core::SignBytesVersion) -> Self {
        match v {
            core::SignBytesVersion::V1 => SignBytesVersion::V1,
            core::SignBytesVersion::V2 => SignBytesVersion::V2,
        }
    }
}

/// `Hybrid` (default): ML-DSA-87 layer plus secp256k1. `ClassicalOnly`: no
/// PQC layer, for the transaction that registers the account's key.
/// `PqOnly` is not accepted by the network for ordinary accounts and fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum SigningMode {
    Hybrid,
    ClassicalOnly,
    PqOnly,
}

impl From<SigningMode> for core::SigningMode {
    fn from(m: SigningMode) -> Self {
        match m {
            SigningMode::Hybrid => core::SigningMode::Hybrid,
            SigningMode::ClassicalOnly => core::SigningMode::ClassicalOnly,
            SigningMode::PqOnly => core::SigningMode::PqOnly,
        }
    }
}

/// Options shared by the signing functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct SignOptions {
    /// Null means `V2`.
    #[uniffi(default = None)]
    pub sign_bytes_version: Option<SignBytesVersion>,
    /// Embed the public key so the chain can register it on first use.
    #[uniffi(default = false)]
    pub include_public_key: bool,
    /// Randomized ML-DSA-87 signing; deterministic when false.
    #[uniffi(default = false)]
    pub hedged: bool,
}

fn core_options(o: Option<SignOptions>) -> core::SignOptions {
    match o {
        None => core::SignOptions::default(),
        Some(o) => core::SignOptions {
            sign_bytes_version: o.sign_bytes_version.map(Into::into).unwrap_or_default(),
            include_public_key: o.include_public_key,
            hedged: o.hedged,
        },
    }
}

/// A body carrying the ML-DSA-87 layer.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PqLayer {
    pub body_bytes: Vec<u8>,
    pub pq_signature: Vec<u8>,
}

/// A signed native-lane transaction.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SignedTx {
    /// Encoded `TxRaw`, ready to broadcast.
    pub tx_bytes: Vec<u8>,
    pub body_bytes: Vec<u8>,
    pub auth_info_bytes: Vec<u8>,
    pub classical_signature: Vec<u8>,
    pub pq_signature: Option<Vec<u8>>,
}

/// Hybrid sign-bytes for `body_bytes` (an existing PQC extension is removed first).
#[uniffi::export(default(version = None))]
pub fn hybrid_sign_bytes(
    chain_id: String,
    body_bytes: Vec<u8>,
    auth_info_bytes: Vec<u8>,
    version: Option<SignBytesVersion>,
) -> Result<Vec<u8>> {
    let version = version.map(Into::into).unwrap_or_default();
    Ok(core::hybrid_sign_bytes(
        &chain_id,
        &body_bytes,
        &auth_info_bytes,
        version,
    )?)
}

/// Add the ML-DSA-87 layer to a transaction body (an existing layer is
/// replaced). The classical signer must sign the returned `body_bytes`.
#[uniffi::export(default(options = None))]
pub fn sign_pq_layer(
    chain_id: String,
    body_bytes: Vec<u8>,
    auth_info_bytes: Vec<u8>,
    pq_key: PqKeyPair,
    options: Option<SignOptions>,
) -> Result<PqLayer> {
    let layer = core::sign_pq_layer(
        &chain_id,
        &body_bytes,
        &auth_info_bytes,
        &pq_key.into(),
        &core_options(options),
    )?;
    Ok(PqLayer {
        body_bytes: layer.body_bytes,
        pq_signature: layer.pq_signature,
    })
}

/// Sign a native-lane transaction with both keys. `pq_key` is required in
/// `Hybrid` mode (the default).
#[uniffi::export(default(pq_key = None, mode = None, options = None))]
#[allow(clippy::too_many_arguments)]
pub fn sign_hybrid(
    chain_id: String,
    account_number: u64,
    body_bytes: Vec<u8>,
    auth_info_bytes: Vec<u8>,
    classical_key: ClassicalKey,
    pq_key: Option<PqKeyPair>,
    mode: Option<SigningMode>,
    options: Option<SignOptions>,
) -> Result<SignedTx> {
    let classical = classical_key.to_core()?;
    let pq: Option<core::PqKeyPair> = pq_key.map(Into::into);
    let args = core::SignHybridArgs {
        chain_id: &chain_id,
        account_number,
        body_bytes: &body_bytes,
        auth_info_bytes: &auth_info_bytes,
        classical_key: &classical,
        pq_key: pq.as_ref(),
        mode: mode.map(Into::into).unwrap_or_default(),
        options: core_options(options),
    };
    let signed = core::sign_hybrid(&args)?;
    Ok(SignedTx {
        tx_bytes: signed.tx_bytes,
        body_bytes: signed.body_bytes,
        auth_info_bytes: signed.auth_info_bytes,
        classical_signature: signed.classical_signature.to_vec(),
        pq_signature: signed.pq_signature,
    })
}

// ---------------------------------------------------------------- verification

/// Which sign-bytes versions a verifier accepts. Null arguments mean `V2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum VerifyVersion {
    V1,
    V2,
    /// A signature over v1 or v2 sign-bytes.
    Either,
}

impl From<VerifyVersion> for core::VerifyVersion {
    fn from(v: VerifyVersion) -> Self {
        match v {
            VerifyVersion::V1 => core::VerifyVersion::V1,
            VerifyVersion::V2 => core::VerifyVersion::V2,
            VerifyVersion::Either => core::VerifyVersion::Either,
        }
    }
}

/// Why a PQC layer did not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum PqLayerFailure {
    Missing,
    Duplicated,
    UnsupportedAlgorithm,
    EmbeddedKeyMismatch,
    InvalidSignature,
}

impl From<core::PqLayerFailure> for PqLayerFailure {
    fn from(f: core::PqLayerFailure) -> Self {
        match f {
            core::PqLayerFailure::Missing => PqLayerFailure::Missing,
            core::PqLayerFailure::Duplicated => PqLayerFailure::Duplicated,
            core::PqLayerFailure::UnsupportedAlgorithm => PqLayerFailure::UnsupportedAlgorithm,
            core::PqLayerFailure::EmbeddedKeyMismatch => PqLayerFailure::EmbeddedKeyMismatch,
            core::PqLayerFailure::InvalidSignature => PqLayerFailure::InvalidSignature,
        }
    }
}

/// Result of [`verify_pq_layer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct PqLayerResult {
    pub valid: bool,
    /// The sign-bytes version the signature verified under.
    pub sign_bytes_version: Option<SignBytesVersion>,
    pub reason: Option<PqLayerFailure>,
}

impl From<core::PqLayerResult> for PqLayerResult {
    fn from(r: core::PqLayerResult) -> Self {
        PqLayerResult {
            valid: r.valid,
            sign_bytes_version: r.sign_bytes_version.map(Into::into),
            reason: r.reason.map(Into::into),
        }
    }
}

/// Result of [`verify_hybrid_tx`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct HybridTxResult {
    /// True when every requested check passed.
    pub valid: bool,
    pub classical: bool,
    /// Null when no PQ key was supplied.
    pub pq: Option<PqLayerResult>,
}

/// Check the ML-DSA-87 layer of a body against the account's registered key.
#[uniffi::export(default(version = None))]
pub fn verify_pq_layer(
    chain_id: String,
    body_bytes: Vec<u8>,
    auth_info_bytes: Vec<u8>,
    pq_public_key: Vec<u8>,
    version: Option<VerifyVersion>,
) -> Result<PqLayerResult> {
    Ok(core::verify_pq_layer(
        &chain_id,
        &body_bytes,
        &auth_info_bytes,
        &pq_public_key,
        version.map(Into::into).unwrap_or_default(),
    )?
    .into())
}

/// Verify a single-signer hybrid transaction. Without `pq_public_key` only
/// the classical signature is checked. Defaults: `Secp256k1`, `V2`.
#[uniffi::export(default(pq_public_key = None, classical_key_type = None, version = None))]
pub fn verify_hybrid_tx(
    tx_bytes: Vec<u8>,
    chain_id: String,
    account_number: u64,
    classical_public_key: Vec<u8>,
    pq_public_key: Option<Vec<u8>>,
    classical_key_type: Option<ClassicalKeyType>,
    version: Option<VerifyVersion>,
) -> Result<HybridTxResult> {
    let args = core::VerifyHybridTxArgs {
        tx_bytes: &tx_bytes,
        chain_id: &chain_id,
        account_number,
        classical_public_key: &classical_public_key,
        classical_key_type: classical_key_type
            .map(Into::into)
            .unwrap_or(core::ClassicalKeyType::Secp256k1),
        pq_public_key: pq_public_key.as_deref(),
        version: version.map(Into::into).unwrap_or_default(),
    };
    let r = core::verify_hybrid_tx(&args)?;
    Ok(HybridTxResult {
        valid: r.valid,
        classical: r.classical,
        pq: r.pq.map(Into::into),
    })
}

// ---------------------------------------------------------------- registration

/// A protobuf `Any`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AnyMessage {
    pub type_url: String,
    pub value: Vec<u8>,
}

/// `qorechain-pqc-pop-v1|<chain-id>|1|<qor1 account>|<lowercase hex public key>`.
#[uniffi::export]
pub fn proof_of_possession_message(
    chain_id: String,
    account: String,
    public_key: Vec<u8>,
) -> Result<Vec<u8>> {
    Ok(core::proof_of_possession_message(
        &chain_id,
        &account,
        &public_key,
    )?)
}

#[uniffi::export(default(hedged = false))]
pub fn sign_proof_of_possession(
    chain_id: String,
    account: String,
    pq_key: PqKeyPair,
    hedged: bool,
) -> Result<Vec<u8>> {
    Ok(core::sign_proof_of_possession(
        &chain_id,
        &account,
        &pq_key.into(),
        hedged,
    )?)
}

#[uniffi::export]
pub fn verify_proof_of_possession(
    chain_id: String,
    account: String,
    public_key: Vec<u8>,
    proof: Vec<u8>,
) -> Result<bool> {
    Ok(core::verify_proof_of_possession(
        &chain_id,
        &account,
        &public_key,
        &proof,
    )?)
}

/// A public key whose t1 part is all zero can be forged and is refused by the network.
#[uniffi::export]
pub fn is_degenerate_pq_public_key(public_key: Vec<u8>) -> bool {
    core::is_degenerate_pq_public_key(&public_key)
}

/// `MsgRegisterPQCKeyV2` with the proof of possession. Sign the transaction
/// that carries it in `ClassicalOnly` mode.
#[uniffi::export(default(hedged = false))]
pub fn build_register_pq_key_message(
    chain_id: String,
    account: String,
    pq_key: PqKeyPair,
    classical_public_key: Vec<u8>,
    hedged: bool,
) -> Result<AnyMessage> {
    let any = core::build_register_pq_key_message(
        &chain_id,
        &account,
        &pq_key.into(),
        &classical_public_key,
        hedged,
    )?;
    Ok(AnyMessage {
        type_url: any.type_url,
        value: any.value,
    })
}

// ---------------------------------------------------------------- SIWQ

/// The fields of a sign-in message.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SiwqFields {
    /// RFC 3986 authority requesting the sign-in, e.g. `app.example.com`.
    pub domain: String,
    /// `qor1...` account.
    pub address: String,
    pub uri: String,
    /// Chain id, e.g. `qorechain-vladi`.
    pub chain_id: String,
    /// At least 8 alphanumeric characters, chosen by the server.
    pub nonce: String,
    /// ISO 8601 timestamp.
    pub issued_at: String,
    /// Optional scheme, e.g. `https`.
    #[uniffi(default = None)]
    pub scheme: Option<String>,
    #[uniffi(default = None)]
    pub statement: Option<String>,
    /// `"1"` when set; null renders as `"1"`.
    #[uniffi(default = None)]
    pub version: Option<String>,
    #[uniffi(default = None)]
    pub expiration_time: Option<String>,
    #[uniffi(default = None)]
    pub not_before: Option<String>,
    #[uniffi(default = None)]
    pub request_id: Option<String>,
    #[uniffi(default = None)]
    pub resources: Option<Vec<String>>,
}

impl From<core::SiwqFields> for SiwqFields {
    fn from(f: core::SiwqFields) -> Self {
        SiwqFields {
            domain: f.domain,
            address: f.address,
            uri: f.uri,
            chain_id: f.chain_id,
            nonce: f.nonce,
            issued_at: f.issued_at,
            scheme: f.scheme,
            statement: f.statement,
            version: f.version,
            expiration_time: f.expiration_time,
            not_before: f.not_before,
            request_id: f.request_id,
            resources: f.resources,
        }
    }
}

impl From<SiwqFields> for core::SiwqFields {
    fn from(f: SiwqFields) -> Self {
        core::SiwqFields {
            domain: f.domain,
            scheme: f.scheme,
            address: f.address,
            statement: f.statement,
            uri: f.uri,
            version: f.version,
            chain_id: f.chain_id,
            nonce: f.nonce,
            issued_at: f.issued_at,
            expiration_time: f.expiration_time,
            not_before: f.not_before,
            request_id: f.request_id,
            resources: f.resources,
        }
    }
}

/// `MlDsa87Hybrid` (`ml-dsa-87-hybrid`) for both parts; `Secp256k1` for a classical-only sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum SiwqSignatureType {
    MlDsa87Hybrid,
    Secp256k1,
}

/// Classical part of a [`SiwqSignature`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SiwqClassicalSignature {
    pub key_type: ClassicalKeyType,
    /// Base64 compressed public key.
    pub public_key: String,
    /// Base64 64-byte signature over the ADR-36 sign document.
    pub signature: String,
}

/// ML-DSA-87 part of a [`SiwqSignature`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SiwqPqSignature {
    pub algorithm_id: u32,
    /// Base64 ML-DSA-87 signature over `"qorechain-siwq-v1|" + message`.
    pub signature: String,
}

/// A SIWQ signature; [`siwq_signature_to_json`] gives the JSON shape shared
/// by every implementation.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SiwqSignature {
    pub signature_type: SiwqSignatureType,
    pub classical: SiwqClassicalSignature,
    #[uniffi(default = None)]
    pub pq: Option<SiwqPqSignature>,
}

impl From<core::SiwqSignature> for SiwqSignature {
    fn from(s: core::SiwqSignature) -> Self {
        SiwqSignature {
            signature_type: match s.signature_type {
                core::SiwqSignatureType::MlDsa87Hybrid => SiwqSignatureType::MlDsa87Hybrid,
                core::SiwqSignatureType::Secp256k1 => SiwqSignatureType::Secp256k1,
            },
            classical: SiwqClassicalSignature {
                key_type: s.classical.key_type.into(),
                public_key: s.classical.public_key,
                signature: s.classical.signature,
            },
            pq: s.pq.map(|p| SiwqPqSignature {
                algorithm_id: p.algorithm_id,
                signature: p.signature,
            }),
        }
    }
}

impl From<SiwqSignature> for core::SiwqSignature {
    fn from(s: SiwqSignature) -> Self {
        core::SiwqSignature {
            signature_type: match s.signature_type {
                SiwqSignatureType::MlDsa87Hybrid => core::SiwqSignatureType::MlDsa87Hybrid,
                SiwqSignatureType::Secp256k1 => core::SiwqSignatureType::Secp256k1,
            },
            classical: core::SiwqClassicalSignature {
                key_type: s.classical.key_type.into(),
                public_key: s.classical.public_key,
                signature: s.classical.signature,
            },
            pq: s.pq.map(|p| core::SiwqPqSignature {
                algorithm_id: p.algorithm_id,
                signature: p.signature,
            }),
        }
    }
}

/// Render a sign-in message (spec/siwq-v1.md).
#[uniffi::export]
pub fn create_siwq_message(fields: SiwqFields) -> Result<String> {
    Ok(core::create_siwq_message(&fields.into())?)
}

/// Parse a sign-in message; fails with `SIWQ_MALFORMED`.
#[uniffi::export]
pub fn parse_siwq_message(message: String) -> Result<SiwqFields> {
    Ok(core::parse_siwq_message(&message)?.into())
}

/// ADR-36 sign document the classical key signs for a sign-in message.
#[uniffi::export]
pub fn adr36_sign_bytes(signer: String, data: Vec<u8>) -> Vec<u8> {
    core::adr36_sign_bytes(&signer, &data)
}

/// The bytes the ML-DSA-87 key signs for a sign-in message.
#[uniffi::export]
pub fn siwq_pq_sign_bytes(message: String) -> Vec<u8> {
    core::siwq_pq_sign_bytes(&message)
}

/// Sign a sign-in message. Without `pq_key` the result is classical-only.
#[uniffi::export(default(pq_key = None, hedged = false))]
pub fn sign_siwq(
    message: String,
    classical_key: ClassicalKey,
    pq_key: Option<PqKeyPair>,
    hedged: bool,
) -> Result<SiwqSignature> {
    let classical = classical_key.to_core()?;
    let pq: Option<core::PqKeyPair> = pq_key.map(Into::into);
    Ok(core::sign_siwq(&message, &classical, pq.as_ref(), hedged)?.into())
}

/// Verify a sign-in and return its fields. `now_ms` is Unix milliseconds;
/// null reads the system clock. A classical-only sign-in is refused unless
/// `require_pq` is false.
#[uniffi::export(default(
    pq_public_key = None,
    chain_id = None,
    require_pq = true,
    now_ms = None,
    clock_skew_seconds = 60
))]
#[allow(clippy::too_many_arguments)]
pub fn verify_siwq(
    message: String,
    signature: SiwqSignature,
    domain: String,
    nonce: String,
    pq_public_key: Option<Vec<u8>>,
    chain_id: Option<String>,
    require_pq: bool,
    now_ms: Option<i64>,
    clock_skew_seconds: i64,
) -> Result<SiwqFields> {
    let signature: core::SiwqSignature = signature.into();
    let args = core::VerifySiwqArgs {
        message: &message,
        signature: &signature,
        domain: &domain,
        nonce: &nonce,
        chain_id: chain_id.as_deref(),
        pq_public_key: pq_public_key.as_deref(),
        require_pq,
        now_ms,
        clock_skew_seconds,
    };
    Ok(core::verify_siwq(&args)?.into())
}

/// The JSON form of a SIWQ signature, as the other implementations exchange it.
#[uniffi::export]
pub fn siwq_signature_to_json(signature: SiwqSignature) -> Result<String> {
    let core_sig: core::SiwqSignature = signature.into();
    serde_json::to_string(&core_sig).map_err(|e| invalid_argument(&e.to_string()))
}

/// Parse the JSON form of a SIWQ signature.
#[uniffi::export]
pub fn siwq_signature_from_json(json: String) -> Result<SiwqSignature> {
    let core_sig: core::SiwqSignature =
        serde_json::from_str(&json).map_err(|e| QoreSignError::Failure {
            code: "SIWQ_MALFORMED".to_owned(),
            detail: format!("invalid SIWQ signature JSON: {e}"),
        })?;
    Ok(core_sig.into())
}

// ---------------------------------------------------------------- message signing

/// `MlDsa87Hybrid` (`ml-dsa-87-hybrid`) for both parts; `Secp256k1` for a classical-only signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum MessageSignatureType {
    MlDsa87Hybrid,
    Secp256k1,
}

/// Classical part of a [`MessageSignature`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MessageClassicalSignature {
    pub key_type: ClassicalKeyType,
    /// Base64 compressed public key.
    pub public_key: String,
    /// Base64 64-byte signature over the ADR-36 sign document of the message.
    pub signature: String,
}

/// ML-DSA-87 part of a [`MessageSignature`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MessagePqSignature {
    pub algorithm_id: u32,
    /// Base64 ML-DSA-87 signature over [`message_pq_sign_bytes`].
    pub signature: String,
}

/// A message signature; [`message_signature_to_json`] gives the JSON shape
/// shared by every implementation.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MessageSignature {
    pub signature_type: MessageSignatureType,
    pub classical: MessageClassicalSignature,
    #[uniffi(default = None)]
    pub pq: Option<MessagePqSignature>,
}

impl From<core::MessageSignature> for MessageSignature {
    fn from(s: core::MessageSignature) -> Self {
        MessageSignature {
            signature_type: match s.signature_type {
                core::MessageSignatureType::MlDsa87Hybrid => MessageSignatureType::MlDsa87Hybrid,
                core::MessageSignatureType::Secp256k1 => MessageSignatureType::Secp256k1,
            },
            classical: MessageClassicalSignature {
                key_type: s.classical.key_type.into(),
                public_key: s.classical.public_key,
                signature: s.classical.signature,
            },
            pq: s.pq.map(|p| MessagePqSignature {
                algorithm_id: p.algorithm_id,
                signature: p.signature,
            }),
        }
    }
}

impl From<MessageSignature> for core::MessageSignature {
    fn from(s: MessageSignature) -> Self {
        core::MessageSignature {
            signature_type: match s.signature_type {
                MessageSignatureType::MlDsa87Hybrid => core::MessageSignatureType::MlDsa87Hybrid,
                MessageSignatureType::Secp256k1 => core::MessageSignatureType::Secp256k1,
            },
            classical: core::MessageClassicalSignature {
                key_type: s.classical.key_type.into(),
                public_key: s.classical.public_key,
                signature: s.classical.signature,
            },
            pq: s.pq.map(|p| core::MessagePqSignature {
                algorithm_id: p.algorithm_id,
                signature: p.signature,
            }),
        }
    }
}

/// The bytes the ML-DSA-87 key signs for a message (spec/message-signing-v1.md):
/// `"qorechain-msg-v1|" + chain_id + "|"` followed by `data`.
#[uniffi::export]
pub fn message_pq_sign_bytes(chain_id: String, data: Vec<u8>) -> Result<Vec<u8>> {
    Ok(core::message_pq_sign_bytes(&chain_id, &data)?)
}

/// Sign arbitrary data with the keys of `signer` (a `qor1` account). Without
/// `pq_key` the result is classical-only.
#[uniffi::export(default(pq_key = None, hedged = false))]
pub fn sign_message(
    chain_id: String,
    signer: String,
    data: Vec<u8>,
    classical_key: ClassicalKey,
    pq_key: Option<PqKeyPair>,
    hedged: bool,
) -> Result<MessageSignature> {
    let classical = classical_key.to_core()?;
    let pq: Option<core::PqKeyPair> = pq_key.map(Into::into);
    Ok(core::sign_message(&chain_id, &signer, &data, &classical, pq.as_ref(), hedged)?.into())
}

/// Verify a message signature. `pq_public_key` is the ML-DSA-87 key
/// registered on chain for `signer`. A classical-only signature is refused
/// unless `require_pq` is false.
#[uniffi::export(default(pq_public_key = None, require_pq = true))]
pub fn verify_message(
    chain_id: String,
    signer: String,
    data: Vec<u8>,
    signature: MessageSignature,
    pq_public_key: Option<Vec<u8>>,
    require_pq: bool,
) -> Result<()> {
    let signature: core::MessageSignature = signature.into();
    let args = core::VerifyMessageArgs {
        chain_id: &chain_id,
        signer: &signer,
        data: &data,
        signature: &signature,
        pq_public_key: pq_public_key.as_deref(),
        require_pq,
    };
    Ok(core::verify_message(&args)?)
}

/// The JSON form of a message signature, as the other implementations exchange it.
#[uniffi::export]
pub fn message_signature_to_json(signature: MessageSignature) -> Result<String> {
    let core_sig: core::MessageSignature = signature.into();
    serde_json::to_string(&core_sig).map_err(|e| invalid_argument(&e.to_string()))
}

/// Parse the JSON form of a message signature; fails with `INVALID_ARGUMENT`.
#[uniffi::export]
pub fn message_signature_from_json(json: String) -> Result<MessageSignature> {
    let core_sig: core::MessageSignature = serde_json::from_str(&json)
        .map_err(|e| invalid_argument(&format!("invalid message signature JSON: {e}")))?;
    Ok(core_sig.into())
}

// ---------------------------------------------------------------- lanes

/// QoreChain's execution lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum Lane {
    Native,
    Evm,
    Svm,
}

impl From<Lane> for core::Lane {
    fn from(l: Lane) -> Self {
        match l {
            Lane::Native => core::Lane::Native,
            Lane::Evm => core::Lane::Evm,
            Lane::Svm => core::Lane::Svm,
        }
    }
}

impl From<core::Lane> for Lane {
    fn from(l: core::Lane) -> Self {
        match l {
            core::Lane::Native => Lane::Native,
            core::Lane::Evm => Lane::Evm,
            core::Lane::Svm => Lane::Svm,
        }
    }
}

/// `Hybrid`: native lane, hybrid ML-DSA-87 (FIPS 204) signature.
/// `QuantumReady`: EVM, no PQC layer on the transaction itself.
/// `Unavailable`: SVM, not open on the network yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum LaneSupport {
    Hybrid,
    QuantumReady,
    Unavailable,
}

/// What QoreSign can do on `lane` today.
#[uniffi::export]
pub fn lane_support(lane: Lane) -> LaneSupport {
    match core::Lane::from(lane).support() {
        core::LaneSupport::Hybrid => LaneSupport::Hybrid,
        core::LaneSupport::QuantumReady => LaneSupport::QuantumReady,
        core::LaneSupport::Unavailable => LaneSupport::Unavailable,
    }
}

/// Fails with `LANE_NOT_AVAILABLE` when `lane` cannot carry a hybrid signature.
#[uniffi::export]
pub fn assert_hybrid_lane(lane: Lane) -> Result<()> {
    Ok(core::assert_hybrid_lane(lane.into())?)
}

/// Input of [`decide_lane`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct LaneRequest {
    /// True when the asset moved is native QOR on QoreChain.
    pub is_qor_transfer: bool,
    /// A lane the user chose explicitly.
    #[uniffi(default = None)]
    pub explicit_lane: Option<Lane>,
    /// A lane a connected dApp requires.
    #[uniffi(default = None)]
    pub dapp_required_lane: Option<Lane>,
}

/// Why [`decide_lane`] picked a lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum LaneReason {
    DefaultNative,
    UserOverride,
    DappRequired,
}

/// Output of [`decide_lane`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct LaneDecision {
    pub lane: Lane,
    /// True when the transfer leaves the hybrid-signed native lane; show it to the user.
    pub leaves_hybrid_default: bool,
    pub reason: LaneReason,
}

/// Native QOR transfers default to the native lane, where they are hybrid-signed.
#[uniffi::export]
pub fn decide_lane(request: LaneRequest) -> LaneDecision {
    let d = core::decide_lane(&core::LaneRequest {
        is_qor_transfer: request.is_qor_transfer,
        explicit_lane: request.explicit_lane.map(Into::into),
        dapp_required_lane: request.dapp_required_lane.map(Into::into),
    });
    LaneDecision {
        lane: d.lane.into(),
        leaves_hybrid_default: d.leaves_hybrid_default,
        reason: match d.reason {
            core::LaneReason::DefaultNative => LaneReason::DefaultNative,
            core::LaneReason::UserOverride => LaneReason::UserOverride,
            core::LaneReason::DappRequired => LaneReason::DappRequired,
        },
    }
}

/// State of a broadcast transaction's PQC layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum LayerState {
    /// The committed transaction has not been read back yet.
    Pending,
    /// Hybrid-signed and the committed transaction still carries the layer.
    Protected,
    /// The committed transaction lacks the layer.
    Downgraded,
    /// A lane or network where the layer does not apply.
    Classical,
}

/// Input of [`evaluate_layer_state`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LayerStateInput {
    pub lane: Lane,
    /// False for transfers on other networks.
    pub on_qore_chain: bool,
    pub signed_with_pq_layer: bool,
    /// Extension type URLs of the committed transaction; null until it is read back.
    #[uniffi(default = None)]
    pub committed_extension_type_urls: Option<Vec<String>>,
}

#[uniffi::export]
pub fn evaluate_layer_state(input: LayerStateInput) -> LayerState {
    let urls: Option<Vec<&str>> = input
        .committed_extension_type_urls
        .as_ref()
        .map(|v| v.iter().map(String::as_str).collect());
    let state = core::evaluate_layer_state(&core::LayerStateInput {
        lane: input.lane.into(),
        on_qore_chain: input.on_qore_chain,
        signed_with_pq_layer: input.signed_with_pq_layer,
        committed_extension_type_urls: urls.as_deref(),
    });
    match state {
        core::LayerState::Pending => LayerState::Pending,
        core::LayerState::Protected => LayerState::Protected,
        core::LayerState::Downgraded => LayerState::Downgraded,
        core::LayerState::Classical => LayerState::Classical,
    }
}
