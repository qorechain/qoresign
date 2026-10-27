// SPDX-License-Identifier: Apache-2.0
//
// Sign In With QoreChain (SIWQ): EIP-4361 / SIWS-style sign-in messages,
// signed with the account's classical key (ADR-36, so any Keplr-compatible
// wallet can produce that part) and with its ML-DSA-87 key.
// Format: spec/siwq-v1.md.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::errors::{Error, Result};
use crate::keys::{
    classical_key_type_for, parse_address, ClassicalKey, ClassicalKeyType, PqKeyPair,
    ALGORITHM_ML_DSA_87,
};
use crate::sign::{classical_sign, classical_verify, pq_sign, pq_verify};

/// Domain prefix of the ML-DSA-87 part of a SIWQ signature.
pub const SIWQ_PQ_DOMAIN: &str = "qorechain-siwq-v1|";
const HEADER: &str = " wants you to sign in with your QoreChain account:";

/// The fields of a sign-in message.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiwqFields {
    /// RFC 3986 authority requesting the sign-in, e.g. `app.example.com`.
    pub domain: String,
    /// Optional scheme, e.g. `https`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    /// `qor1...` account.
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    pub uri: String,
    /// `"1"` when set; `None` renders as `"1"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Chain id, e.g. `qorechain-vladi`.
    pub chain_id: String,
    /// At least 8 alphanumeric characters, chosen by the server.
    pub nonce: String,
    /// ISO 8601 timestamp.
    pub issued_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<String>>,
}

fn check(cond: bool, msg: &str) -> Result<()> {
    if cond {
        Ok(())
    } else {
        Err(Error::SiwqMalformed(msg.to_owned()))
    }
}

/// The characters JavaScript's `\s` matches.
fn is_js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{0B}' | '\u{0C}' | '\r' | ' ' | '\u{A0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200A}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{3000}'
                | '\u{FEFF}'
    )
}

fn is_scheme_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-')
}

/// `^[a-zA-Z][a-zA-Z0-9+.-]*$`
fn is_scheme(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic()) && chars.all(is_scheme_char)
}

/// `^[a-zA-Z][a-zA-Z0-9+.-]*:\S+$`
fn is_uri(s: &str) -> bool {
    let Some(colon) = s.find(|c: char| !is_scheme_char(c)) else {
        return false;
    };
    if s.as_bytes()[colon] != b':' || !is_scheme(&s[..colon]) {
        return false;
    }
    let rest = &s[colon + 1..];
    !rest.is_empty() && !rest.chars().any(is_js_space)
}

fn is_digits(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|b| b.is_ascii_digit())
}

/// Split `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$`
/// into (date-time digits, fraction digits, signed offset hours and minutes).
fn split_iso(s: &str) -> Option<([u32; 6], &str, (i64, i64))> {
    if !s.is_ascii() || s.len() < 20 {
        return None;
    }
    let b = s.as_bytes();
    if b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let parts = [
        &s[0..4],
        &s[5..7],
        &s[8..10],
        &s[11..13],
        &s[14..16],
        &s[17..19],
    ];
    let mut n = [0u32; 6];
    for (i, p) in parts.iter().enumerate() {
        if !is_digits(p, if i == 0 { 4 } else { 2 }) {
            return None;
        }
        n[i] = p.parse().ok()?;
    }
    let mut rest = &s[19..];
    let mut fraction = "";
    if let Some(r) = rest.strip_prefix('.') {
        let end = r.find(|c: char| !c.is_ascii_digit()).unwrap_or(r.len());
        if end == 0 {
            return None;
        }
        fraction = &r[..end];
        rest = &r[end..];
    }
    let offset = if rest == "Z" {
        (0, 0)
    } else {
        let rb = rest.as_bytes();
        if rb.len() != 6 || !matches!(rb[0], b'+' | b'-') || rb[3] != b':' {
            return None;
        }
        if !is_digits(&rest[1..3], 2) || !is_digits(&rest[4..6], 2) {
            return None;
        }
        let h: i64 = rest[1..3].parse().ok()?;
        let m: i64 = rest[4..6].parse().ok()?;
        if rb[0] == b'-' {
            (-h, -m)
        } else {
            (h, m)
        }
    };
    Some((n, fraction, offset))
}

fn is_iso(s: &str) -> bool {
    split_iso(s).is_some()
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Unix milliseconds of an ISO 8601 timestamp in the SIWQ form
/// (`YYYY-MM-DDTHH:MM:SS[.fff...](Z|+HH:MM|-HH:MM)`), or `None` when it is
/// not one or names an impossible date. Digits past milliseconds are dropped.
pub fn parse_timestamp_ms(s: &str) -> Option<i64> {
    let ([year, month, day, hour, minute, second], fraction, (off_h, off_m)) = split_iso(s)?;
    if !(1..=12).contains(&month) || minute > 59 || second > 59 {
        return None;
    }
    if off_h.abs() > 23 || off_m.abs() > 59 {
        return None;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day < 1 || day > month_days[month as usize - 1] {
        return None;
    }
    let mut ms: i64 = 0;
    for (i, d) in fraction.bytes().take(3).enumerate() {
        ms += i64::from(d - b'0') * [100, 10, 1][i];
    }
    // 24:00:00 is the end of the day, as in ECMAScript's Date.parse.
    if hour > 24 || (hour == 24 && (minute != 0 || second != 0 || ms != 0)) {
        return None;
    }
    let days = days_from_civil(i64::from(year), i64::from(month), i64::from(day));
    let secs = days * 86_400 + i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second)
        - (off_h * 3600 + off_m * 60);
    Some(secs * 1000 + ms)
}

fn validate(f: &SiwqFields) -> Result<()> {
    check(
        !f.domain.is_empty() && !f.domain.chars().any(|c| c == '/' || is_js_space(c)),
        "domain must be a host (and optional port) without spaces or slashes",
    )?;
    check(f.scheme.as_deref().is_none_or(is_scheme), "invalid scheme")?;
    parse_address(&f.address)?;
    check(
        f.address.starts_with("qor1"),
        "address must be the bech32 qor1 form",
    )?;
    check(
        f.statement.as_deref().is_none_or(|s| !s.contains('\n')),
        "statement must be a single line",
    )?;
    check(is_uri(&f.uri), "uri must be an absolute URI")?;
    check(
        f.version.as_deref().unwrap_or("1") == "1",
        "version must be 1",
    )?;
    check(
        !f.chain_id.is_empty()
            && f.chain_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
        "invalid chain id",
    )?;
    check(
        f.nonce.len() >= 8 && f.nonce.bytes().all(|b| b.is_ascii_alphanumeric()),
        "nonce must be at least 8 alphanumeric characters",
    )?;
    check(is_iso(&f.issued_at), "issuedAt must be ISO 8601")?;
    check(
        f.expiration_time.as_deref().is_none_or(is_iso),
        "expirationTime must be ISO 8601",
    )?;
    check(
        f.not_before.as_deref().is_none_or(is_iso),
        "notBefore must be ISO 8601",
    )?;
    check(
        f.request_id.as_deref().is_none_or(|s| !s.contains('\n')),
        "requestId must be a single line",
    )?;
    for r in f.resources.iter().flatten() {
        check(is_uri(r), "resources must be URIs")?;
    }
    Ok(())
}

/// Render the sign-in message text.
pub fn create_siwq_message(fields: &SiwqFields) -> Result<String> {
    validate(fields)?;
    let mut lines: Vec<String> = Vec::new();
    let scheme = fields
        .scheme
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| format!("{s}://"))
        .unwrap_or_default();
    lines.push(format!("{scheme}{}{HEADER}", fields.domain));
    lines.push(fields.address.clone());
    lines.push(String::new());
    if let Some(s) = &fields.statement {
        lines.push(s.clone());
    }
    lines.push(String::new());
    lines.push(format!("URI: {}", fields.uri));
    lines.push(format!(
        "Version: {}",
        fields.version.as_deref().unwrap_or("1")
    ));
    lines.push(format!("Chain ID: {}", fields.chain_id));
    lines.push(format!("Nonce: {}", fields.nonce));
    lines.push(format!("Issued At: {}", fields.issued_at));
    if let Some(v) = &fields.expiration_time {
        lines.push(format!("Expiration Time: {v}"));
    }
    if let Some(v) = &fields.not_before {
        lines.push(format!("Not Before: {v}"));
    }
    if let Some(v) = &fields.request_id {
        lines.push(format!("Request ID: {v}"));
    }
    if let Some(resources) = fields.resources.as_ref().filter(|r| !r.is_empty()) {
        lines.push("Resources:".to_owned());
        for r in resources {
            lines.push(format!("- {r}"));
        }
    }
    Ok(lines.join("\n"))
}

/// Parse a sign-in message. The result re-renders to exactly the same text.
pub fn parse_siwq_message(text: &str) -> Result<SiwqFields> {
    let lines: Vec<&str> = text.split('\n').collect();
    let mut i = 0usize;
    let header = lines[i];
    i += 1;
    let Some(mut origin) = header.strip_suffix(HEADER) else {
        return Err(Error::SiwqMalformed("missing SIWQ header line".into()));
    };
    let mut scheme = None;
    if let Some(sep) = origin.find("://") {
        scheme = Some(origin[..sep].to_owned());
        origin = &origin[sep + 3..];
    }
    let address = lines.get(i).copied().unwrap_or("").to_owned();
    i += 1;
    check(
        lines.get(i) == Some(&""),
        "expected an empty line after the address",
    )?;
    i += 1;
    let mut statement = None;
    if lines.get(i) != Some(&"") {
        statement = lines.get(i).map(|s| (*s).to_owned());
        i += 1;
    }
    check(
        lines.get(i) == Some(&""),
        "expected an empty line before the fields",
    )?;
    i += 1;
    let mut take = |label: &str, optional: bool| -> Result<Option<String>> {
        if let Some(value) = lines.get(i).and_then(|l| {
            l.strip_prefix(label)
                .and_then(|rest| rest.strip_prefix(": "))
        }) {
            i += 1;
            return Ok(Some(value.to_owned()));
        }
        check(optional, &format!("missing \"{label}\""))?;
        Ok(None)
    };
    let uri = take("URI", false)?.unwrap_or_default();
    let version = take("Version", false)?.unwrap_or_default();
    let chain_id = take("Chain ID", false)?.unwrap_or_default();
    let nonce = take("Nonce", false)?.unwrap_or_default();
    let issued_at = take("Issued At", false)?.unwrap_or_default();
    let expiration_time = take("Expiration Time", true)?;
    let not_before = take("Not Before", true)?;
    let request_id = take("Request ID", true)?;
    let mut resources = None;
    if lines.get(i) == Some(&"Resources:") {
        i += 1;
        let mut list = Vec::new();
        while let Some(r) = lines.get(i).and_then(|l| l.strip_prefix("- ")) {
            list.push(r.to_owned());
            i += 1;
        }
        resources = Some(list);
    }
    check(i == lines.len(), "unexpected trailing content")?;
    check(version == "1", "version must be 1")?;
    let fields = SiwqFields {
        domain: origin.to_owned(),
        scheme,
        address,
        statement,
        uri,
        version: Some("1".to_owned()),
        chain_id,
        nonce,
        issued_at,
        expiration_time,
        not_before,
        request_id,
        resources,
    };
    validate(&fields)?;
    check(
        create_siwq_message(&fields)? == text,
        "message is not in canonical form",
    )?;
    Ok(fields)
}

/// ADR-36 sign document for arbitrary data, as Keplr-compatible wallets build
/// it for `signArbitrary`, serialized with sorted keys and no whitespace.
pub fn adr36_sign_bytes(signer: &str, data: &[u8]) -> Vec<u8> {
    format!(
        "{{\"account_number\":\"0\",\"chain_id\":\"\",\"fee\":{{\"amount\":[],\"gas\":\"0\"}},\"memo\":\"\",\
         \"msgs\":[{{\"type\":\"sign/MsgSignData\",\"value\":{{\"data\":\"{}\",\"signer\":\"{signer}\"}}}}],\
         \"sequence\":\"0\"}}",
        B64.encode(data)
    )
    .into_bytes()
}

/// The bytes the ML-DSA-87 key signs for a sign-in message.
pub fn siwq_pq_sign_bytes(message: &str) -> Vec<u8> {
    format!("{SIWQ_PQ_DOMAIN}{message}").into_bytes()
}

/// `ml-dsa-87-hybrid` for both parts; `secp256k1` for a classical-only sign-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SiwqSignatureType {
    #[serde(rename = "ml-dsa-87-hybrid")]
    MlDsa87Hybrid,
    #[serde(rename = "secp256k1")]
    Secp256k1,
}

/// Classical part of a [`SiwqSignature`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiwqClassicalSignature {
    pub key_type: ClassicalKeyType,
    /// Base64 compressed public key.
    pub public_key: String,
    /// Base64 64-byte signature over the ADR-36 sign document.
    pub signature: String,
}

/// ML-DSA-87 part of a [`SiwqSignature`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiwqPqSignature {
    pub algorithm_id: u32,
    /// Base64 ML-DSA-87 signature over `"qorechain-siwq-v1|" + message`.
    pub signature: String,
}

/// A SIWQ signature, in the JSON shape shared by every implementation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiwqSignature {
    pub signature_type: SiwqSignatureType,
    pub classical: SiwqClassicalSignature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq: Option<SiwqPqSignature>,
}

/// Sign a sign-in message with the account's keys. Without `pq_key` the
/// result is a classical-only sign-in.
pub fn sign_siwq(
    message: &str,
    classical_key: &ClassicalKey,
    pq_key: Option<&PqKeyPair>,
    hedged: bool,
) -> Result<SiwqSignature> {
    let fields = parse_siwq_message(message)?;
    if classical_key_type_for(&classical_key.public_key, &fields.address)?.is_none() {
        return Err(Error::AddressMismatch(format!(
            "the classical key does not control {}",
            fields.address
        )));
    }
    let classical = classical_sign(
        classical_key.key_type,
        &classical_key.private_key,
        &adr36_sign_bytes(&fields.address, message.as_bytes()),
    )?;
    let pq = match pq_key {
        Some(k) => Some(SiwqPqSignature {
            algorithm_id: ALGORITHM_ML_DSA_87,
            signature: B64.encode(pq_sign(
                &k.secret_key,
                &siwq_pq_sign_bytes(message),
                hedged,
            )?),
        }),
        None => None,
    };
    Ok(SiwqSignature {
        signature_type: if pq.is_some() {
            SiwqSignatureType::MlDsa87Hybrid
        } else {
            SiwqSignatureType::Secp256k1
        },
        classical: SiwqClassicalSignature {
            key_type: classical_key.key_type,
            public_key: B64.encode(classical_key.public_key),
            signature: B64.encode(classical),
        },
        pq,
    })
}

/// Input of [`verify_siwq`].
#[derive(Clone, Copy, Debug)]
pub struct VerifySiwqArgs<'a> {
    pub message: &'a str,
    pub signature: &'a SiwqSignature,
    /// The domain the server expects (the request's host).
    pub domain: &'a str,
    /// The nonce the server issued for this sign-in.
    pub nonce: &'a str,
    /// Expected chain id; checked when set.
    pub chain_id: Option<&'a str>,
    /// The account's registered ML-DSA-87 public key. Required unless `require_pq` is false.
    pub pq_public_key: Option<&'a [u8]>,
    /// Default true: a classical-only sign-in is refused.
    pub require_pq: bool,
    /// Current time in Unix milliseconds; `None` reads the system clock.
    pub now_ms: Option<i64>,
    /// Allowed clock skew for `issuedAt` and `notBefore`, in seconds. Default 60.
    pub clock_skew_seconds: i64,
}

impl<'a> VerifySiwqArgs<'a> {
    /// Defaults: PQ part required, no chain check, system clock, 60 s skew.
    pub fn new(
        message: &'a str,
        signature: &'a SiwqSignature,
        domain: &'a str,
        nonce: &'a str,
        pq_public_key: Option<&'a [u8]>,
    ) -> Self {
        Self {
            message,
            signature,
            domain,
            nonce,
            chain_id: None,
            pq_public_key,
            require_pq: true,
            now_ms: None,
            clock_skew_seconds: 60,
        }
    }
}

#[cfg(feature = "std")]
fn system_now_ms() -> Result<i64> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::InvalidArgument("system clock is before 1970".into()))?;
    Ok(i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(not(feature = "std"))]
fn system_now_ms() -> Result<i64> {
    Err(Error::InvalidArgument("now_ms is required".into()))
}

fn decode_b64(s: &str) -> Option<Vec<u8>> {
    B64.decode(s).ok()
}

/// Verify a sign-in. Returns the parsed fields.
///
/// A timestamp that matches the ISO form but names an impossible date fails
/// closed: as expired (`expirationTime`) or not yet valid (`notBefore`, `issuedAt`).
pub fn verify_siwq(args: &VerifySiwqArgs<'_>) -> Result<SiwqFields> {
    let fields = parse_siwq_message(args.message)?;
    if fields.domain != args.domain {
        return Err(Error::SiwqDomainMismatch(format!(
            "message is for {}, expected {}",
            fields.domain, args.domain
        )));
    }
    if fields.nonce != args.nonce {
        return Err(Error::SiwqNonceMismatch("nonce does not match".into()));
    }
    if let Some(chain_id) = args.chain_id {
        if fields.chain_id != chain_id {
            return Err(Error::SiwqChainMismatch(format!(
                "message is for {}, expected {chain_id}",
                fields.chain_id
            )));
        }
    }
    let now = match args.now_ms {
        Some(ms) => ms,
        None => system_now_ms()?,
    };
    let skew = args.clock_skew_seconds.saturating_mul(1000);
    let latest = now.saturating_add(skew);
    if let Some(exp) = &fields.expiration_time {
        if parse_timestamp_ms(exp).is_none_or(|t| t <= now) {
            return Err(Error::SiwqExpired("the sign-in message has expired".into()));
        }
    }
    if let Some(nbf) = &fields.not_before {
        if parse_timestamp_ms(nbf).is_none_or(|t| t > latest) {
            return Err(Error::SiwqNotYetValid(
                "the sign-in message is not valid yet".into(),
            ));
        }
    }
    if parse_timestamp_ms(&fields.issued_at).is_none_or(|t| t > latest) {
        return Err(Error::SiwqNotYetValid("issuedAt is in the future".into()));
    }

    let sig = args.signature;
    let (Some(classical_pub), Some(classical_sig)) = (
        decode_b64(&sig.classical.public_key),
        decode_b64(&sig.classical.signature),
    ) else {
        return Err(Error::ClassicalSignatureInvalid(
            "classical signature fields are not base64".into(),
        ));
    };
    let owner = classical_key_type_for(&classical_pub, &fields.address).unwrap_or(None);
    let Some(owner) = owner.filter(|o| *o == sig.classical.key_type) else {
        return Err(Error::AddressMismatch(format!(
            "the classical key does not control {}",
            fields.address
        )));
    };
    let adr36 = adr36_sign_bytes(&fields.address, args.message.as_bytes());
    if !classical_verify(owner, &classical_pub, &adr36, &classical_sig) {
        return Err(Error::ClassicalSignatureInvalid(
            "the classical signature does not verify".into(),
        ));
    }

    let Some(pq) = &sig.pq else {
        if args.require_pq {
            return Err(Error::PqLayerMissing(
                "the sign-in carries no ML-DSA-87 signature".into(),
            ));
        }
        return Ok(fields);
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
    if !pq_verify(pq_public_key, &siwq_pq_sign_bytes(args.message), &pq_sig) {
        return Err(Error::PqSignatureInvalid(
            "the ML-DSA-87 signature does not verify".into(),
        ));
    }
    Ok(fields)
}
