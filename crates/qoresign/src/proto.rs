// SPDX-License-Identifier: Apache-2.0
//
// Minimal protobuf wire handling for the handful of Cosmos SDK messages
// QoreSign touches (TxRaw, TxBody, Any, SignDoc, PQCHybridSignature).
//
// The signer never re-encodes a message it did not build: TxBody bytes are
// edited at the top level only (one field appended or removed), so every other
// field keeps the exact bytes the caller supplied.

use crate::errors::{Error, Result};

pub const WIRE_VARINT: u8 = 0;
pub const WIRE_FIXED64: u8 = 1;
pub const WIRE_LEN: u8 = 2;
pub const WIRE_FIXED32: u8 = 5;

/// One top-level field of an encoded message, with its raw bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawField<'a> {
    pub field: u64,
    pub wire_type: u8,
    /// The complete encoding of this field (tag + payload).
    pub raw: &'a [u8],
    /// Payload for length-delimited fields.
    pub bytes: Option<&'a [u8]>,
    /// Value for varint fields.
    pub varint: Option<u64>,
}

fn malformed(detail: &str) -> Error {
    Error::MalformedProtobuf(format!("malformed protobuf: {detail}"))
}

fn read_varint(buf: &[u8], mut pos: usize) -> Result<(u64, usize)> {
    let mut result: u64 = 0;
    for i in 0..10 {
        let b = *buf.get(pos).ok_or_else(|| malformed("truncated varint"))?;
        pos += 1;
        if i == 9 && b > 1 {
            return Err(malformed("varint overflows 64 bits"));
        }
        result |= u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            return Ok((result, pos));
        }
    }
    Err(malformed("varint longer than 10 bytes"))
}

/// Split an encoded message into its top-level fields, in order.
pub fn read_fields(buf: &[u8]) -> Result<Vec<RawField<'_>>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < buf.len() {
        let start = pos;
        let (tag, after_tag) = read_varint(buf, pos)?;
        pos = after_tag;
        let field = tag >> 3;
        let wire_type = (tag & 7) as u8;
        if field == 0 {
            return Err(malformed("field number 0"));
        }
        let mut bytes = None;
        let mut varint = None;
        match wire_type {
            WIRE_VARINT => {
                let (v, next) = read_varint(buf, pos)?;
                varint = Some(v);
                pos = next;
            }
            WIRE_FIXED64 => pos += 8,
            WIRE_FIXED32 => pos += 4,
            WIRE_LEN => {
                let (len, next) = read_varint(buf, pos)?;
                let end = usize::try_from(len)
                    .ok()
                    .and_then(|l| next.checked_add(l))
                    .filter(|&e| e <= buf.len())
                    .ok_or_else(|| malformed("length-delimited field runs past the end"))?;
                bytes = Some(&buf[next..end]);
                pos = end;
            }
            other => return Err(malformed(&format!("unsupported wire type {other}"))),
        }
        if pos > buf.len() {
            return Err(malformed("field runs past the end"));
        }
        out.push(RawField {
            field,
            wire_type,
            raw: &buf[start..pos],
            bytes,
            varint,
        });
    }
    Ok(out)
}

/// Append the varint encoding of `value` to `out`.
pub fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut b = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            b |= 0x80;
        }
        out.push(b);
        if value == 0 {
            break;
        }
    }
}

fn tag(field: u64, wire_type: u8, out: &mut Vec<u8>) {
    encode_varint((field << 3) | u64::from(wire_type), out);
}

/// Append a length-delimited field, even when the payload is empty.
fn len_field_always(field: u64, payload: &[u8], out: &mut Vec<u8>) {
    tag(field, WIRE_LEN, out);
    encode_varint(payload.len() as u64, out);
    out.extend_from_slice(payload);
}

/// Append a length-delimited field. Empty payloads are omitted (proto3).
pub fn len_field(field: u64, payload: &[u8], out: &mut Vec<u8>) {
    if !payload.is_empty() {
        len_field_always(field, payload, out);
    }
}

/// Append a varint field. Zero is omitted (proto3).
pub fn varint_field(field: u64, value: u64, out: &mut Vec<u8>) {
    if value != 0 {
        tag(field, WIRE_VARINT, out);
        encode_varint(value, out);
    }
}

/// Append a string field. Empty strings are omitted (proto3).
pub fn string_field(field: u64, value: &str, out: &mut Vec<u8>) {
    len_field(field, value.as_bytes(), out);
}

/// `google.protobuf.Any`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AnyMessage {
    pub type_url: String,
    pub value: Vec<u8>,
}

pub fn encode_any(any: &AnyMessage) -> Vec<u8> {
    let mut out = Vec::with_capacity(any.type_url.len() + any.value.len() + 8);
    string_field(1, &any.type_url, &mut out);
    len_field(2, &any.value, &mut out);
    out
}

pub fn decode_any(buf: &[u8]) -> Result<AnyMessage> {
    let mut out = AnyMessage::default();
    for f in read_fields(buf)? {
        match (f.field, f.bytes) {
            (1, Some(b)) => out.type_url = decode_string(b)?,
            (2, Some(b)) => out.value = b.to_vec(),
            _ => {}
        }
    }
    Ok(out)
}

pub fn decode_string(bytes: &[u8]) -> Result<String> {
    core::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| malformed("invalid UTF-8 in a string field"))
}

/// `cosmos.tx.v1beta1.TxRaw`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TxRawParts {
    pub body_bytes: Vec<u8>,
    pub auth_info_bytes: Vec<u8>,
    pub signatures: Vec<Vec<u8>>,
}

pub fn encode_tx_raw(tx: &TxRawParts) -> Vec<u8> {
    let mut out = Vec::new();
    len_field(1, &tx.body_bytes, &mut out);
    len_field(2, &tx.auth_info_bytes, &mut out);
    // repeated bytes keeps empty entries, so encode them explicitly
    for s in &tx.signatures {
        len_field_always(3, s, &mut out);
    }
    out
}

pub fn decode_tx_raw(buf: &[u8]) -> Result<TxRawParts> {
    let mut out = TxRawParts::default();
    for f in read_fields(buf)? {
        let Some(b) = f.bytes else { continue };
        match f.field {
            1 => out.body_bytes = b.to_vec(),
            2 => out.auth_info_bytes = b.to_vec(),
            3 => out.signatures.push(b.to_vec()),
            _ => {}
        }
    }
    Ok(out)
}

/// `cosmos.tx.v1beta1.SignDoc` (SIGN_MODE_DIRECT).
pub fn encode_sign_doc(
    body_bytes: &[u8],
    auth_info_bytes: &[u8],
    chain_id: &str,
    account_number: u64,
) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(body_bytes.len() + auth_info_bytes.len() + chain_id.len() + 24);
    len_field(1, body_bytes, &mut out);
    len_field(2, auth_info_bytes, &mut out);
    string_field(3, chain_id, &mut out);
    varint_field(4, account_number, &mut out);
    out
}

/// TxBody field numbers.
pub const TXBODY_EXTENSION_OPTIONS: u64 = 1023;
pub const TXBODY_NON_CRITICAL_EXTENSION_OPTIONS: u64 = 2047;

fn is_extension(f: &RawField<'_>) -> bool {
    f.field == TXBODY_EXTENSION_OPTIONS && f.wire_type == WIRE_LEN
}

/// Extension options (`Any`) carried by a TxBody, in order.
pub fn body_extensions(body_bytes: &[u8]) -> Result<Vec<AnyMessage>> {
    read_fields(body_bytes)?
        .iter()
        .filter(|f| is_extension(f))
        .map(|f| decode_any(f.bytes.unwrap_or_default()))
        .collect()
}

/// Remove every extension option whose type URL is `type_url`.
pub fn strip_extension(body_bytes: &[u8], type_url: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(body_bytes.len());
    for f in read_fields(body_bytes)? {
        if is_extension(&f) && decode_any(f.bytes.unwrap_or_default())?.type_url == type_url {
            continue;
        }
        out.extend_from_slice(f.raw);
    }
    Ok(out)
}

/// Add an extension option in canonical field order: after the existing
/// extension options and before any non-critical extension options.
pub fn append_extension(body_bytes: &[u8], any: &AnyMessage) -> Result<Vec<u8>> {
    let fields = read_fields(body_bytes)?;
    let mut encoded = Vec::new();
    len_field(TXBODY_EXTENSION_OPTIONS, &encode_any(any), &mut encoded);
    let at = fields
        .iter()
        .position(|f| f.field > TXBODY_EXTENSION_OPTIONS)
        .unwrap_or(fields.len());
    let mut out = Vec::with_capacity(body_bytes.len() + encoded.len());
    for f in &fields[..at] {
        out.extend_from_slice(f.raw);
    }
    out.extend_from_slice(&encoded);
    for f in &fields[at..] {
        out.extend_from_slice(f.raw);
    }
    Ok(out)
}
