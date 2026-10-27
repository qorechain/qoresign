// SPDX-License-Identifier: Apache-2.0
//
// Minimal protobuf wire handling for the handful of Cosmos SDK messages
// QoreSign touches (TxRaw, TxBody, Any, SignDoc, PQCHybridSignature).
//
// The signer never re-encodes a message it did not build: TxBody bytes are
// edited at the top level only (one field appended or removed), so every other
// field keeps the exact bytes the caller supplied.

package qoresign

import (
	"strconv"
	"unicode/utf8"
)

// Protobuf wire types.
const (
	WireVarint  = 0
	WireFixed64 = 1
	WireLen     = 2
	WireFixed32 = 5
)

// RawField is one top-level field of an encoded message, with its raw bytes.
type RawField struct {
	Field    uint64
	WireType int
	// Raw is the complete encoding of this field (tag + payload).
	Raw []byte
	// Bytes is the payload of a length-delimited field (nil for other wire types).
	Bytes []byte
	// Varint is the value of a varint field.
	Varint uint64
}

func malformed(detail string) *Error {
	return errorf(CodeMalformedProtobuf, "malformed protobuf: %s", detail)
}

func readVarint(buf []byte, pos int) (uint64, int, error) {
	var result uint64
	for i := 0; i < 10; i++ {
		if pos >= len(buf) {
			return 0, 0, malformed("truncated varint")
		}
		b := buf[pos]
		pos++
		if i == 9 && b > 1 {
			return 0, 0, malformed("varint overflows 64 bits")
		}
		result |= uint64(b&0x7f) << (7 * uint(i))
		if b&0x80 == 0 {
			return result, pos, nil
		}
	}
	return 0, 0, malformed("varint longer than 10 bytes")
}

// ReadFields splits an encoded message into its top-level fields, in order.
func ReadFields(buf []byte) ([]RawField, error) {
	var out []RawField
	pos := 0
	for pos < len(buf) {
		start := pos
		tag, next, err := readVarint(buf, pos)
		if err != nil {
			return nil, err
		}
		pos = next
		f := RawField{Field: tag >> 3, WireType: int(tag & 7)}
		if f.Field == 0 {
			return nil, malformed("field number 0")
		}
		switch f.WireType {
		case WireVarint:
			v, next, err := readVarint(buf, pos)
			if err != nil {
				return nil, err
			}
			f.Varint = v
			pos = next
		case WireFixed64:
			pos += 8
		case WireFixed32:
			pos += 4
		case WireLen:
			n, next, err := readVarint(buf, pos)
			if err != nil {
				return nil, err
			}
			if n > uint64(len(buf)-next) {
				return nil, malformed("length-delimited field runs past the end")
			}
			end := next + int(n)
			f.Bytes = buf[next:end:end]
			pos = end
		default:
			return nil, malformed("unsupported wire type " + strconv.Itoa(f.WireType))
		}
		if pos > len(buf) {
			return nil, malformed("field runs past the end")
		}
		f.Raw = buf[start:pos:pos]
		out = append(out, f)
	}
	return out, nil
}

// AppendVarint appends the varint encoding of v.
func AppendVarint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

func appendTag(dst []byte, field uint64, wireType int) []byte {
	return AppendVarint(dst, field<<3|uint64(wireType))
}

// Concat joins byte slices into a new slice.
func Concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// LenField encodes a length-delimited field. Empty payloads are omitted (proto3).
func LenField(field uint64, payload []byte) []byte {
	if len(payload) == 0 {
		return nil
	}
	return forceLenField(field, payload)
}

// forceLenField encodes a length-delimited field even when empty (repeated bytes).
func forceLenField(field uint64, payload []byte) []byte {
	out := appendTag(nil, field, WireLen)
	out = AppendVarint(out, uint64(len(payload)))
	return append(out, payload...)
}

// VarintField encodes a varint field. Zero is omitted (proto3).
func VarintField(field uint64, value uint64) []byte {
	if value == 0 {
		return nil
	}
	return AppendVarint(appendTag(nil, field, WireVarint), value)
}

// StringField encodes a string field. Empty strings are omitted (proto3).
func StringField(field uint64, value string) []byte {
	return LenField(field, []byte(value))
}

// Any is google.protobuf.Any.
type Any struct {
	TypeURL string
	Value   []byte
}

// EncodeAny encodes an Any.
func EncodeAny(a Any) []byte {
	return Concat(StringField(1, a.TypeURL), LenField(2, a.Value))
}

// DecodeAny decodes an Any.
func DecodeAny(buf []byte) (Any, error) {
	fields, err := ReadFields(buf)
	if err != nil {
		return Any{}, err
	}
	var out Any
	for _, f := range fields {
		if f.WireType != WireLen {
			continue
		}
		switch f.Field {
		case 1:
			s, err := decodeString(f.Bytes)
			if err != nil {
				return Any{}, err
			}
			out.TypeURL = s
		case 2:
			out.Value = f.Bytes
		}
	}
	return out, nil
}

func decodeString(b []byte) (string, error) {
	if !utf8.Valid(b) {
		return "", malformed("invalid UTF-8 in a string field")
	}
	return string(b), nil
}

// TxRaw is cosmos.tx.v1beta1.TxRaw.
type TxRaw struct {
	BodyBytes     []byte
	AuthInfoBytes []byte
	Signatures    [][]byte
}

// EncodeTxRaw encodes a TxRaw. Empty signatures are kept (repeated bytes).
func EncodeTxRaw(tx TxRaw) []byte {
	out := Concat(LenField(1, tx.BodyBytes), LenField(2, tx.AuthInfoBytes))
	for _, s := range tx.Signatures {
		out = append(out, forceLenField(3, s)...)
	}
	return out
}

// DecodeTxRaw decodes a TxRaw.
func DecodeTxRaw(buf []byte) (TxRaw, error) {
	fields, err := ReadFields(buf)
	if err != nil {
		return TxRaw{}, err
	}
	out := TxRaw{BodyBytes: []byte{}, AuthInfoBytes: []byte{}}
	for _, f := range fields {
		if f.WireType != WireLen {
			continue
		}
		switch f.Field {
		case 1:
			out.BodyBytes = f.Bytes
		case 2:
			out.AuthInfoBytes = f.Bytes
		case 3:
			out.Signatures = append(out.Signatures, f.Bytes)
		}
	}
	return out, nil
}

// EncodeSignDoc encodes cosmos.tx.v1beta1.SignDoc (SIGN_MODE_DIRECT).
func EncodeSignDoc(bodyBytes, authInfoBytes []byte, chainID string, accountNumber uint64) []byte {
	return Concat(
		LenField(1, bodyBytes),
		LenField(2, authInfoBytes),
		StringField(3, chainID),
		VarintField(4, accountNumber),
	)
}

// TxBody field numbers.
const (
	TxBodyExtensionOptions            = 1023
	TxBodyNonCriticalExtensionOptions = 2047
)

// BodyExtensions returns the extension options carried by a TxBody, in order.
func BodyExtensions(bodyBytes []byte) ([]Any, error) {
	fields, err := ReadFields(bodyBytes)
	if err != nil {
		return nil, err
	}
	var out []Any
	for _, f := range fields {
		if f.Field == TxBodyExtensionOptions && f.WireType == WireLen {
			a, err := DecodeAny(f.Bytes)
			if err != nil {
				return nil, err
			}
			out = append(out, a)
		}
	}
	return out, nil
}

// StripExtension removes every extension option whose type URL is typeURL.
func StripExtension(bodyBytes []byte, typeURL string) ([]byte, error) {
	fields, err := ReadFields(bodyBytes)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(bodyBytes))
	for _, f := range fields {
		if f.Field == TxBodyExtensionOptions && f.WireType == WireLen {
			a, err := DecodeAny(f.Bytes)
			if err != nil {
				return nil, err
			}
			if a.TypeURL == typeURL {
				continue
			}
		}
		out = append(out, f.Raw...)
	}
	return out, nil
}

// AppendExtension adds an extension option in canonical field order: after
// the existing extension options and before any non-critical extension options.
func AppendExtension(bodyBytes []byte, a Any) ([]byte, error) {
	fields, err := ReadFields(bodyBytes)
	if err != nil {
		return nil, err
	}
	encoded := LenField(TxBodyExtensionOptions, EncodeAny(a))
	out := make([]byte, 0, len(bodyBytes)+len(encoded))
	inserted := false
	for _, f := range fields {
		if !inserted && f.Field > TxBodyExtensionOptions {
			out = append(out, encoded...)
			inserted = true
		}
		out = append(out, f.Raw...)
	}
	if !inserted {
		out = append(out, encoded...)
	}
	return out, nil
}
