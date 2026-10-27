// SPDX-License-Identifier: Apache-2.0

package qoresign

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// ToHex encodes bytes as lowercase hex.
func ToHex(b []byte) string { return hex.EncodeToString(b) }

// FromHex decodes hex, with or without a 0x prefix.
func FromHex(s string) ([]byte, error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, errorf(CodeInvalidArgument, "invalid hex string")
	}
	return b, nil
}

// ToBase64 encodes bytes as standard padded base64.
func ToBase64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// FromBase64 decodes standard padded base64, strictly.
func FromBase64(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, errorf(CodeInvalidArgument, "invalid base64 string")
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, errorf(CodeInvalidArgument, "invalid base64 string")
	}
	return b, nil
}

func equalBytes(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}

func requireLength(b []byte, n int, what string) error {
	if len(b) != n {
		return errorf(CodeBadKeyLength, "%s must be %d bytes, got %d", what, n, len(b))
	}
	return nil
}

func clone(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}
