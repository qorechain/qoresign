// SPDX-License-Identifier: Apache-2.0

package qoresign

import (
	"errors"
	"fmt"
)

// Stable error codes. New codes may be added; existing ones never change meaning.
const (
	CodeInvalidArgument           = "INVALID_ARGUMENT"
	CodeInvalidMnemonic           = "INVALID_MNEMONIC"
	CodeInvalidAddress            = "INVALID_ADDRESS"
	CodeAddressMismatch           = "ADDRESS_MISMATCH"
	CodeHDNonHardened             = "HD_NON_HARDENED"
	CodeHDInvalidPath             = "HD_INVALID_PATH"
	CodeBadKeyLength              = "BAD_KEY_LENGTH"
	CodeMalformedProtobuf         = "MALFORMED_PROTOBUF"
	CodeSignBytesVersionUnknown   = "SIGN_BYTES_VERSION_UNKNOWN"
	CodePqLayerMissing            = "PQ_LAYER_MISSING"
	CodePqLayerDuplicated         = "PQ_LAYER_DUPLICATED"
	CodePqSignatureInvalid        = "PQ_SIGNATURE_INVALID"
	CodeClassicalSignatureInvalid = "CLASSICAL_SIGNATURE_INVALID"
	CodeUnsupportedAlgorithm      = "UNSUPPORTED_ALGORITHM"
	CodeSiwqMalformed             = "SIWQ_MALFORMED"
	CodeSiwqExpired               = "SIWQ_EXPIRED"
	CodeSiwqNotYetValid           = "SIWQ_NOT_YET_VALID"
	CodeSiwqDomainMismatch        = "SIWQ_DOMAIN_MISMATCH"
	CodeSiwqNonceMismatch         = "SIWQ_NONCE_MISMATCH"
	CodeSiwqChainMismatch         = "SIWQ_CHAIN_MISMATCH"
	CodeKeyNotRegistered          = "KEY_NOT_REGISTERED"
	CodeKeyMismatch               = "KEY_MISMATCH"
	CodeLaneNotAvailable          = "LANE_NOT_AVAILABLE"
	CodeNetworkUnavailable        = "NETWORK_UNAVAILABLE"
	CodeSimulationFailed          = "SIMULATION_FAILED"
)

// Error is every error QoreSign returns on purpose.
type Error struct {
	Code    string
	Message string
	Details map[string]any
}

func (e *Error) Error() string {
	return fmt.Sprintf("qoresign: %s: %s", e.Code, e.Message)
}

// NewError builds an *Error.
func NewError(code, message string, details map[string]any) *Error {
	return &Error{Code: code, Message: message, Details: details}
}

func errorf(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// IsCode reports whether err is (or wraps) an *Error with the given code.
func IsCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}
