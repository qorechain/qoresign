// SPDX-License-Identifier: Apache-2.0

package qoresign_test

import (
	"testing"

	qoresign "github.com/qorechain/qoresign/go"
)

const (
	testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	testChainID  = "qorechain-diana"
)

var (
	testClassical = must(qoresign.DeriveClassicalKey(testMnemonic, qoresign.DeriveClassicalOptions{}))
	testAccount   = must(qoresign.AddressFromPublicKey(testClassical.PublicKey, qoresign.Secp256k1))
	testPq        = must(qoresign.DeriveCanonicalPqKey(testMnemonic, testAccount.Bech32))
)

// msgSend encodes cosmos.bank.v1beta1.MsgSend by hand.
func msgSend(from, to, amount string) []byte {
	coin := qoresign.Concat(qoresign.StringField(1, "uqor"), qoresign.StringField(2, amount))
	return qoresign.Concat(qoresign.StringField(1, from), qoresign.StringField(2, to), qoresign.LenField(3, coin))
}

// sendBody encodes a TxBody with one self-send and a memo.
func sendBody(memo string) []byte {
	msg := qoresign.Any{TypeURL: "/cosmos.bank.v1beta1.MsgSend", Value: msgSend(testAccount.Bech32, testAccount.Bech32, "1")}
	return qoresign.Concat(qoresign.LenField(1, qoresign.EncodeAny(msg)), qoresign.StringField(2, memo))
}

// authInfo encodes AuthInfo for one SIGN_MODE_DIRECT secp256k1 signer.
func authInfo(pubkey []byte, sequence, gasLimit uint64, feeAmount string) []byte {
	pk := qoresign.EncodeAny(qoresign.Any{TypeURL: "/cosmos.crypto.secp256k1.PubKey", Value: qoresign.LenField(1, pubkey)})
	modeInfo := qoresign.LenField(1, qoresign.VarintField(1, 1))
	signerInfo := qoresign.Concat(qoresign.LenField(1, pk), qoresign.LenField(2, modeInfo), qoresign.VarintField(3, sequence))
	coin := qoresign.Concat(qoresign.StringField(1, "uqor"), qoresign.StringField(2, feeAmount))
	fee := qoresign.Concat(qoresign.LenField(1, coin), qoresign.VarintField(2, gasLimit))
	return qoresign.Concat(qoresign.LenField(1, signerInfo), qoresign.LenField(2, fee))
}

func testAuth(sequence uint64) []byte {
	return authInfo(testClassical.PublicKey, sequence, 500_000, "50000")
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got no error", code)
	}
	if !qoresign.IsCode(err, code) {
		t.Fatalf("expected %s, got %v", code, err)
	}
}
