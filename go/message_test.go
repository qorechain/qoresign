// SPDX-License-Identifier: Apache-2.0

package qoresign_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	qoresign "github.com/qorechain/qoresign/go"
)

var messageData = []byte("Approve export of report 2026-10")

func signTestMessage(t *testing.T, pq *qoresign.PqKeyPair, hedged bool) qoresign.MessageSignature {
	t.Helper()
	return must(qoresign.SignMessage(qoresign.SignMessageArgs{
		ChainID: testChainID, Signer: testAccount.Bech32, Data: messageData,
		ClassicalKey: testClassical, PqKey: pq, Hedged: hedged,
	}))
}

func verifyTestMessage(sig qoresign.MessageSignature, edit func(*qoresign.VerifyMessageOptions)) error {
	opts := qoresign.VerifyMessageOptions{
		ChainID: testChainID, Signer: testAccount.Bech32, Data: messageData,
		Signature: sig, PqPublicKey: testPq.PublicKey,
	}
	if edit != nil {
		edit(&opts)
	}
	return qoresign.VerifyMessage(opts)
}

func TestMessageDomain(t *testing.T) {
	got := must(qoresign.MessagePqSignBytes(testChainID, nil))
	if string(got) != "qorechain-msg-v1|qorechain-diana|" {
		t.Fatalf("%q", got)
	}
	found := map[string]bool{}
	for _, d := range qoresign.ReservedPqDomains {
		found[d] = true
	}
	if !found[qoresign.MessageDomain] || !found[qoresign.SiwqPqDomain] || len(qoresign.ReservedPqDomains) != 6 {
		t.Fatal(qoresign.ReservedPqDomains)
	}
	for _, bad := range []string{"", "qorechain diana", "qorechain|diana", "qorechain-diana\n", "qé"} {
		if _, err := qoresign.MessagePqSignBytes(bad, messageData); errCode(err) != qoresign.CodeInvalidArgument {
			t.Errorf("%q: %v", bad, err)
		}
		_, err := qoresign.SignMessage(qoresign.SignMessageArgs{
			ChainID: bad, Signer: testAccount.Bech32, Data: messageData, ClassicalKey: testClassical, PqKey: &testPq,
		})
		if errCode(err) != qoresign.CodeInvalidArgument {
			t.Errorf("sign %q: %v", bad, err)
		}
	}
}

func TestMessageChecks(t *testing.T) {
	sig := signTestMessage(t, &testPq, false)
	if err := verifyTestMessage(sig, nil); err != nil {
		t.Fatal(err)
	}
	optional := false
	cases := []struct {
		name string
		sig  func() qoresign.MessageSignature
		edit func(*qoresign.VerifyMessageOptions)
		want string
	}{
		{"bad chain id", nil, func(o *qoresign.VerifyMessageOptions) { o.ChainID = "bad chain" }, qoresign.CodeInvalidArgument},
		{"other chain", nil, func(o *qoresign.VerifyMessageOptions) { o.ChainID = "qorechain-vladi" }, qoresign.CodePqSignatureInvalid},
		{"no pq key", nil, func(o *qoresign.VerifyMessageOptions) { o.PqPublicKey = nil }, qoresign.CodeKeyNotRegistered},
		{"other data", nil, func(o *qoresign.VerifyMessageOptions) { o.Data = []byte("Approve export of report 2026-11") }, qoresign.CodeClassicalSignatureInvalid},
		{"bad signer", nil, func(o *qoresign.VerifyMessageOptions) { o.Signer = "qor1nope" }, qoresign.CodeInvalidAddress},
		{"other pq key", nil, func(o *qoresign.VerifyMessageOptions) {
			o.PqPublicKey = must(qoresign.DeriveHdPqKey(qoresign.DeriveHdOptions{Mnemonic: testMnemonic, Path: "m/44'/118'/0'/0'/0'"})).PublicKey
		}, qoresign.CodePqSignatureInvalid},
		{"classical only", func() qoresign.MessageSignature { return signTestMessage(t, nil, false) }, nil, qoresign.CodePqLayerMissing},
		{"classical only, optional", func() qoresign.MessageSignature { return signTestMessage(t, nil, false) },
			func(o *qoresign.VerifyMessageOptions) { o.RequirePq = &optional; o.PqPublicKey = nil }, ""},
		{"classical only, optional, other data", func() qoresign.MessageSignature { return signTestMessage(t, nil, false) },
			func(o *qoresign.VerifyMessageOptions) { o.RequirePq = &optional; o.Data = []byte("x") }, qoresign.CodeClassicalSignatureInvalid},
		{"hedged", func() qoresign.MessageSignature { return signTestMessage(t, &testPq, true) }, nil, ""},
		{"pq not base64", func() qoresign.MessageSignature {
			s := signTestMessage(t, &testPq, false)
			s.Pq.Signature = "!!"
			return s
		}, nil, qoresign.CodePqSignatureInvalid},
		{"unsupported algorithm", func() qoresign.MessageSignature {
			s := signTestMessage(t, &testPq, false)
			s.Pq.AlgorithmID = 2
			return s
		}, nil, qoresign.CodeUnsupportedAlgorithm},
		{"classical not base64", func() qoresign.MessageSignature {
			s := signTestMessage(t, &testPq, false)
			s.Classical.PublicKey = "!!"
			return s
		}, nil, qoresign.CodeClassicalSignatureInvalid},
		{"classical over other bytes", func() qoresign.MessageSignature {
			s := signTestMessage(t, &testPq, false)
			s.Classical.Signature = qoresign.ToBase64(must(qoresign.ClassicalSign(testClassical, []byte("other"))))
			return s
		}, nil, qoresign.CodeClassicalSignatureInvalid},
		{"wrong declared key type", func() qoresign.MessageSignature {
			s := signTestMessage(t, &testPq, false)
			s.Classical.KeyType = qoresign.EthSecp256k1
			return s
		}, nil, qoresign.CodeAddressMismatch},
		{"siwq-domain pq signature", func() qoresign.MessageSignature {
			s := signTestMessage(t, &testPq, false)
			s.Pq.Signature = qoresign.ToBase64(must(qoresign.PqSign(testPq.SecretKey, qoresign.SiwqPqSignBytes("x"), false)))
			return s
		}, nil, qoresign.CodePqSignatureInvalid},
	}
	for _, c := range cases {
		s := sig
		if c.sig != nil {
			s = c.sig()
		}
		if got := errCode(verifyTestMessage(s, c.edit)); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestMessageAddressMismatch(t *testing.T) {
	eth := must(qoresign.DeriveClassicalKey(testMnemonic, qoresign.DeriveClassicalOptions{Type: qoresign.EthSecp256k1}))
	ethAddr := must(qoresign.AddressFromPublicKey(eth.PublicKey, qoresign.EthSecp256k1))
	_, err := qoresign.SignMessage(qoresign.SignMessageArgs{
		ChainID: testChainID, Signer: testAccount.Bech32, Data: messageData, ClassicalKey: eth, PqKey: &testPq,
	})
	if errCode(err) != qoresign.CodeAddressMismatch {
		t.Fatal(err)
	}

	// A valid signature by another account's key.
	ethSig := must(qoresign.SignMessage(qoresign.SignMessageArgs{
		ChainID: testChainID, Signer: ethAddr.Bech32, Data: messageData, ClassicalKey: eth,
	}))
	swapped := signTestMessage(t, &testPq, false)
	swapped.Classical = ethSig.Classical
	if err := verifyTestMessage(swapped, nil); errCode(err) != qoresign.CodeAddressMismatch {
		t.Fatal(err)
	}
	// Verified against another signer.
	if err := verifyTestMessage(signTestMessage(t, &testPq, false), func(o *qoresign.VerifyMessageOptions) {
		o.Signer = ethAddr.Bech32
	}); errCode(err) != qoresign.CodeAddressMismatch {
		t.Fatal(err)
	}

	// eth_secp256k1 accounts verify (keccak digest), also when given the 0x form.
	ethPq := must(qoresign.DeriveCanonicalPqKey(testMnemonic, ethAddr.Bech32))
	sig := must(qoresign.SignMessage(qoresign.SignMessageArgs{
		ChainID: testChainID, Signer: ethAddr.Hex, Data: messageData, ClassicalKey: eth, PqKey: &ethPq,
	}))
	if err := qoresign.VerifyMessage(qoresign.VerifyMessageOptions{
		ChainID: testChainID, Signer: ethAddr.Bech32, Data: messageData, Signature: sig, PqPublicKey: ethPq.PublicKey,
	}); err != nil {
		t.Fatal(err)
	}

	// JSON round trip keeps the shared shape.
	raw := must(json.Marshal(sig))
	if !strings.HasPrefix(string(raw), `{"signatureType":"ml-dsa-87-hybrid","classical":{"keyType":"eth_secp256k1"`) {
		t.Fatalf("%s", raw)
	}
	var back qoresign.MessageSignature
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(must(json.Marshal(back)), raw) {
		t.Fatal("round trip changed the signature")
	}
	classicalOnly := must(json.Marshal(signTestMessage(t, nil, false)))
	if bytes.Contains(classicalOnly, []byte(`"pq"`)) || !bytes.Contains(classicalOnly, []byte(`"signatureType":"secp256k1"`)) {
		t.Fatalf("%s", classicalOnly)
	}
}
