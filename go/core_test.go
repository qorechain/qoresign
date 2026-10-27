// SPDX-License-Identifier: Apache-2.0

package qoresign_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cosmos/btcutil/bech32"
	qoresign "github.com/qorechain/qoresign/go"
)

func TestAccountsAndDerivation(t *testing.T) {
	t.Run("the well-known Cosmos test account under the qor prefix", func(t *testing.T) {
		// m/44'/118'/0'/0/0 of the BIP-39 test mnemonic is cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4.
		_, words, err := bech32.Decode("cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4", 90)
		if err != nil {
			t.Fatal(err)
		}
		raw := must(bech32.ConvertBits(words, 5, 8, false))
		if !bytes.Equal(raw, testAccount.Bytes) || !strings.HasPrefix(testAccount.Bech32, "qor1") {
			t.Fatalf("account %s does not match the Cosmos test account", testAccount.Bech32)
		}
		if must(qoresign.ParseAddress(testAccount.Hex)).Bech32 != testAccount.Bech32 {
			t.Fatal("hex form does not parse back")
		}
		upper := must(qoresign.ParseAddress(strings.ToUpper(testAccount.Bech32)))
		if upper.Bech32 != testAccount.Bech32 {
			t.Fatal("upper-case bech32 does not parse")
		}
	})

	t.Run("invalid addresses", func(t *testing.T) {
		for _, a := range []string{"", "qor1", "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4", "0x1234", testAccount.Bech32[:len(testAccount.Bech32)-1] + "q"} {
			_, err := qoresign.ParseAddress(a)
			wantCode(t, err, qoresign.CodeInvalidAddress)
		}
	})

	t.Run("the 0x form resolves to the same canonical key", func(t *testing.T) {
		viaHex := must(qoresign.DeriveCanonicalPqKey(testMnemonic, testAccount.Hex))
		if !bytes.Equal(viaHex.PublicKey, testPq.PublicKey) {
			t.Fatal("canonical key differs between address forms")
		}
	})

	t.Run("canonical keys are bound to the address", func(t *testing.T) {
		eth := must(qoresign.DeriveClassicalKey(testMnemonic, qoresign.DeriveClassicalOptions{Type: qoresign.EthSecp256k1}))
		ethAddr := must(qoresign.AddressFromPublicKey(eth.PublicKey, qoresign.EthSecp256k1))
		other := must(qoresign.DeriveCanonicalPqKey(testMnemonic, ethAddr.Bech32))
		if bytes.Equal(other.PublicKey, testPq.PublicKey) {
			t.Fatal("same key for two accounts")
		}
		if kt := must(qoresign.ClassicalKeyTypeFor(eth.PublicKey, ethAddr.Bech32)); kt != qoresign.EthSecp256k1 {
			t.Fatalf("eth key type %q", kt)
		}
		if kt := must(qoresign.ClassicalKeyTypeFor(testClassical.PublicKey, testAccount.Bech32)); kt != qoresign.Secp256k1 {
			t.Fatalf("key type %q", kt)
		}
		if kt := must(qoresign.ClassicalKeyTypeFor(eth.PublicKey, testAccount.Bech32)); kt != "" {
			t.Fatalf("foreign key matched as %q", kt)
		}
	})

	t.Run("refuses a non-canonical mnemonic instead of deriving a different key", func(t *testing.T) {
		for _, m := range []string{
			" " + testMnemonic,
			testMnemonic + "\n",
			strings.Replace(testMnemonic, " ", "  ", 1),
			strings.Replace(testMnemonic, " ", "\t", 1),
			strings.ToUpper(testMnemonic),
			"abandon abandon",
			strings.Repeat("abandon ", 11) + "abandon", // bad checksum
		} {
			_, err := qoresign.DeriveCanonicalPqKey(m, testAccount.Bech32)
			wantCode(t, err, qoresign.CodeInvalidMnemonic)
			_, err = qoresign.DeriveClassicalKey(m, qoresign.DeriveClassicalOptions{})
			wantCode(t, err, qoresign.CodeInvalidMnemonic)
		}
	})

	t.Run("HD derivation is hardened-only and deterministic", func(t *testing.T) {
		a := must(qoresign.DeriveHdPqKey(qoresign.DeriveHdOptions{Mnemonic: testMnemonic, Path: qoresign.DefaultHdPath(0, 118)}))
		b := must(qoresign.DeriveHdPqKey(qoresign.DeriveHdOptions{Mnemonic: testMnemonic, Path: qoresign.DefaultHdPath(0, 118)}))
		c := must(qoresign.DeriveHdPqKey(qoresign.DeriveHdOptions{Mnemonic: testMnemonic, Path: qoresign.DefaultHdPath(1, 118)}))
		if !bytes.Equal(a.PublicKey, b.PublicKey) || bytes.Equal(a.PublicKey, c.PublicKey) || bytes.Equal(a.PublicKey, testPq.PublicKey) {
			t.Fatal("HD derivation is not deterministic or not index-dependent")
		}
		_, err := qoresign.DeriveHdPqKey(qoresign.DeriveHdOptions{Mnemonic: testMnemonic, Path: "m/44'/118'/0'/0/0"})
		wantCode(t, err, qoresign.CodeHDNonHardened)
		_, err = qoresign.DeriveHdPqKey(qoresign.DeriveHdOptions{Mnemonic: testMnemonic, Path: "44'/118'"})
		wantCode(t, err, qoresign.CodeHDInvalidPath)
		if !strings.Contains(err.Error(), `start with "m"`) {
			t.Fatalf("unexpected message: %v", err)
		}
		_, err = qoresign.DeriveHdPqKey(qoresign.DeriveHdOptions{Mnemonic: testMnemonic, Path: "m/2147483648'"})
		wantCode(t, err, qoresign.CodeHDInvalidPath)
		_, err = qoresign.DeriveHdPqKey(qoresign.DeriveHdOptions{Seed: make([]byte, 8), Path: "m/0'"})
		wantCode(t, err, qoresign.CodeInvalidArgument)
		_, err = qoresign.DeriveHdPqKey(qoresign.DeriveHdOptions{Path: "m/0'"})
		wantCode(t, err, qoresign.CodeInvalidArgument)
		seed := bytes.Repeat([]byte{7}, 32)
		s1 := must(qoresign.DeriveHdPqKey(qoresign.DeriveHdOptions{Seed: seed, Path: "m/0'"}))
		s2 := must(qoresign.DeriveHdPqKey(qoresign.DeriveHdOptions{Seed: seed, Path: " m/0' "}))
		if !bytes.Equal(s1.PublicKey, s2.PublicKey) {
			t.Fatal("surrounding whitespace in the path changed the key")
		}
	})

	t.Run("key length and private key checks", func(t *testing.T) {
		_, err := qoresign.PqKeyFromSeed(make([]byte, 31))
		wantCode(t, err, qoresign.CodeBadKeyLength)
		_, err = qoresign.ClassicalKeyFromPrivate(make([]byte, 31), qoresign.Secp256k1)
		wantCode(t, err, qoresign.CodeBadKeyLength)
		_, err = qoresign.ClassicalKeyFromPrivate(make([]byte, 32), qoresign.Secp256k1)
		wantCode(t, err, qoresign.CodeInvalidArgument)
		_, err = qoresign.DeriveClassicalKey(testMnemonic, qoresign.DeriveClassicalOptions{Path: "m/44'/x"})
		wantCode(t, err, qoresign.CodeHDInvalidPath)
	})
}

func TestProtobufBodyEdits(t *testing.T) {
	ext := qoresign.Any{TypeURL: qoresign.PqcHybridTypeURL, Value: []byte{8, 1}}

	t.Run("strip(append(body)) returns the original bytes", func(t *testing.T) {
		body := sendBody("qoresign test")
		withExt := must(qoresign.AppendExtension(body, ext))
		want := qoresign.Concat(body, qoresign.LenField(qoresign.TxBodyExtensionOptions, qoresign.EncodeAny(ext)))
		if !bytes.Equal(withExt, want) {
			t.Fatal("extension not appended at the end")
		}
		if !bytes.Equal(must(qoresign.StripExtension(withExt, qoresign.PqcHybridTypeURL)), body) {
			t.Fatal("strip did not restore the body")
		}
		exts := must(qoresign.BodyExtensions(withExt))
		if len(exts) != 1 || exts[0].TypeURL != qoresign.PqcHybridTypeURL {
			t.Fatalf("extensions %+v", exts)
		}
	})

	t.Run("inserts before non-critical extension options", func(t *testing.T) {
		memo := qoresign.StringField(2, "m")
		nonCritical := qoresign.LenField(qoresign.TxBodyNonCriticalExtensionOptions,
			qoresign.EncodeAny(qoresign.Any{TypeURL: "/x.Y", Value: []byte{1}}))
		body := qoresign.Concat(memo, nonCritical)
		got := must(qoresign.AppendExtension(body, ext))
		want := qoresign.Concat(memo, qoresign.LenField(qoresign.TxBodyExtensionOptions, qoresign.EncodeAny(ext)), nonCritical)
		if !bytes.Equal(got, want) {
			t.Fatalf("got %x, want %x", got, want)
		}
	})

	t.Run("malformed input is an error, never a panic", func(t *testing.T) {
		for _, b := range [][]byte{
			{0x0a},             // truncated length
			{0x0a, 0x05, 0x01}, // runs past the end
			{0x00, 0x01},       // field 0
			{0x0b},             // wire type 3
			{0x09, 1, 2, 3},    // fixed64 past the end
			bytes.Repeat([]byte{0xff}, 11),
		} {
			_, err := qoresign.ReadFields(b)
			wantCode(t, err, qoresign.CodeMalformedProtobuf)
			_, err = qoresign.StripExtension(b, qoresign.PqcHybridTypeURL)
			wantCode(t, err, qoresign.CodeMalformedProtobuf)
		}
		badUTF8 := qoresign.LenField(qoresign.TxBodyExtensionOptions, qoresign.LenField(1, []byte{0xff, 0xfe}))
		_, err := qoresign.PqcLayers(badUTF8)
		wantCode(t, err, qoresign.CodeMalformedProtobuf)
	})

	t.Run("TxRaw round trip keeps empty signatures", func(t *testing.T) {
		tx := qoresign.TxRaw{BodyBytes: []byte{1}, AuthInfoBytes: []byte{2}, Signatures: [][]byte{{}, {3}}}
		back := must(qoresign.DecodeTxRaw(qoresign.EncodeTxRaw(tx)))
		if len(back.Signatures) != 2 || len(back.Signatures[0]) != 0 || back.Signatures[1][0] != 3 {
			t.Fatalf("round trip %+v", back)
		}
	})
}

func signTest(t *testing.T, args qoresign.SignHybridArgs) qoresign.SignedTx {
	t.Helper()
	if args.ChainID == "" {
		args.ChainID = testChainID
	}
	if args.BodyBytes == nil {
		args.BodyBytes = sendBody("qoresign test")
	}
	if args.AuthInfoBytes == nil {
		args.AuthInfoBytes = testAuth(3)
	}
	if args.ClassicalKey.PrivateKey == nil {
		args.ClassicalKey = testClassical
	}
	return must(qoresign.SignHybrid(args))
}

func TestHybridSigning(t *testing.T) {
	pq := testPq

	t.Run("verifies, and rejects tampering", func(t *testing.T) {
		signed := signTest(t, qoresign.SignHybridArgs{AccountNumber: 7, PqKey: &pq})
		ok := must(qoresign.VerifyHybridTx(qoresign.VerifyHybridTxArgs{
			TxBytes: signed.TxBytes, ChainID: testChainID, AccountNumber: 7,
			ClassicalPublicKey: testClassical.PublicKey, PqPublicKey: pq.PublicKey,
		}))
		if !ok.Valid || !ok.Classical || ok.Pq == nil || !ok.Pq.Valid || ok.Pq.SignBytesVersion != qoresign.SignBytesV2 {
			t.Fatalf("valid tx rejected: %+v", ok)
		}

		wrongChain := must(qoresign.VerifyHybridTx(qoresign.VerifyHybridTxArgs{
			TxBytes: signed.TxBytes, ChainID: "qorechain-vladi", AccountNumber: 7,
			ClassicalPublicKey: testClassical.PublicKey, PqPublicKey: pq.PublicKey,
		}))
		if wrongChain.Valid || wrongChain.Pq.Reason != qoresign.ReasonInvalidSignature {
			t.Fatalf("wrong chain accepted: %+v", wrongChain)
		}

		wrongAccount := must(qoresign.VerifyHybridTx(qoresign.VerifyHybridTxArgs{
			TxBytes: signed.TxBytes, ChainID: testChainID, AccountNumber: 8, ClassicalPublicKey: testClassical.PublicKey,
		}))
		if wrongAccount.Valid || wrongAccount.Classical || wrongAccount.Pq != nil {
			t.Fatalf("wrong account number accepted: %+v", wrongAccount)
		}

		other := must(qoresign.DeriveHdPqKey(qoresign.DeriveHdOptions{Mnemonic: testMnemonic, Path: qoresign.DefaultHdPath(0, 118)}))
		wrongKey := must(qoresign.VerifyPqLayer(qoresign.VerifyPqLayerArgs{
			ChainID: testChainID, BodyBytes: signed.BodyBytes, AuthInfoBytes: signed.AuthInfoBytes, PqPublicKey: other.PublicKey,
		}))
		if wrongKey.Valid {
			t.Fatal("wrong key accepted")
		}

		// a different fee (auth info) invalidates the PQ layer
		feeSwap := must(qoresign.VerifyPqLayer(qoresign.VerifyPqLayerArgs{
			ChainID: testChainID, BodyBytes: signed.BodyBytes, AuthInfoBytes: testAuth(4), PqPublicKey: pq.PublicKey,
		}))
		if feeSwap.Valid {
			t.Fatal("auth info swap accepted")
		}

		_, err := qoresign.VerifyHybridTx(qoresign.VerifyHybridTxArgs{
			TxBytes: qoresign.EncodeTxRaw(qoresign.TxRaw{BodyBytes: signed.BodyBytes}), ChainID: testChainID,
			ClassicalPublicKey: testClassical.PublicKey,
		})
		wantCode(t, err, qoresign.CodeInvalidArgument)
	})

	t.Run("SignPqLayer leaves the classical signature to another signer and is checked with either version", func(t *testing.T) {
		layered := must(qoresign.SignPqLayer(qoresign.SignPqLayerArgs{
			ChainID: testChainID, BodyBytes: sendBody("x"), AuthInfoBytes: testAuth(3), PqKey: pq, SignBytesVersion: qoresign.SignBytesV1,
		}))
		if n := len(must(qoresign.PqcLayers(layered.BodyBytes))); n != 1 {
			t.Fatalf("%d layers", n)
		}
		v2 := must(qoresign.VerifyPqLayer(qoresign.VerifyPqLayerArgs{
			ChainID: testChainID, BodyBytes: layered.BodyBytes, AuthInfoBytes: testAuth(3), PqPublicKey: pq.PublicKey,
		}))
		if v2.Valid {
			t.Fatal("v1 layer verified as v2")
		}
		either := must(qoresign.VerifyPqLayer(qoresign.VerifyPqLayerArgs{
			ChainID: testChainID, BodyBytes: layered.BodyBytes, AuthInfoBytes: testAuth(3), PqPublicKey: pq.PublicKey,
			SignBytesVersion: qoresign.SignBytesEither,
		}))
		if !either.Valid || either.SignBytesVersion != qoresign.SignBytesV1 {
			t.Fatalf("either: %+v", either)
		}
		// re-layering replaces the old layer instead of adding a second one
		again := must(qoresign.SignPqLayer(qoresign.SignPqLayerArgs{
			ChainID: testChainID, BodyBytes: layered.BodyBytes, AuthInfoBytes: testAuth(3), PqKey: pq,
		}))
		if n := len(must(qoresign.PqcLayers(again.BodyBytes))); n != 1 {
			t.Fatalf("%d layers after re-layering", n)
		}
	})

	t.Run("detects missing, duplicated, foreign-algorithm and mismatched embedded keys", func(t *testing.T) {
		verify := func(body []byte) qoresign.PqLayerResult {
			return must(qoresign.VerifyPqLayer(qoresign.VerifyPqLayerArgs{
				ChainID: testChainID, BodyBytes: body, AuthInfoBytes: testAuth(3), PqPublicKey: pq.PublicKey,
			}))
		}
		if r := verify(sendBody("x")); r.Reason != qoresign.ReasonMissing {
			t.Fatalf("missing: %+v", r)
		}
		one := must(qoresign.SignPqLayer(qoresign.SignPqLayerArgs{ChainID: testChainID, BodyBytes: sendBody("x"), AuthInfoBytes: testAuth(3), PqKey: pq}))
		dup := must(qoresign.AppendExtension(one.BodyBytes, qoresign.Any{TypeURL: qoresign.PqcHybridTypeURL, Value: []byte{8, 1}}))
		if r := verify(dup); r.Reason != qoresign.ReasonDuplicated {
			t.Fatalf("duplicated: %+v", r)
		}
		foreign := must(qoresign.AppendExtension(sendBody("x"), qoresign.Any{
			TypeURL: qoresign.PqcHybridTypeURL,
			Value:   qoresign.EncodePqcHybridSignature(qoresign.PqcHybridSignature{AlgorithmID: 2, Signature: one.PqSignature}),
		}))
		if r := verify(foreign); r.Reason != qoresign.ReasonUnsupportedAlgorithm {
			t.Fatalf("algorithm: %+v", r)
		}
		other := must(qoresign.DeriveHdPqKey(qoresign.DeriveHdOptions{Mnemonic: testMnemonic, Path: qoresign.DefaultHdPath(0, 118)}))
		embedded := must(qoresign.SignPqLayer(qoresign.SignPqLayerArgs{
			ChainID: testChainID, BodyBytes: sendBody("x"), AuthInfoBytes: testAuth(3), PqKey: other, IncludePublicKey: true,
		}))
		if r := verify(embedded.BodyBytes); r.Reason != qoresign.ReasonEmbeddedKeyMismatch {
			t.Fatalf("embedded: %+v", r)
		}
		layer := must(qoresign.PqcLayers(embedded.BodyBytes))[0]
		if !bytes.Equal(layer.PublicKey, other.PublicKey) || layer.AlgorithmID != qoresign.AlgorithmMLDSA87 {
			t.Fatal("embedded key not carried")
		}
	})

	t.Run("classicalOnly carries no layer; pqOnly and a missing key are refused", func(t *testing.T) {
		signed := signTest(t, qoresign.SignHybridArgs{AccountNumber: 1, Mode: qoresign.ModeClassicalOnly})
		tx := must(qoresign.DecodeTxRaw(signed.TxBytes))
		if n := len(must(qoresign.PqcLayers(tx.BodyBytes))); n != 0 || signed.PqSignature != nil {
			t.Fatalf("classicalOnly carries %d layers", n)
		}
		_, err := qoresign.SignHybrid(qoresign.SignHybridArgs{
			ChainID: testChainID, BodyBytes: sendBody("x"), AuthInfoBytes: testAuth(3), ClassicalKey: testClassical, PqKey: &pq, Mode: qoresign.ModePqOnly,
		})
		wantCode(t, err, qoresign.CodeLaneNotAvailable)
		if !strings.Contains(err.Error(), "PQ-only") {
			t.Fatalf("message: %v", err)
		}
		_, err = qoresign.SignHybrid(qoresign.SignHybridArgs{
			ChainID: testChainID, BodyBytes: sendBody("x"), AuthInfoBytes: testAuth(3), ClassicalKey: testClassical,
		})
		wantCode(t, err, qoresign.CodeInvalidArgument)
	})

	t.Run("sign-bytes ignore an existing layer and check their inputs", func(t *testing.T) {
		layered := must(qoresign.SignPqLayer(qoresign.SignPqLayerArgs{ChainID: testChainID, BodyBytes: sendBody("x"), AuthInfoBytes: testAuth(3), PqKey: pq}))
		a := must(qoresign.HybridSignBytes(testChainID, layered.BodyBytes, testAuth(3), ""))
		b := must(qoresign.HybridSignBytes(testChainID, sendBody("x"), testAuth(3), qoresign.SignBytesV2))
		if !bytes.Equal(a, b) {
			t.Fatal("sign-bytes depend on the PQC layer")
		}
		_, err := qoresign.HybridSignBytes(testChainID, sendBody("x"), testAuth(3), "v3")
		wantCode(t, err, qoresign.CodeSignBytesVersionUnknown)
		_, err = qoresign.HybridSignBytes(testChainID, sendBody("x"), testAuth(3), qoresign.SignBytesEither)
		wantCode(t, err, qoresign.CodeSignBytesVersionUnknown)
		_, err = qoresign.HybridSignBytes("", sendBody("x"), testAuth(3), qoresign.SignBytesV1)
		wantCode(t, err, qoresign.CodeInvalidArgument)
	})

	t.Run("hedged signatures differ and verify", func(t *testing.T) {
		msg := []byte("hedged")
		s1 := must(qoresign.PqSign(pq.SecretKey, msg, true))
		s2 := must(qoresign.PqSign(pq.SecretKey, msg, true))
		d1 := must(qoresign.PqSign(pq.SecretKey, msg, false))
		d2 := must(qoresign.PqSign(pq.SecretKey, msg, false))
		if bytes.Equal(s1, s2) || !bytes.Equal(d1, d2) {
			t.Fatal("hedged/deterministic behaviour wrong")
		}
		for _, s := range [][]byte{s1, s2, d1} {
			if !qoresign.PqVerify(pq.PublicKey, msg, s) {
				t.Fatal("signature does not verify")
			}
		}
		_, err := qoresign.PqSign(pq.SecretKey[:10], msg, false)
		wantCode(t, err, qoresign.CodeBadKeyLength)
	})

	t.Run("verifiers never panic on malformed input", func(t *testing.T) {
		sig := must(qoresign.PqSign(pq.SecretKey, []byte("m"), false))
		cases := []struct{ pk, sig []byte }{
			{nil, nil},
			{pq.PublicKey, sig[:len(sig)-1]},
			{pq.PublicKey, append(append([]byte{}, sig...), 0)},
			{pq.PublicKey[:100], sig},
			{make([]byte, qoresign.MLDSA87PublicKeyLength), make([]byte, qoresign.MLDSA87SignatureLength)},
			{bytes.Repeat([]byte{0xff}, qoresign.MLDSA87PublicKeyLength), bytes.Repeat([]byte{0xff}, qoresign.MLDSA87SignatureLength)},
		}
		for _, c := range cases {
			if qoresign.PqVerify(c.pk, []byte("m"), c.sig) {
				t.Fatal("malformed ML-DSA input verified")
			}
		}
		csig := must(qoresign.ClassicalSign(testClassical, []byte("m")))
		if !qoresign.ClassicalVerify(qoresign.Secp256k1, testClassical.PublicKey, []byte("m"), csig) {
			t.Fatal("classical signature does not verify")
		}
		if qoresign.ClassicalVerify(qoresign.EthSecp256k1, testClassical.PublicKey, []byte("m"), csig) {
			t.Fatal("digest type ignored")
		}
		for _, c := range []struct{ pk, sig []byte }{
			{testClassical.PublicKey, csig[:63]},
			{testClassical.PublicKey[:10], csig},
			{testClassical.PublicKey, make([]byte, 64)},
			{testClassical.PublicKey, bytes.Repeat([]byte{0xff}, 64)},
			{testClassical.PublicKey, highS(csig)},
		} {
			if qoresign.ClassicalVerify(qoresign.Secp256k1, c.pk, []byte("m"), c.sig) {
				t.Fatalf("malformed classical input verified: %x", c.sig)
			}
		}
	})
}

// highS returns the same signature with s replaced by n - s.
func highS(sig []byte) []byte {
	n := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
		0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
	}
	out := append([]byte{}, sig...)
	borrow := 0
	for i := 31; i >= 0; i-- {
		d := int(n[i]) - int(sig[32+i]) - borrow
		borrow = 0
		if d < 0 {
			d += 256
			borrow = 1
		}
		out[32+i] = byte(d)
	}
	return out
}

func TestKeyRegistration(t *testing.T) {
	pq := testPq

	t.Run("proof of possession", func(t *testing.T) {
		proof := must(qoresign.SignProofOfPossession(testChainID, testAccount.Bech32, pq, false))
		if !must(qoresign.VerifyProofOfPossession(testChainID, testAccount.Bech32, pq.PublicKey, proof)) {
			t.Fatal("proof does not verify")
		}
		if !must(qoresign.VerifyProofOfPossession(testChainID, testAccount.Hex, pq.PublicKey, proof)) {
			t.Fatal("proof does not verify via the 0x form")
		}
		if must(qoresign.VerifyProofOfPossession("qorechain-vladi", testAccount.Bech32, pq.PublicKey, proof)) {
			t.Fatal("proof verified on another chain")
		}
		_, err := qoresign.ProofOfPossessionMessage("", testAccount.Bech32, qoresign.AlgorithmMLDSA87, pq.PublicKey)
		wantCode(t, err, qoresign.CodeInvalidArgument)
	})

	t.Run("MsgRegisterPQCKeyV2 layout", func(t *testing.T) {
		msg := must(qoresign.BuildRegisterPqKeyMessage(qoresign.RegisterPqKeyArgs{
			ChainID: testChainID, Account: testAccount.Bech32, PqKey: pq, ClassicalPublicKey: testClassical.PublicKey,
		}))
		if msg.TypeURL != qoresign.MsgRegisterPQCKeyV2TypeURL {
			t.Fatal(msg.TypeURL)
		}
		fields := must(qoresign.ReadFields(msg.Value))
		if len(fields) != 6 {
			t.Fatalf("%d fields", len(fields))
		}
		if string(fields[0].Bytes) != testAccount.Bech32 || !bytes.Equal(fields[1].Bytes, pq.PublicKey) ||
			fields[2].Varint != qoresign.AlgorithmMLDSA87 || !bytes.Equal(fields[3].Bytes, testClassical.PublicKey) ||
			string(fields[4].Bytes) != "hybrid" {
			t.Fatal("unexpected field values")
		}
		if !must(qoresign.VerifyProofOfPossession(testChainID, testAccount.Bech32, fields[1].Bytes, fields[5].Bytes)) {
			t.Fatal("embedded proof does not verify")
		}
	})

	t.Run("refuses a classical key that does not control the account, and a forgeable key", func(t *testing.T) {
		eth := must(qoresign.DeriveClassicalKey(testMnemonic, qoresign.DeriveClassicalOptions{Type: qoresign.EthSecp256k1}))
		_, err := qoresign.BuildRegisterPqKeyMessage(qoresign.RegisterPqKeyArgs{
			ChainID: testChainID, Account: testAccount.Bech32, PqKey: pq, ClassicalPublicKey: eth.PublicKey,
		})
		wantCode(t, err, qoresign.CodeAddressMismatch)
		degenerate := make([]byte, qoresign.MLDSA87PublicKeyLength)
		degenerate[0] = 1
		if !qoresign.IsDegeneratePqPublicKey(degenerate) || qoresign.IsDegeneratePqPublicKey(pq.PublicKey) {
			t.Fatal("degenerate key detection wrong")
		}
		_, err = qoresign.BuildRegisterPqKeyMessage(qoresign.RegisterPqKeyArgs{
			ChainID: testChainID, Account: testAccount.Bech32,
			PqKey:              qoresign.PqKeyPair{PublicKey: degenerate, SecretKey: pq.SecretKey},
			ClassicalPublicKey: testClassical.PublicKey,
		})
		wantCode(t, err, qoresign.CodeInvalidArgument)
		if !strings.Contains(err.Error(), "forgeable") {
			t.Fatalf("message: %v", err)
		}
		_, err = qoresign.BuildRegisterPqKeyMessage(qoresign.RegisterPqKeyArgs{
			ChainID: testChainID, Account: testAccount.Bech32,
			PqKey:              qoresign.PqKeyPair{PublicKey: pq.PublicKey[:10], SecretKey: pq.SecretKey},
			ClassicalPublicKey: testClassical.PublicKey,
		})
		wantCode(t, err, qoresign.CodeBadKeyLength)
	})
}

func TestLanes(t *testing.T) {
	if err := qoresign.AssertHybridLane(qoresign.LaneNative); err != nil {
		t.Fatal(err)
	}
	err := qoresign.AssertHybridLane(qoresign.LaneEVM)
	wantCode(t, err, qoresign.CodeLaneNotAvailable)
	if !strings.Contains(err.Error(), "per-lane PQC") {
		t.Fatal(err)
	}
	err = qoresign.AssertHybridLane(qoresign.LaneSVM)
	wantCode(t, err, qoresign.CodeLaneNotAvailable)
	if !strings.Contains(err.Error(), "not open") {
		t.Fatal(err)
	}
	if qoresign.LaneSupport(qoresign.LaneNative) != qoresign.SupportHybrid ||
		qoresign.LaneSupport(qoresign.LaneEVM) != qoresign.SupportQuantumReady ||
		qoresign.LaneSupport(qoresign.LaneSVM) != qoresign.SupportUnavailable {
		t.Fatal("lane support table")
	}
	d := qoresign.DecideLane(qoresign.LaneRequest{IsQorTransfer: true})
	if d != (qoresign.LaneDecision{Lane: qoresign.LaneNative, Reason: qoresign.LaneReasonDefaultNative}) {
		t.Fatalf("%+v", d)
	}
	if d := qoresign.DecideLane(qoresign.LaneRequest{IsQorTransfer: true, DappRequiredLane: qoresign.LaneEVM}); !d.LeavesHybridDefault || d.Reason != qoresign.LaneReasonDappRequired {
		t.Fatalf("%+v", d)
	}
	if d := qoresign.DecideLane(qoresign.LaneRequest{ExplicitLane: qoresign.LaneSVM}); d.Lane != qoresign.LaneSVM || d.Reason != qoresign.LaneReasonUserOverride {
		t.Fatalf("%+v", d)
	}

	state := func(in qoresign.LayerStateInput) qoresign.LayerState { return qoresign.EvaluateLayerState(in) }
	if s := state(qoresign.LayerStateInput{Lane: qoresign.LaneNative, OnQoreChain: true, SignedWithPqLayer: true}); s != qoresign.LayerPending {
		t.Fatal(s)
	}
	if s := state(qoresign.LayerStateInput{Lane: qoresign.LaneNative, OnQoreChain: true, SignedWithPqLayer: true,
		CommittedExtensionTypeURLs: []string{qoresign.PqcHybridTypeURL}}); s != qoresign.LayerProtected {
		t.Fatal(s)
	}
	if s := state(qoresign.LayerStateInput{Lane: qoresign.LaneNative, OnQoreChain: true, SignedWithPqLayer: true,
		CommittedExtensionTypeURLs: []string{}}); s != qoresign.LayerDowngraded {
		t.Fatal(s)
	}
	if s := state(qoresign.LayerStateInput{Lane: qoresign.LaneEVM, OnQoreChain: true}); s != qoresign.LayerClassical {
		t.Fatal(s)
	}
}

func TestErrors(t *testing.T) {
	_, err := qoresign.ParseAddress("nope")
	wrapped := fmt.Errorf("context: %w", err)
	if !qoresign.IsCode(wrapped, qoresign.CodeInvalidAddress) || qoresign.IsCode(wrapped, qoresign.CodeKeyMismatch) {
		t.Fatal("IsCode does not unwrap")
	}
	if qoresign.IsCode(errors.New("x"), qoresign.CodeInvalidAddress) || qoresign.IsCode(nil, qoresign.CodeInvalidAddress) {
		t.Fatal("IsCode matched a foreign error")
	}
	var qe *qoresign.Error
	if !errors.As(wrapped, &qe) || qe.Code != qoresign.CodeInvalidAddress || qe.Message == "" {
		t.Fatal("errors.As")
	}
}
