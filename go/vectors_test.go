// SPDX-License-Identifier: Apache-2.0

package qoresign_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	qoresign "github.com/qorechain/qoresign/go"
)

type vectorKey struct {
	Path            string `json:"path"`
	Address         string `json:"address"`
	PublicKey       string `json:"publicKey"`
	PublicKeySha256 string `json:"publicKeySha256"`
}

type vectorAccount struct {
	Path       string `json:"path"`
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
	Address    string `json:"address"`
	Hex        string `json:"hex"`
}

type vectorTxCase struct {
	SignBytesVersion   string `json:"signBytesVersion"`
	SignBytes          string `json:"signBytes"`
	PqSignature        string `json:"pqSignature"`
	SignedBodyBytes    string `json:"signedBodyBytes"`
	ClassicalSignature string `json:"classicalSignature"`
	TxBytes            string `json:"txBytes"`
}

type vectorFile struct {
	Format   string `json:"format"`
	Mnemonic string `json:"mnemonic"`
	ChainID  string `json:"chainId"`
	Accounts struct {
		Secp256k1    vectorAccount `json:"secp256k1"`
		EthSecp256k1 vectorAccount `json:"eth_secp256k1"`
	} `json:"accounts"`
	Canonical  []vectorKey `json:"canonical"`
	HD         []vectorKey `json:"hd"`
	HDRejected []string    `json:"hdRejected"`
	HybridTx   struct {
		AccountNumber uint64         `json:"accountNumber"`
		BodyBytes     string         `json:"bodyBytes"`
		AuthInfoBytes string         `json:"authInfoBytes"`
		Cases         []vectorTxCase `json:"cases"`
	} `json:"hybridTx"`
	ProofOfPossession struct {
		Account   string `json:"account"`
		Message   string `json:"message"`
		Signature string `json:"signature"`
	} `json:"proofOfPossession"`
	RegisterMessage struct {
		TypeURL string `json:"typeUrl"`
		Value   string `json:"value"`
	} `json:"registerMessage"`
	Siwq struct {
		Fields         qoresign.SiwqFields `json:"fields"`
		Message        string              `json:"message"`
		Adr36SignBytes string              `json:"adr36SignBytes"`
		PqSignBytes    string              `json:"pqSignBytes"`
		Signature      json.RawMessage     `json:"signature"`
		VerifyAt       string              `json:"verifyAt"`
	} `json:"siwq"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "vectors", "qoresign-v1.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if v.Format != "qoresign-vectors-v1" {
		t.Fatalf("unexpected vector format %q", v.Format)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in vectors: %v", err)
	}
	return b
}

func eqHex(t *testing.T, what string, got []byte, want string) {
	t.Helper()
	if hex.EncodeToString(got) != want {
		t.Errorf("%s mismatch:\n got  %.120s...\n want %.120s...", what, hex.EncodeToString(got), want)
	}
}

// must panics on error; a panic fails the running test with its stack.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestVectors(t *testing.T) {
	v := loadVectors(t)

	classical := must(qoresign.DeriveClassicalKey(v.Mnemonic, qoresign.DeriveClassicalOptions{}))
	eth := must(qoresign.DeriveClassicalKey(v.Mnemonic, qoresign.DeriveClassicalOptions{Type: qoresign.EthSecp256k1}))

	t.Run("accounts", func(t *testing.T) {
		for _, c := range []struct {
			key  qoresign.ClassicalKey
			want vectorAccount
		}{{classical, v.Accounts.Secp256k1}, {eth, v.Accounts.EthSecp256k1}} {
			if p := qoresign.ClassicalPath(c.key.Type, 0); p != c.want.Path {
				t.Errorf("path %s, want %s", p, c.want.Path)
			}
			viaPath := must(qoresign.DeriveClassicalKey(v.Mnemonic, qoresign.DeriveClassicalOptions{Type: c.key.Type, Path: c.want.Path}))
			eqHex(t, "private key via path", viaPath.PrivateKey, c.want.PrivateKey)
			eqHex(t, "private key", c.key.PrivateKey, c.want.PrivateKey)
			eqHex(t, "public key", c.key.PublicKey, c.want.PublicKey)
			addr := must(qoresign.AddressFromPublicKey(c.key.PublicKey, c.key.Type))
			if addr.Bech32 != c.want.Address || addr.Hex != c.want.Hex {
				t.Errorf("address %s / %s, want %s / %s", addr.Bech32, addr.Hex, c.want.Address, c.want.Hex)
			}
			fromHex := must(qoresign.ParseAddress(c.want.Hex))
			if fromHex.Bech32 != c.want.Address {
				t.Errorf("ParseAddress(hex) = %s", fromHex.Bech32)
			}
			fromPriv := must(qoresign.ClassicalKeyFromPrivate(mustHex(t, c.want.PrivateKey), c.key.Type))
			eqHex(t, "public key from private", fromPriv.PublicKey, c.want.PublicKey)
			kt := must(qoresign.ClassicalKeyTypeFor(c.key.PublicKey, c.want.Address))
			if kt != c.key.Type {
				t.Errorf("ClassicalKeyTypeFor = %q, want %q", kt, c.key.Type)
			}
		}
	})

	t.Run("canonical", func(t *testing.T) {
		for _, c := range v.Canonical {
			k := must(qoresign.DeriveCanonicalPqKey(v.Mnemonic, c.Address))
			eqHex(t, "canonical public key "+c.Address, k.PublicKey, c.PublicKey)
			sum := sha256.Sum256(k.PublicKey)
			eqHex(t, "canonical public key sha256", sum[:], c.PublicKeySha256)
			if len(k.SecretKey) != qoresign.MLDSA87SecretKeyLength {
				t.Errorf("secret key length %d", len(k.SecretKey))
			}
		}
	})

	t.Run("hd", func(t *testing.T) {
		for _, c := range v.HD {
			k := must(qoresign.DeriveHdPqKey(qoresign.DeriveHdOptions{Mnemonic: v.Mnemonic, Path: c.Path}))
			eqHex(t, "hd public key "+c.Path, k.PublicKey, c.PublicKey)
			sum := sha256.Sum256(k.PublicKey)
			eqHex(t, "hd public key sha256", sum[:], c.PublicKeySha256)
		}
		wantCodes := map[string]string{
			"m/44'/118'/0'/0/0": qoresign.CodeHDNonHardened,
			"44'/118'/0'":       qoresign.CodeHDInvalidPath,
			"m/44'/x'":          qoresign.CodeHDInvalidPath,
		}
		for _, p := range v.HDRejected {
			_, err := qoresign.DeriveHdPqKey(qoresign.DeriveHdOptions{Mnemonic: v.Mnemonic, Path: p})
			if err == nil {
				t.Errorf("path %q accepted", p)
				continue
			}
			if want, ok := wantCodes[p]; ok && !qoresign.IsCode(err, want) {
				t.Errorf("path %q: %v, want %s", p, err, want)
			}
		}
	})

	pq := must(qoresign.DeriveCanonicalPqKey(v.Mnemonic, v.Accounts.Secp256k1.Address))
	body := mustHex(t, v.HybridTx.BodyBytes)
	auth := mustHex(t, v.HybridTx.AuthInfoBytes)

	t.Run("hybridTx", func(t *testing.T) {
		// the helpers the tests and the live test use encode the vector body and auth info
		eqHex(t, "hand-encoded body", sendBody("qoresign vector"), v.HybridTx.BodyBytes)
		eqHex(t, "hand-encoded auth info", authInfo(classical.PublicKey, 3, 500000, "50000"), v.HybridTx.AuthInfoBytes)
		if len(v.HybridTx.Cases) != 2 {
			t.Fatalf("expected 2 cases, got %d", len(v.HybridTx.Cases))
		}
		for _, c := range v.HybridTx.Cases {
			ver := qoresign.SignBytesVersion(c.SignBytesVersion)
			sb := must(qoresign.HybridSignBytes(v.ChainID, body, auth, ver))
			eqHex(t, c.SignBytesVersion+" signBytes", sb, c.SignBytes)
			signed := must(qoresign.SignHybrid(qoresign.SignHybridArgs{
				ChainID:          v.ChainID,
				AccountNumber:    v.HybridTx.AccountNumber,
				BodyBytes:        body,
				AuthInfoBytes:    auth,
				ClassicalKey:     classical,
				PqKey:            &pq,
				SignBytesVersion: ver,
			}))
			eqHex(t, c.SignBytesVersion+" pqSignature", signed.PqSignature, c.PqSignature)
			eqHex(t, c.SignBytesVersion+" signedBodyBytes", signed.BodyBytes, c.SignedBodyBytes)
			eqHex(t, c.SignBytesVersion+" classicalSignature", signed.ClassicalSignature, c.ClassicalSignature)
			eqHex(t, c.SignBytesVersion+" txBytes", signed.TxBytes, c.TxBytes)

			// the vector bytes verify as the network checks them
			res := must(qoresign.VerifyHybridTx(qoresign.VerifyHybridTxArgs{
				TxBytes:            mustHex(t, c.TxBytes),
				ChainID:            v.ChainID,
				AccountNumber:      v.HybridTx.AccountNumber,
				ClassicalPublicKey: classical.PublicKey,
				PqPublicKey:        pq.PublicKey,
				SignBytesVersion:   ver,
			}))
			if !res.Valid || !res.Classical || res.Pq == nil || res.Pq.SignBytesVersion != ver {
				t.Errorf("%s: vector tx does not verify: %+v", c.SignBytesVersion, res)
			}
			if !qoresign.PqVerify(pq.PublicKey, mustHex(t, c.SignBytes), mustHex(t, c.PqSignature)) {
				t.Errorf("%s: vector pq signature does not verify", c.SignBytesVersion)
			}
		}
	})

	t.Run("proofOfPossession", func(t *testing.T) {
		msg := must(qoresign.ProofOfPossessionMessage(v.ChainID, v.ProofOfPossession.Account, qoresign.AlgorithmMLDSA87, pq.PublicKey))
		if string(msg) != v.ProofOfPossession.Message {
			t.Errorf("PoP message mismatch")
		}
		sig := must(qoresign.SignProofOfPossession(v.ChainID, v.ProofOfPossession.Account, pq, false))
		eqHex(t, "PoP signature", sig, v.ProofOfPossession.Signature)
		if ok := must(qoresign.VerifyProofOfPossession(v.ChainID, v.ProofOfPossession.Account, pq.PublicKey, sig)); !ok {
			t.Error("PoP does not verify")
		}
	})

	t.Run("registerMessage", func(t *testing.T) {
		msg := must(qoresign.BuildRegisterPqKeyMessage(qoresign.RegisterPqKeyArgs{
			ChainID:            v.ChainID,
			Account:            v.Accounts.Secp256k1.Address,
			PqKey:              pq,
			ClassicalPublicKey: classical.PublicKey,
		}))
		if msg.TypeURL != v.RegisterMessage.TypeURL {
			t.Errorf("type url %s", msg.TypeURL)
		}
		eqHex(t, "register message", msg.Value, v.RegisterMessage.Value)
	})

	t.Run("siwq", func(t *testing.T) {
		msg := must(qoresign.CreateSiwqMessage(v.Siwq.Fields))
		if msg != v.Siwq.Message {
			t.Fatalf("message mismatch:\n%s\n---\n%s", msg, v.Siwq.Message)
		}
		parsed := must(qoresign.ParseSiwqMessage(msg))
		want := v.Siwq.Fields
		want.Version = "1"
		if !reflect.DeepEqual(parsed, want) {
			t.Errorf("parsed fields %+v, want %+v", parsed, want)
		}
		eqHex(t, "adr36SignBytes", qoresign.Adr36SignBytes(v.Accounts.Secp256k1.Address, []byte(msg)), v.Siwq.Adr36SignBytes)
		eqHex(t, "pqSignBytes", qoresign.SiwqPqSignBytes(msg), v.Siwq.PqSignBytes)

		sig := must(qoresign.SignSiwq(qoresign.SignSiwqArgs{Message: msg, ClassicalKey: classical, PqKey: &pq}))
		gotJSON := must(json.Marshal(sig))
		var got, wantAny any
		_ = json.Unmarshal(gotJSON, &got)
		_ = json.Unmarshal(v.Siwq.Signature, &wantAny)
		if !reflect.DeepEqual(got, wantAny) {
			t.Errorf("signature JSON mismatch:\n got  %.200s\n want %.200s", gotJSON, v.Siwq.Signature)
		}
		var compact bytes.Buffer
		_ = json.Compact(&compact, v.Siwq.Signature)
		if compact.String() != string(gotJSON) {
			t.Errorf("signature JSON differs in key order or formatting")
		}

		var vecSig qoresign.SiwqSignature
		if err := json.Unmarshal(v.Siwq.Signature, &vecSig); err != nil {
			t.Fatal(err)
		}
		at := must(time.Parse(time.RFC3339, v.Siwq.VerifyAt))
		fields := must(qoresign.VerifySiwq(qoresign.VerifySiwqOptions{
			Message:     v.Siwq.Message,
			Signature:   vecSig,
			Domain:      v.Siwq.Fields.Domain,
			Nonce:       v.Siwq.Fields.Nonce,
			ChainID:     v.ChainID,
			PqPublicKey: pq.PublicKey,
			Now:         at,
		}))
		if fields.Address != v.Accounts.Secp256k1.Address {
			t.Errorf("verified address %s", fields.Address)
		}
	})
}
