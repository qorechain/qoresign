// SPDX-License-Identifier: Apache-2.0

package qoresign_test

import (
	"reflect"
	"strings"
	"testing"
	"time"

	qoresign "github.com/qorechain/qoresign/go"
)

func siwqFields() qoresign.SiwqFields {
	return qoresign.SiwqFields{
		Scheme:         "https",
		Domain:         "app.example.com",
		Address:        testAccount.Bech32,
		Statement:      "Sign in to the example app.",
		URI:            "https://app.example.com/login",
		ChainID:        testChainID,
		Nonce:          "a1b2c3d4e5",
		IssuedAt:       "2026-10-27T10:00:00Z",
		ExpirationTime: "2026-10-27T10:10:00Z",
		Resources:      []string{"https://app.example.com/terms"},
	}
}

var siwqNow = time.Date(2026, 10, 27, 10, 1, 0, 0, time.UTC)

func errCode(err error) string {
	if err == nil {
		return ""
	}
	if e, ok := err.(*qoresign.Error); ok {
		return e.Code
	}
	return err.Error()
}

func TestSiwqMessageFormat(t *testing.T) {
	t.Run("renders the EIP-4361-style layout and round-trips", func(t *testing.T) {
		text := must(qoresign.CreateSiwqMessage(siwqFields()))
		want := strings.Join([]string{
			"https://app.example.com wants you to sign in with your QoreChain account:",
			testAccount.Bech32,
			"",
			"Sign in to the example app.",
			"",
			"URI: https://app.example.com/login",
			"Version: 1",
			"Chain ID: qorechain-diana",
			"Nonce: a1b2c3d4e5",
			"Issued At: 2026-10-27T10:00:00Z",
			"Expiration Time: 2026-10-27T10:10:00Z",
			"Resources:",
			"- https://app.example.com/terms",
		}, "\n")
		if text != want {
			t.Fatalf("got:\n%s", text)
		}
		parsed := must(qoresign.ParseSiwqMessage(text))
		wantFields := siwqFields()
		wantFields.Version = "1"
		if !reflect.DeepEqual(parsed, wantFields) {
			t.Fatalf("parsed %+v", parsed)
		}
	})

	t.Run("handles a message without statement and optional fields", func(t *testing.T) {
		f := siwqFields()
		f.Statement, f.ExpirationTime, f.Resources, f.Scheme = "", "", nil, ""
		f.NotBefore, f.RequestID = "2026-10-27T09:59:00.123+02:00", "req-1"
		text := must(qoresign.CreateSiwqMessage(f))
		lines := strings.Split(text, "\n")
		if !reflect.DeepEqual(lines[:4], []string{"app.example.com wants you to sign in with your QoreChain account:", testAccount.Bech32, "", ""}) {
			t.Fatalf("got %q", lines[:4])
		}
		parsed := must(qoresign.ParseSiwqMessage(text))
		if parsed.Statement != "" || parsed.NotBefore != f.NotBefore || parsed.RequestID != "req-1" {
			t.Fatalf("parsed %+v", parsed)
		}
		if must(qoresign.CreateSiwqMessage(parsed)) != text {
			t.Fatal("re-render differs")
		}
	})

	t.Run("rejects malformed input", func(t *testing.T) {
		mut := func(fn func(*qoresign.SiwqFields)) error {
			f := siwqFields()
			fn(&f)
			_, err := qoresign.CreateSiwqMessage(f)
			return err
		}
		for name, fn := range map[string]func(*qoresign.SiwqFields){
			"short nonce":       func(f *qoresign.SiwqFields) { f.Nonce = "short" },
			"two-line stmt":     func(f *qoresign.SiwqFields) { f.Statement = "two\nlines" },
			"issuedAt":          func(f *qoresign.SiwqFields) { f.IssuedAt = "yesterday" },
			"domain slash":      func(f *qoresign.SiwqFields) { f.Domain = "app.example.com/x" },
			"domain space":      func(f *qoresign.SiwqFields) { f.Domain = "app example" },
			"domain nbsp":       func(f *qoresign.SiwqFields) { f.Domain = "app example" },
			"scheme":            func(f *qoresign.SiwqFields) { f.Scheme = "1http" },
			"uri":               func(f *qoresign.SiwqFields) { f.URI = "/login" },
			"uri space":         func(f *qoresign.SiwqFields) { f.URI = "https://a b" },
			"version":           func(f *qoresign.SiwqFields) { f.Version = "2" },
			"chain id":          func(f *qoresign.SiwqFields) { f.ChainID = "a b" },
			"expiration":        func(f *qoresign.SiwqFields) { f.ExpirationTime = "2026-10-27" },
			"resource":          func(f *qoresign.SiwqFields) { f.Resources = []string{"terms"} },
			"request id":        func(f *qoresign.SiwqFields) { f.RequestID = "a\nb" },
			"hex address":       func(f *qoresign.SiwqFields) { f.Address = testAccount.Hex },
			"lowercase iso 'z'": func(f *qoresign.SiwqFields) { f.IssuedAt = "2026-10-27T10:00:00z" },
		} {
			if c := errCode(mut(fn)); c != qoresign.CodeSiwqMalformed {
				t.Errorf("%s: got %q", name, c)
			}
		}
		if c := errCode(mut(func(f *qoresign.SiwqFields) { f.Address = "qor1nope" })); c != qoresign.CodeInvalidAddress {
			t.Errorf("bad address: %q", c)
		}
		text := must(qoresign.CreateSiwqMessage(siwqFields()))
		for _, bad := range []string{
			text + "\nextra",
			text + "\n",
			strings.Replace(text, "Version: 1", "Version: 2", 1),
			strings.Replace(text, "\n\nURI", "\nURI", 1),
			strings.Replace(text, "wants you", "asks you", 1),
			strings.Replace(text, "Nonce: a1b2c3d4e5\n", "", 1),
			strings.Replace(text, "Resources:\n- https://app.example.com/terms", "Resources:", 1),
			"",
		} {
			if _, err := qoresign.ParseSiwqMessage(bad); errCode(err) != qoresign.CodeSiwqMalformed {
				t.Errorf("accepted or wrong code (%v) for:\n%s", err, bad)
			}
		}
	})
}

func TestAdr36(t *testing.T) {
	// The amino sign document Keplr-compatible wallets sign for signArbitrary("hello").
	want := `{"account_number":"0","chain_id":"","fee":{"amount":[],"gas":"0"},"memo":"",` +
		`"msgs":[{"type":"sign/MsgSignData","value":{"data":"aGVsbG8=","signer":"` + testAccount.Bech32 + `"}}],"sequence":"0"}`
	if got := string(qoresign.Adr36SignBytes(testAccount.Bech32, []byte("hello"))); got != want {
		t.Fatalf("got %s", got)
	}
}

func TestSiwqSignAndVerify(t *testing.T) {
	pq := testPq
	message := must(qoresign.CreateSiwqMessage(siwqFields()))
	signature := must(qoresign.SignSiwq(qoresign.SignSiwqArgs{Message: message, ClassicalKey: testClassical, PqKey: &pq}))
	base := func() qoresign.VerifySiwqOptions {
		return qoresign.VerifySiwqOptions{
			Message: message, Signature: signature, Domain: "app.example.com", Nonce: "a1b2c3d4e5",
			PqPublicKey: pq.PublicKey, Now: siwqNow,
		}
	}

	t.Run("verifies a hybrid sign-in", func(t *testing.T) {
		if signature.SignatureType != qoresign.SiwqSignatureHybrid {
			t.Fatal(signature.SignatureType)
		}
		out := must(qoresign.VerifySiwq(base()))
		if out.Address != testAccount.Bech32 {
			t.Fatal(out.Address)
		}
		hedged := must(qoresign.SignSiwq(qoresign.SignSiwqArgs{Message: message, ClassicalKey: testClassical, PqKey: &pq, Hedged: true}))
		o := base()
		o.Signature = hedged
		must(qoresign.VerifySiwq(o))
	})

	t.Run("refuses the wrong domain, nonce, chain, time or key", func(t *testing.T) {
		other := must(qoresign.DeriveHdPqKey(qoresign.DeriveHdOptions{Mnemonic: testMnemonic, Path: qoresign.DefaultHdPath(0, 118)}))
		cases := []struct {
			name string
			fn   func(*qoresign.VerifySiwqOptions)
			code string
		}{
			{"domain", func(o *qoresign.VerifySiwqOptions) { o.Domain = "evil.example" }, qoresign.CodeSiwqDomainMismatch},
			{"nonce", func(o *qoresign.VerifySiwqOptions) { o.Nonce = "zzzzzzzzzz" }, qoresign.CodeSiwqNonceMismatch},
			{"chain", func(o *qoresign.VerifySiwqOptions) { o.ChainID = "qorechain-vladi" }, qoresign.CodeSiwqChainMismatch},
			{"expired", func(o *qoresign.VerifySiwqOptions) { o.Now = time.Date(2026, 10, 27, 10, 10, 0, 0, time.UTC) }, qoresign.CodeSiwqExpired},
			{"early", func(o *qoresign.VerifySiwqOptions) { o.Now = time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC) }, qoresign.CodeSiwqNotYetValid},
			{"no skew", func(o *qoresign.VerifySiwqOptions) {
				o.Now = time.Date(2026, 10, 27, 9, 59, 30, 0, time.UTC)
				o.ClockSkew = -1
			}, qoresign.CodeSiwqNotYetValid},
			{"wrong key", func(o *qoresign.VerifySiwqOptions) { o.PqPublicKey = other.PublicKey }, qoresign.CodePqSignatureInvalid},
			{"no key", func(o *qoresign.VerifySiwqOptions) { o.PqPublicKey = nil }, qoresign.CodeKeyNotRegistered},
			{"pq not base64", func(o *qoresign.VerifySiwqOptions) {
				pqs := *o.Signature.Pq
				pqs.Signature = "!!"
				o.Signature.Pq = &pqs
			}, qoresign.CodePqSignatureInvalid},
			{"algorithm", func(o *qoresign.VerifySiwqOptions) {
				pqs := *o.Signature.Pq
				pqs.AlgorithmID = 2
				o.Signature.Pq = &pqs
			}, qoresign.CodeUnsupportedAlgorithm},
			{"classical not base64", func(o *qoresign.VerifySiwqOptions) { o.Signature.Classical.Signature = "@@" }, qoresign.CodeClassicalSignatureInvalid},
			{"key type", func(o *qoresign.VerifySiwqOptions) { o.Signature.Classical.KeyType = qoresign.EthSecp256k1 }, qoresign.CodeAddressMismatch},
		}
		for _, c := range cases {
			o := base()
			c.fn(&o)
			if _, err := qoresign.VerifySiwq(o); errCode(err) != c.code {
				t.Errorf("%s: got %v, want %s", c.name, err, c.code)
			}
		}
		// within the default 60 s skew
		o := base()
		o.Now = time.Date(2026, 10, 27, 9, 59, 30, 0, time.UTC)
		must(qoresign.VerifySiwq(o))
	})

	t.Run("refuses an altered message or a key that does not own the address", func(t *testing.T) {
		o := base()
		o.Message = strings.Replace(message, "Sign in to the example app.", "Transfer everything.", 1)
		if _, err := qoresign.VerifySiwq(o); errCode(err) != qoresign.CodeClassicalSignatureInvalid {
			t.Fatal(err)
		}
		eth := must(qoresign.DeriveClassicalKey(testMnemonic, qoresign.DeriveClassicalOptions{Type: qoresign.EthSecp256k1}))
		o = base()
		o.Signature.Classical.PublicKey = qoresign.ToBase64(eth.PublicKey)
		if _, err := qoresign.VerifySiwq(o); errCode(err) != qoresign.CodeAddressMismatch {
			t.Fatal(err)
		}
		o.Signature.Classical.PublicKey = qoresign.ToBase64([]byte{1, 2, 3})
		if _, err := qoresign.VerifySiwq(o); errCode(err) != qoresign.CodeAddressMismatch {
			t.Fatal(err)
		}
		if _, err := qoresign.SignSiwq(qoresign.SignSiwqArgs{Message: message, ClassicalKey: eth}); errCode(err) != qoresign.CodeAddressMismatch {
			t.Fatal(err)
		}
	})

	t.Run("classical-only sign-in is refused unless explicitly allowed", func(t *testing.T) {
		sig := must(qoresign.SignSiwq(qoresign.SignSiwqArgs{Message: message, ClassicalKey: testClassical}))
		if sig.SignatureType != qoresign.SiwqSignatureClassical || sig.Pq != nil {
			t.Fatal(sig.SignatureType)
		}
		o := base()
		o.Signature, o.PqPublicKey = sig, nil
		if _, err := qoresign.VerifySiwq(o); errCode(err) != qoresign.CodePqLayerMissing {
			t.Fatal(err)
		}
		no := false
		o.RequirePq = &no
		if out := must(qoresign.VerifySiwq(o)); out.Address != testAccount.Bech32 {
			t.Fatal(out.Address)
		}
	})

	t.Run("works for eth-native accounts", func(t *testing.T) {
		eth := must(qoresign.DeriveClassicalKey(testMnemonic, qoresign.DeriveClassicalOptions{Type: qoresign.EthSecp256k1}))
		ethAddr := must(qoresign.AddressFromPublicKey(eth.PublicKey, qoresign.EthSecp256k1)).Bech32
		ethPq := must(qoresign.DeriveCanonicalPqKey(testMnemonic, ethAddr))
		f := siwqFields()
		f.Address = ethAddr
		msg := must(qoresign.CreateSiwqMessage(f))
		sig := must(qoresign.SignSiwq(qoresign.SignSiwqArgs{Message: msg, ClassicalKey: eth, PqKey: &ethPq}))
		if sig.Classical.KeyType != qoresign.EthSecp256k1 {
			t.Fatal(sig.Classical.KeyType)
		}
		out := must(qoresign.VerifySiwq(qoresign.VerifySiwqOptions{
			Message: msg, Signature: sig, Domain: "app.example.com", Nonce: "a1b2c3d4e5", PqPublicKey: ethPq.PublicKey, Now: siwqNow,
		}))
		if out.Address != ethAddr {
			t.Fatal(out.Address)
		}
	})
}
