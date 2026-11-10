// SPDX-License-Identifier: Apache-2.0

package network_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	qoresign "github.com/qorechain/qoresign/go"
	"github.com/qorechain/qoresign/go/network"
)

const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

var (
	classical = must(qoresign.DeriveClassicalKey(testMnemonic, qoresign.DeriveClassicalOptions{}))
	address   = must(qoresign.AddressFromPublicKey(classical.PublicKey, qoresign.Secp256k1)).Bech32
	pqKey     = must(qoresign.DeriveCanonicalPqKey(testMnemonic, address))
)

type reply struct {
	status int
	body   any
}

type route func(r *http.Request, body string) reply

// server records "METHOD path" of every request and answers with route.
func server(t *testing.T, rt route) (*network.Client, *[]string) {
	t.Helper()
	var mu sync.Mutex
	calls := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		rep := rt(r, string(b))
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(rep.status)
		switch v := rep.body.(type) {
		case string:
			_, _ = io.WriteString(w, v)
		default:
			_ = json.NewEncoder(w).Encode(v)
		}
	}))
	t.Cleanup(srv.Close)
	c := network.NewClient(srv.URL + "/")
	c.HTTP = srv.Client()
	return c, &calls
}

// features answers the protocol feature query with the sign-bytes v2 switch
// in the given state ("" leaves it out of the list).
func features(enabled any) map[string]any {
	list := []any{map[string]any{"name": "pqc-time-proof", "enabled": true, "known": true, "staged": false}}
	if enabled != "" {
		list = append(list, map[string]any{"name": network.SignBytesV2Feature, "enabled": enabled, "known": true, "staged": false})
	}
	return map[string]any{"features": list, "height": "4200"}
}

// v2Route is accountRoute on a network whose sign-bytes v2 switch is on.
func v2Route(r *http.Request, body string) reply {
	if r.URL.Path == network.ProtocolFeaturesPath {
		return reply{200, features(true)}
	}
	return accountRoute(r, body)
}

func accountRoute(r *http.Request, _ string) reply {
	if strings.HasPrefix(r.URL.Path, "/qorechain/pqc/v1/account/") {
		return reply{200, map[string]any{
			"found": true,
			"account": map[string]any{
				"public_key": qoresign.ToBase64(pqKey.PublicKey), "algorithm_id": 1, "key_type": "hybrid", "possession_proven": true,
			},
		}}
	}
	return reply{404, map[string]any{}}
}

func code(err error) string {
	var e *qoresign.Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err == nil {
		return ""
	}
	return err.Error()
}

var ctx = context.Background()

func TestKeyStatus(t *testing.T) {
	t.Run("reads a registered key", func(t *testing.T) {
		c, calls := server(t, accountRoute)
		s := must(c.FetchPqKeyStatus(ctx, address))
		if !s.Registered || !s.PossessionProven || len(s.PublicKey) != 2592 || s.AlgorithmID != 1 || s.KeyType != "hybrid" {
			t.Fatalf("%+v", s)
		}
		if (*calls)[0] != "GET /qorechain/pqc/v1/account/"+address {
			t.Fatalf("calls %v", *calls)
		}
	})

	t.Run("reports an unregistered account and a broken endpoint differently", func(t *testing.T) {
		c, _ := server(t, func(*http.Request, string) reply { return reply{200, map[string]any{"found": false}} })
		if s := must(c.FetchPqKeyStatus(ctx, address)); s.Registered {
			t.Fatal("registered")
		}
		c, _ = server(t, func(*http.Request, string) reply { return reply{404, "not found"} })
		if s := must(c.FetchPqKeyStatus(ctx, address)); s.Registered {
			t.Fatal("registered")
		}
		c, _ = server(t, func(*http.Request, string) reply { return reply{500, map[string]any{}} })
		if _, err := c.FetchPqKeyStatus(ctx, address); code(err) != qoresign.CodeNetworkUnavailable {
			t.Fatal(err)
		}
		c, _ = server(t, func(*http.Request, string) reply { return reply{200, "<html>"} })
		if _, err := c.FetchPqKeyStatus(ctx, address); code(err) != qoresign.CodeNetworkUnavailable {
			t.Fatal(err)
		}
	})

	t.Run("an unreachable endpoint or a missing one", func(t *testing.T) {
		c := network.NewClient("http://127.0.0.1:1")
		c.HTTP = &http.Client{Timeout: 2 * time.Second}
		_, err := c.FetchPqKeyStatus(ctx, address)
		if code(err) != qoresign.CodeNetworkUnavailable {
			t.Fatal(err)
		}
		var e *qoresign.Error
		if !errors.As(err, &e) || e.Details["cause"] == nil {
			t.Fatal("no cause in details")
		}
		if _, err := network.NewClient("").FetchPqKeyStatus(ctx, address); code(err) != qoresign.CodeInvalidArgument {
			t.Fatal(err)
		}
	})
}

func TestSignBytesVersion(t *testing.T) {
	applied := func(h string) route {
		return func(r *http.Request, _ string) reply {
			if strings.HasSuffix(r.URL.Path, "v3.2.0") {
				return reply{200, map[string]any{"height": h}}
			}
			return reply{200, map[string]any{"height": "0"}}
		}
	}
	for _, c := range []struct {
		chain, height string
		want          qoresign.SignBytesVersion
	}{
		{"qorechain-vladi", "2981742", qoresign.SignBytesV2},
		{"qorechain-vladi", "0", qoresign.SignBytesV1},
		{"my-new-chain", "0", qoresign.SignBytesV2},
	} {
		cl, calls := server(t, applied(c.height))
		if got := must(cl.ResolveSignBytesVersion(ctx, c.chain)); got != c.want {
			t.Errorf("%s at %s: %s", c.chain, c.height, got)
		}
		// The protocol feature query is answered without a feature list, so
		// the version comes from the applied plans.
		if len(*calls) != 3 || (*calls)[0] != "GET "+network.ProtocolFeaturesPath {
			t.Errorf("expected the feature query, then one query per upgrade name, got %v", *calls)
		}
	}
	// testnet took the switch as v3.1.98
	cl, _ := server(t, func(r *http.Request, _ string) reply {
		if strings.HasSuffix(r.URL.Path, "v3.1.98") {
			return reply{200, map[string]any{"height": "100"}}
		}
		return reply{200, map[string]any{"plan": nil}}
	})
	if got := must(cl.ResolveSignBytesVersion(ctx, "qorechain-diana")); got != qoresign.SignBytesV2 {
		t.Error(got)
	}
	cl, _ = server(t, func(*http.Request, string) reply { return reply{500, map[string]any{}} })
	if _, err := cl.ResolveSignBytesVersion(ctx, "qorechain-diana"); code(err) != qoresign.CodeNetworkUnavailable {
		t.Error(err)
	}
}

func TestSignBytesVersionFromProtocolFeature(t *testing.T) {
	// No upgrade plan applied, as on a fresh network that reuses a chain id.
	noPlans := func(feature reply) route {
		return func(r *http.Request, _ string) reply {
			if r.URL.Path == network.ProtocolFeaturesPath {
				return feature
			}
			if strings.Contains(r.URL.Path, "applied_plan") {
				return reply{200, map[string]any{"plan": nil}}
			}
			return reply{404, map[string]any{}}
		}
	}
	for _, c := range []struct {
		name     string
		feature  reply
		want     qoresign.SignBytesVersion
		fallback bool
	}{
		{"enabled switch on a legacy chain id with no plan applied", reply{200, features(true)}, qoresign.SignBytesV2, false},
		{"enabled switch spelled as a string", reply{200, features("true")}, qoresign.SignBytesV2, false},
		{"listed but disabled switch", reply{200, features(false)}, qoresign.SignBytesV1, false},
		{"route not served (404) falls back to the applied plans", reply{404, map[string]any{"code": 5, "message": "Not Implemented"}}, qoresign.SignBytesV1, true},
		{"route not implemented (501) falls back", reply{501, map[string]any{}}, qoresign.SignBytesV1, true},
		{"unreadable answer falls back", reply{200, "not json"}, qoresign.SignBytesV1, true},
		{"answer without a feature list falls back", reply{200, map[string]any{"features": "x"}}, qoresign.SignBytesV1, true},
		{"invalid enabled value falls back", reply{200, features(7)}, qoresign.SignBytesV1, true},
		{"switch not listed means v1, the list is authoritative", reply{200, features("")}, qoresign.SignBytesV1, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			cl, calls := server(t, noPlans(c.feature))
			if got := must(cl.ResolveSignBytesVersion(ctx, "qorechain-diana")); got != c.want {
				t.Errorf("got %s, want %s", got, c.want)
			}
			want := []string{"GET " + network.ProtocolFeaturesPath}
			if c.fallback {
				want = append(want, "GET /cosmos/upgrade/v1beta1/applied_plan/v3.2.0", "GET /cosmos/upgrade/v1beta1/applied_plan/v3.1.98")
			}
			if !reflect.DeepEqual(*calls, want) {
				t.Errorf("calls %v, want %v", *calls, want)
			}
		})
	}

	t.Run("a fallback still reads every applied plan", func(t *testing.T) {
		cl, _ := server(t, func(r *http.Request, _ string) reply {
			if strings.HasSuffix(r.URL.Path, "/v3.2.0") {
				return reply{200, map[string]any{"height": "2981742"}}
			}
			if strings.Contains(r.URL.Path, "applied_plan") {
				return reply{200, map[string]any{"plan": nil}}
			}
			return reply{404, map[string]any{}}
		})
		if got := must(cl.ResolveSignBytesVersion(ctx, "qorechain-vladi")); got != qoresign.SignBytesV2 {
			t.Error(got)
		}
	})

	t.Run("an unreachable node is an error", func(t *testing.T) {
		cl := network.NewClient("http://127.0.0.1:1")
		if _, err := cl.ResolveSignBytesVersion(ctx, "qorechain-diana"); code(err) != qoresign.CodeNetworkUnavailable {
			t.Error(err)
		}
	})
}

func TestSimulation(t *testing.T) {
	events := []map[string]any{
		{"type": "coin_spent", "attributes": []map[string]string{{"key": "spender", "value": "qor1a"}, {"key": "amount", "value": "1500uqor"}}},
		{"type": "coin_received", "attributes": []map[string]string{{"key": "receiver", "value": "qor1b"}, {"key": "amount", "value": "1000uqor"}}},
		{"type": "coin_received", "attributes": []map[string]string{{"key": "receiver", "value": "qor1fee"}, {"key": "amount", "value": "500uqor"}}},
	}

	t.Run("returns gas, a suggested limit and balance deltas", func(t *testing.T) {
		var posted string
		c, calls := server(t, func(r *http.Request, body string) reply {
			if strings.HasSuffix(r.URL.Path, "/simulate") {
				posted = body
				return reply{200, map[string]any{"gas_info": map[string]any{"gas_used": "166300"}, "result": map[string]any{"events": events}}}
			}
			return reply{200, map[string]any{"height": "8890800"}}
		})
		r := must(c.SimulateTx(ctx, []byte{1}, nil))
		if r.GasUsed != 166300 || r.SuggestedGasLimit != 171626 {
			t.Fatalf("%+v", r)
		}
		want := network.BalanceDeltas{
			"qor1a":   {"uqor": big.NewInt(-1500)},
			"qor1b":   {"uqor": big.NewInt(1000)},
			"qor1fee": {"uqor": big.NewInt(500)},
		}
		if !reflect.DeepEqual(r.BalanceDeltas, want) {
			t.Fatalf("deltas %v", r.BalanceDeltas)
		}
		if len(r.Events) != 3 || r.Events[0].Attributes[1].Value != "1500uqor" {
			t.Fatalf("events %+v", r.Events)
		}
		if posted != `{"tx_bytes":"AQ=="}` {
			t.Fatalf("posted %s", posted)
		}
		if !reflect.DeepEqual(*calls, []string{"POST /cosmos/tx/v1beta1/simulate", "GET /cosmos/upgrade/v1beta1/applied_plan/v3.2.5"}) {
			t.Fatalf("calls %v", *calls)
		}
	})

	t.Run("multi-coin amounts accumulate", func(t *testing.T) {
		c, _ := server(t, func(*http.Request, string) reply {
			return reply{200, map[string]any{"gas_info": map[string]any{"gas_used": "1"}, "result": map[string]any{"events": []map[string]any{
				{"type": "coin_spent", "attributes": []map[string]string{{"key": "spender", "value": "qor1a"}, {"key": "amount", "value": "1uqor,2ibc/AB"}}},
				{"type": "coin_spent", "attributes": []map[string]string{{"key": "spender", "value": "qor1a"}, {"key": "amount", "value": "3uqor"}}},
			}}}}
		})
		yes := true
		r := must(c.SimulateTx(ctx, []byte{1}, &network.SimulateOptions{ExactSimulation: &yes}))
		if r.BalanceDeltas["qor1a"]["uqor"].Int64() != -4 || r.BalanceDeltas["qor1a"]["ibc/AB"].Int64() != -2 {
			t.Fatalf("%v", r.BalanceDeltas)
		}
	})

	t.Run("uses the wider margin on nodes before v3.2.5", func(t *testing.T) {
		if network.SuggestGasLimit(129_000, false) != 236_600 || network.SuggestGasLimit(166_300, true) != 171_626 {
			t.Fatal("gas rule")
		}
		if network.SuggestGasLimit(100, true) != 2102 || network.SuggestGasLimit(1, false) != 56002 {
			t.Fatal("rounding")
		}
	})

	t.Run("a refused simulation is an error with the network's reason", func(t *testing.T) {
		c, calls := server(t, func(*http.Request, string) reply {
			return reply{400, map[string]any{"code": 2, "message": "failed to execute message; codespace stakingtier code 12: nothing to claim"}}
		})
		yes := true
		_, err := c.SimulateTx(ctx, []byte{1}, &network.SimulateOptions{ExactSimulation: &yes})
		var e *qoresign.Error
		if !errors.As(err, &e) || e.Code != qoresign.CodeSimulationFailed {
			t.Fatal(err)
		}
		if e.Details["codespace"] != "stakingtier" || e.Details["code"] != uint32(12) {
			t.Fatalf("details %v", e.Details)
		}
		if len(*calls) != 1 {
			t.Fatalf("calls %v", *calls)
		}
		c, _ = server(t, func(*http.Request, string) reply { return reply{500, map[string]any{"code": 13}} })
		_, err = c.SimulateTx(ctx, []byte{1}, &network.SimulateOptions{ExactSimulation: &yes})
		if !errors.As(err, &e) || e.Details["code"] != uint32(13) || e.Details["codespace"] != "" {
			t.Fatalf("%v %v", err, e.Details)
		}
	})
}

func TestBroadcastWithFallback(t *testing.T) {
	t.Run("retries once with the other version after a pqc 21 refusal", func(t *testing.T) {
		var used []qoresign.SignBytesVersion
		n := 0
		c, _ := server(t, func(r *http.Request, body string) reply {
			if !strings.HasSuffix(r.URL.Path, "/txs") {
				return reply{200, map[string]any{"height": "0"}}
			}
			if !strings.Contains(body, `"mode":"BROADCAST_MODE_SYNC"`) {
				return reply{400, map[string]any{"message": "bad mode"}}
			}
			n++
			if n == 1 {
				return reply{200, map[string]any{"tx_response": map[string]any{"txhash": "", "code": 21, "codespace": "pqc", "raw_log": "sign-bytes"}}}
			}
			return reply{200, map[string]any{"tx_response": map[string]any{"txhash": "ABC", "code": 0, "codespace": ""}}}
		})
		res := must(c.SubmitWithSignBytesFallback(ctx, network.SubmitArgs{
			ChainID:          "qorechain-vladi",
			SignBytesVersion: qoresign.SignBytesV1,
			Sign: func(v qoresign.SignBytesVersion) ([]byte, error) {
				used = append(used, v)
				return []byte{1}, nil
			},
		}))
		if !reflect.DeepEqual(used, []qoresign.SignBytesVersion{qoresign.SignBytesV1, qoresign.SignBytesV2}) {
			t.Fatalf("used %v", used)
		}
		if res.TxHash != "ABC" || res.Code != 0 || res.SignBytesVersion != qoresign.SignBytesV2 {
			t.Fatalf("%+v", res)
		}
	})

	t.Run("does not retry other refusals", func(t *testing.T) {
		var used []qoresign.SignBytesVersion
		c, _ := server(t, func(*http.Request, string) reply {
			return reply{200, map[string]any{"tx_response": map[string]any{"txhash": "", "code": 5, "codespace": "sdk", "raw_log": "insufficient funds"}}}
		})
		res := must(c.SubmitWithSignBytesFallback(ctx, network.SubmitArgs{
			ChainID: "qorechain-vladi", SignBytesVersion: qoresign.SignBytesV2,
			Sign: func(v qoresign.SignBytesVersion) ([]byte, error) { used = append(used, v); return []byte{1}, nil },
		}))
		if len(used) != 1 || res.Code != 5 || res.Log != "insufficient funds" || res.SignBytesVersion != qoresign.SignBytesV2 {
			t.Fatalf("%v %+v", used, res)
		}
	})

	t.Run("resolves the version from the network when not given", func(t *testing.T) {
		var used []qoresign.SignBytesVersion
		c, _ := server(t, func(r *http.Request, _ string) reply {
			if strings.Contains(r.URL.Path, "applied_plan") {
				return reply{200, map[string]any{"height": "0"}}
			}
			return reply{200, map[string]any{"tx_response": map[string]any{"txhash": "X", "code": 0}}}
		})
		res := must(c.SubmitWithSignBytesFallback(ctx, network.SubmitArgs{
			ChainID: "qorechain-diana",
			Sign:    func(v qoresign.SignBytesVersion) ([]byte, error) { used = append(used, v); return []byte{1}, nil },
		}))
		if res.SignBytesVersion != qoresign.SignBytesV1 || len(used) != 1 {
			t.Fatalf("%+v %v", res, used)
		}
	})

	t.Run("a gateway error without tx_response is a refusal", func(t *testing.T) {
		c, _ := server(t, func(*http.Request, string) reply {
			return reply{400, map[string]any{"code": 3, "message": "tx parse error"}}
		})
		res := must(c.BroadcastTx(ctx, []byte{1}))
		if res.Code != 3 || res.Log != "tx parse error" {
			t.Fatalf("%+v", res)
		}
		c, _ = server(t, func(*http.Request, string) reply { return reply{502, "bad gateway"} })
		res = must(c.BroadcastTx(ctx, []byte{1}))
		if res.Code != 1 {
			t.Fatalf("%+v", res)
		}
		if !network.IsSignBytesRefusal(21, "pqc") || network.IsSignBytesRefusal(21, "sdk") || network.IsSignBytesRefusal(20, "pqc") {
			t.Fatal("IsSignBytesRefusal")
		}
	})
}

func TestChecksAgainstRegisteredKey(t *testing.T) {
	body := []byte{0x12, 0x01, 0x6d}
	auth := []byte{0x12, 0x00}
	layered := must(qoresign.SignPqLayer(qoresign.SignPqLayerArgs{ChainID: "qorechain-diana", BodyBytes: body, AuthInfoBytes: auth, PqKey: pqKey})).BodyBytes
	args := network.AssertPqLayerArgs{ChainID: "qorechain-diana", Signer: address, BodyBytes: layered, AuthInfoBytes: auth}

	t.Run("accepts a layer made with the registered key and refuses a missing one", func(t *testing.T) {
		c, _ := server(t, v2Route)
		if ok := must(c.AssertPqLayerMatchesRegisteredKey(ctx, args)); !ok.Valid {
			t.Fatal(ok)
		}
		missing := args
		missing.BodyBytes = body
		if _, err := c.AssertPqLayerMatchesRegisteredKey(ctx, missing); code(err) != qoresign.CodePqLayerMissing {
			t.Fatal(err)
		}
		dup := args
		dup.BodyBytes = must(qoresign.AppendExtension(layered, qoresign.Any{TypeURL: qoresign.PqcHybridTypeURL, Value: []byte{8, 1}}))
		if _, err := c.AssertPqLayerMatchesRegisteredKey(ctx, dup); code(err) != qoresign.CodePqLayerDuplicated {
			t.Fatal(err)
		}
		bad := args
		bad.ChainID = "qorechain-vladi"
		_, err := c.AssertPqLayerMatchesRegisteredKey(ctx, bad)
		var e *qoresign.Error
		if !errors.As(err, &e) || e.Code != qoresign.CodePqSignatureInvalid || e.Details["reason"] != "invalid_signature" {
			t.Fatal(err)
		}
		none, _ := server(t, func(*http.Request, string) reply { return reply{200, map[string]any{"found": false}} })
		if _, err := none.AssertPqLayerMatchesRegisteredKey(ctx, args); code(err) != qoresign.CodeKeyNotRegistered {
			t.Fatal(err)
		}
	})

	t.Run("checks only the version the network verifies", func(t *testing.T) {
		v1 := args
		v1.BodyBytes = must(qoresign.SignPqLayer(qoresign.SignPqLayerArgs{
			ChainID: "qorechain-diana", BodyBytes: body, AuthInfoBytes: auth, PqKey: pqKey, SignBytesVersion: qoresign.SignBytesV1,
		})).BodyBytes
		c, _ := server(t, v2Route)
		_, err := c.AssertPqLayerMatchesRegisteredKey(ctx, v1)
		var e *qoresign.Error
		if !errors.As(err, &e) || e.Code != qoresign.CodePqSignatureInvalid || e.Details["reason"] != "invalid_signature" {
			t.Fatalf("a v1 layer on a v2 network: %v", err)
		}

		legacy := v1
		legacy.AllowLegacyEither = true
		if r := must(c.AssertPqLayerMatchesRegisteredKey(ctx, legacy)); !r.Valid || r.SignBytesVersion != qoresign.SignBytesV1 {
			t.Fatalf("legacy option: %+v", r)
		}

		// An explicit version is used as given, without asking the network.
		explicit := v1
		explicit.SignBytesVersion = qoresign.SignBytesV1
		ec, calls := server(t, accountRoute)
		if r := must(ec.AssertPqLayerMatchesRegisteredKey(ctx, explicit)); !r.Valid || r.SignBytesVersion != qoresign.SignBytesV1 {
			t.Fatalf("explicit v1: %+v", r)
		}
		for _, call := range *calls {
			if !strings.Contains(call, "/qorechain/pqc/v1/account/") {
				t.Fatalf("unexpected query %s", call)
			}
		}
		explicit.SignBytesVersion = qoresign.SignBytesV2
		if _, err := ec.AssertPqLayerMatchesRegisteredKey(ctx, explicit); code(err) != qoresign.CodePqSignatureInvalid {
			t.Fatal(err)
		}

		either := v1
		either.SignBytesVersion = qoresign.SignBytesEither
		if _, err := c.AssertPqLayerMatchesRegisteredKey(ctx, either); code(err) != qoresign.CodeInvalidArgument {
			t.Fatal(err)
		}

		// A network that verifies v1 (switch listed but off) accepts the v1 layer.
		off, _ := server(t, func(r *http.Request, b string) reply {
			if r.URL.Path == network.ProtocolFeaturesPath {
				return reply{200, features(false)}
			}
			return accountRoute(r, b)
		})
		if r := must(off.AssertPqLayerMatchesRegisteredKey(ctx, v1)); !r.Valid || r.SignBytesVersion != qoresign.SignBytesV1 {
			t.Fatalf("v1 network: %+v", r)
		}
	})

	t.Run("verifies a sign-in against the chain", func(t *testing.T) {
		message := must(qoresign.CreateSiwqMessage(qoresign.SiwqFields{
			Domain: "app.example.com", Address: address, URI: "https://app.example.com",
			ChainID: "qorechain-diana", Nonce: "noncenonce1", IssuedAt: "2026-10-27T10:00:00Z",
		}))
		signature := must(qoresign.SignSiwq(qoresign.SignSiwqArgs{Message: message, ClassicalKey: classical, PqKey: &pqKey}))
		opts := qoresign.VerifySiwqOptions{
			Message: message, Signature: signature, Domain: "app.example.com", Nonce: "noncenonce1",
			Now: time.Date(2026, 10, 27, 10, 0, 30, 0, time.UTC),
		}
		c, _ := server(t, accountRoute)
		out := must(c.VerifySiwqWithChain(ctx, address, opts))
		if !out.PossessionProven || out.Address != address {
			t.Fatalf("%+v", out)
		}
		other := must(qoresign.DeriveClassicalKey(testMnemonic, qoresign.DeriveClassicalOptions{Index: 1}))
		otherAddr := must(qoresign.AddressFromPublicKey(other.PublicKey, qoresign.Secp256k1)).Bech32
		if _, err := c.VerifySiwqWithChain(ctx, otherAddr, opts); code(err) != qoresign.CodeAddressMismatch {
			t.Fatal(err)
		}
		none, _ := server(t, func(*http.Request, string) reply { return reply{200, map[string]any{"found": false}} })
		if _, err := none.VerifySiwqWithChain(ctx, address, opts); code(err) != qoresign.CodeKeyNotRegistered {
			t.Fatal(err)
		}
	})

	t.Run("verifies a message signature against the chain", func(t *testing.T) {
		data := []byte("Approve export of report 2026-10")
		signature := must(qoresign.SignMessage(qoresign.SignMessageArgs{
			ChainID: "qorechain-diana", Signer: address, Data: data, ClassicalKey: classical, PqKey: &pqKey,
		}))
		opts := qoresign.VerifyMessageOptions{ChainID: "qorechain-diana", Signer: address, Data: data, Signature: signature}
		c, calls := server(t, accountRoute)
		out := must(c.VerifyMessageWithChain(ctx, opts))
		if !out.PossessionProven {
			t.Fatalf("%+v", out)
		}
		if len(*calls) != 1 || !strings.HasSuffix((*calls)[0], "/qorechain/pqc/v1/account/"+address) {
			t.Fatal(*calls)
		}
		wrongChain := opts
		wrongChain.ChainID = "qorechain-vladi"
		if _, err := c.VerifyMessageWithChain(ctx, wrongChain); code(err) != qoresign.CodePqSignatureInvalid {
			t.Fatal(err)
		}
		other := must(qoresign.DeriveClassicalKey(testMnemonic, qoresign.DeriveClassicalOptions{Index: 1}))
		otherAddr := must(qoresign.AddressFromPublicKey(other.PublicKey, qoresign.Secp256k1)).Bech32
		wrongSigner := opts
		wrongSigner.Signer = otherAddr
		if _, err := c.VerifyMessageWithChain(ctx, wrongSigner); code(err) != qoresign.CodeAddressMismatch {
			t.Fatal(err)
		}
		none, _ := server(t, func(*http.Request, string) reply { return reply{200, map[string]any{"found": false}} })
		if _, err := none.VerifyMessageWithChain(ctx, opts); code(err) != qoresign.CodeKeyNotRegistered {
			t.Fatal(err)
		}
		classicalOnly := must(qoresign.SignMessage(qoresign.SignMessageArgs{
			ChainID: "qorechain-diana", Signer: address, Data: data, ClassicalKey: classical,
		}))
		optional := false
		if _, err := none.VerifyMessageWithChain(ctx, qoresign.VerifyMessageOptions{
			ChainID: "qorechain-diana", Signer: address, Data: data, Signature: classicalOnly, RequirePq: &optional,
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCommittedExtensions(t *testing.T) {
	c, _ := server(t, func(r *http.Request, _ string) reply {
		switch {
		case strings.HasSuffix(r.URL.Path, "/ABC"):
			return reply{200, map[string]any{"tx": map[string]any{"body": map[string]any{"extension_options": []map[string]any{
				{"@type": qoresign.PqcHybridTypeURL}, {"type_url": "/x.Y"},
			}}}}}
		case strings.HasSuffix(r.URL.Path, "/NOEXT"):
			return reply{200, map[string]any{"tx": map[string]any{"body": map[string]any{}}}}
		case strings.HasSuffix(r.URL.Path, "/ERR"):
			return reply{500, map[string]any{}}
		}
		return reply{404, map[string]any{"code": 5}}
	})
	got := must(c.FetchCommittedExtensionTypeURLs(ctx, "ABC"))
	if !reflect.DeepEqual(got, []string{qoresign.PqcHybridTypeURL, "/x.Y"}) {
		t.Fatal(got)
	}
	if got := must(c.FetchCommittedExtensionTypeURLs(ctx, "NOEXT")); got == nil || len(got) != 0 {
		t.Fatalf("%#v", got)
	}
	if got := must(c.FetchCommittedExtensionTypeURLs(ctx, "MISSING")); got != nil {
		t.Fatalf("%#v", got)
	}
	if _, err := c.FetchCommittedExtensionTypeURLs(ctx, "ERR"); code(err) != qoresign.CodeNetworkUnavailable {
		t.Fatal(err)
	}
	state := qoresign.EvaluateLayerState(qoresign.LayerStateInput{
		Lane: qoresign.LaneNative, OnQoreChain: true, SignedWithPqLayer: true,
		CommittedExtensionTypeURLs: must(c.FetchCommittedExtensionTypeURLs(ctx, "ABC")),
	})
	if state != qoresign.LayerProtected {
		t.Fatal(state)
	}
}
