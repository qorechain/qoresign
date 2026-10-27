// SPDX-License-Identifier: Apache-2.0
//
// End-to-end checks against the qorechain-diana testnet. Skipped unless
// QORE_LIVE_TEST=1 and QORE_TEST_MNEMONIC (a funded testnet account) are set.
// QORE_REST and QORE_CHAIN_ID override the endpoint and chain id. Never point
// this at mainnet.

package qoresign_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	qoresign "github.com/qorechain/qoresign/go"
	"github.com/qorechain/qoresign/go/network"
)

type liveEnv struct {
	rest      string
	chainID   string
	client    *network.Client
	address   string
	classical qoresign.ClassicalKey
	pq        qoresign.PqKeyPair
}

func liveSetup(t *testing.T) liveEnv {
	t.Helper()
	mnemonic := os.Getenv("QORE_TEST_MNEMONIC")
	if os.Getenv("QORE_LIVE_TEST") != "1" || mnemonic == "" {
		t.Skip("set QORE_LIVE_TEST=1 and QORE_TEST_MNEMONIC to run the live tests")
	}
	env := liveEnv{rest: os.Getenv("QORE_REST"), chainID: os.Getenv("QORE_CHAIN_ID")}
	if env.rest == "" {
		env.rest = "https://api-testnet.qore.host"
	}
	if env.chainID == "" {
		env.chainID = "qorechain-diana"
	}
	if env.chainID == "qorechain-vladi" {
		t.Fatal("live tests must not run on mainnet")
	}
	env.client = network.NewClient(env.rest)
	classical, err := qoresign.DeriveClassicalKey(mnemonic, qoresign.DeriveClassicalOptions{})
	if err != nil {
		t.Fatal(err)
	}
	env.classical = classical
	env.address = must(qoresign.AddressFromPublicKey(classical.PublicKey, qoresign.Secp256k1)).Bech32
	env.pq = must(qoresign.DeriveCanonicalPqKey(mnemonic, env.address))
	return env
}

func liveGet(ctx context.Context, url string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	res, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		return res.StatusCode, nil
	}
	return res.StatusCode, json.NewDecoder(res.Body).Decode(out)
}

func (e liveEnv) accountInfo(ctx context.Context, t *testing.T) (accountNumber, sequence uint64) {
	t.Helper()
	var body struct {
		Info *struct {
			AccountNumber string `json:"account_number"`
			Sequence      string `json:"sequence"`
		} `json:"info"`
	}
	status, err := liveGet(ctx, e.rest+"/cosmos/auth/v1beta1/account_info/"+e.address, &body)
	if err != nil || status >= 400 || body.Info == nil {
		t.Fatalf("account %s not found (HTTP %d): %v", e.address, status, err)
	}
	accountNumber, _ = strconv.ParseUint(body.Info.AccountNumber, 10, 64)
	sequence, _ = strconv.ParseUint(body.Info.Sequence, 10, 64)
	return accountNumber, sequence
}

func (e liveEnv) waitForTx(ctx context.Context, t *testing.T, txhash string) (gasUsed uint64) {
	t.Helper()
	for i := 0; i < 40; i++ {
		var body struct {
			TxResponse struct {
				GasUsed string `json:"gas_used"`
				Code    uint32 `json:"code"`
				RawLog  string `json:"raw_log"`
			} `json:"tx_response"`
		}
		status, err := liveGet(ctx, e.rest+"/cosmos/tx/v1beta1/txs/"+txhash, &body)
		if err == nil && status == http.StatusOK {
			if body.TxResponse.Code != 0 {
				t.Fatalf("transaction %s failed: %s", txhash, body.TxResponse.RawLog)
			}
			n, _ := strconv.ParseUint(body.TxResponse.GasUsed, 10, 64)
			return n
		}
		time.Sleep(1500 * time.Millisecond)
	}
	t.Fatalf("transaction %s was not committed", txhash)
	return 0
}

func TestLiveCanonicalKeyIsRegistered(t *testing.T) {
	env := liveSetup(t)
	status, err := env.client.FetchPqKeyStatus(context.Background(), env.address)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Registered || qoresign.ToHex(status.PublicKey) != qoresign.ToHex(env.pq.PublicKey) {
		t.Fatalf("the canonical key of %s is not the registered one", env.address)
	}
}

func TestLiveSiwq(t *testing.T) {
	env := liveSetup(t)
	nonce := fmt.Sprintf("livetest%d", time.Now().UnixNano())
	message := must(qoresign.CreateSiwqMessage(qoresign.SiwqFields{
		Domain:   "localhost:3000",
		Address:  env.address,
		URI:      "http://localhost:3000",
		ChainID:  env.chainID,
		Nonce:    nonce,
		IssuedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}))
	signature := must(qoresign.SignSiwq(qoresign.SignSiwqArgs{Message: message, ClassicalKey: env.classical, PqKey: &env.pq}))
	out, err := env.client.VerifySiwqWithChain(context.Background(), env.address, qoresign.VerifySiwqOptions{
		Message:   message,
		Signature: signature,
		Domain:    "localhost:3000",
		Nonce:     nonce,
		ChainID:   env.chainID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !out.PossessionProven {
		t.Fatal("the registered key has no proof of possession")
	}
}

func TestLiveHybridSelfSend(t *testing.T) {
	env := liveSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	msg := qoresign.Any{TypeURL: "/cosmos.bank.v1beta1.MsgSend", Value: msgSend(env.address, env.address, "1")}
	body := qoresign.Concat(qoresign.LenField(1, qoresign.EncodeAny(msg)), qoresign.StringField(2, "qoresign go live test"))
	accountNumber, sequence := env.accountInfo(ctx, t)
	sign := func(gasLimit uint64, version qoresign.SignBytesVersion) ([]byte, error) {
		fee := (gasLimit + 9) / 10 // 0.1 uqor per gas, rounded up
		signed, err := qoresign.SignHybrid(qoresign.SignHybridArgs{
			ChainID:          env.chainID,
			AccountNumber:    accountNumber,
			BodyBytes:        body,
			AuthInfoBytes:    authInfo(env.classical.PublicKey, sequence, gasLimit, strconv.FormatUint(fee, 10)),
			ClassicalKey:     env.classical,
			PqKey:            &env.pq,
			SignBytesVersion: version,
		})
		return signed.TxBytes, err
	}

	version, err := env.client.ResolveSignBytesVersion(ctx, env.chainID)
	if err != nil {
		t.Fatal(err)
	}
	sim, err := env.client.SimulateTx(ctx, must(sign(400_000, version)), nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := env.client.SubmitWithSignBytesFallback(ctx, network.SubmitArgs{
		ChainID:          env.chainID,
		SignBytesVersion: version,
		Sign: func(v qoresign.SignBytesVersion) ([]byte, error) {
			return sign(sim.SuggestedGasLimit, v)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Code != 0 {
		t.Fatalf("broadcast refused: code %d codespace %s: %s", res.Code, res.Codespace, res.Log)
	}
	gasUsed := env.waitForTx(ctx, t, res.TxHash)
	if sim.SuggestedGasLimit < gasUsed {
		t.Fatalf("suggested limit %d below gas used %d", sim.SuggestedGasLimit, gasUsed)
	}
	urls, err := env.client.FetchCommittedExtensionTypeURLs(ctx, res.TxHash)
	if err != nil {
		t.Fatal(err)
	}
	state := qoresign.EvaluateLayerState(qoresign.LayerStateInput{
		Lane: qoresign.LaneNative, OnQoreChain: true, SignedWithPqLayer: true, CommittedExtensionTypeURLs: urls,
	})
	if state != qoresign.LayerProtected {
		t.Fatalf("layer state %s, extensions %s", state, strings.Join(urls, ","))
	}
	t.Logf("hybrid send %s (%s): simulated %d, limit %d, used %d", res.TxHash, res.SignBytesVersion, sim.GasUsed, sim.SuggestedGasLimit, gasUsed)
}
