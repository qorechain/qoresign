// SPDX-License-Identifier: Apache-2.0

// Package network holds the parts of QoreSign that talk to a QoreChain REST
// endpoint (Cosmos SDK gateway). Everything here is optional; the root
// package signs and verifies offline.
package network

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	pqc "github.com/qorechain/qorechain-pqc/go"
	qoresign "github.com/qorechain/qoresign/go"
)

// DefaultTimeout is the timeout of the HTTP client NewClient creates.
const DefaultTimeout = 30 * time.Second

const maxBody = 32 << 20

// Client talks to one REST endpoint.
type Client struct {
	// REST is the endpoint, e.g. https://api-testnet.qore.host.
	REST string
	// HTTP is the client used for requests; nil uses a client with DefaultTimeout.
	HTTP *http.Client
}

var defaultHTTP = &http.Client{Timeout: DefaultTimeout}

// NewClient returns a Client for rest with a 30-second HTTP timeout.
func NewClient(rest string) *Client {
	return &Client{REST: rest, HTTP: &http.Client{Timeout: DefaultTimeout}}
}

func (c *Client) base() (string, error) {
	if c == nil || c.REST == "" {
		return "", qoresign.NewError(qoresign.CodeInvalidArgument, "a REST endpoint is required", nil)
	}
	return strings.TrimRight(c.REST, "/"), nil
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return defaultHTTP
}

func unavailable(msg string, cause error) error {
	var details map[string]any
	if cause != nil {
		details = map[string]any{"cause": cause.Error()}
	}
	return qoresign.NewError(qoresign.CodeNetworkUnavailable, msg, details)
}

type response struct {
	status int
	body   map[string]any
	raw    []byte
}

func (r response) ok() bool { return r.status >= 200 && r.status < 300 }

// do sends a request and decodes a JSON object body. A body that is not JSON
// reads as empty; for a strict request it is an error on a successful status.
func (c *Client) do(ctx context.Context, method, path string, payload any, what string, strict bool) (response, error) {
	base, err := c.base()
	if err != nil {
		return response{}, err
	}
	var rd io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return response{}, qoresign.NewError(qoresign.CodeInvalidArgument, err.Error(), nil)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, rd)
	if err != nil {
		return response{}, unavailable(what+" failed", err)
	}
	req.Header.Set("accept", "application/json")
	if payload != nil {
		req.Header.Set("content-type", "application/json")
	}
	res, err := c.httpClient().Do(req)
	if err != nil {
		return response{}, unavailable(what+" failed", err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	out := response{status: res.StatusCode, body: map[string]any{}, raw: raw}
	if err != nil {
		return response{}, unavailable(what+" failed", err)
	}
	var decoded any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil {
		if strict && out.ok() {
			return response{}, unavailable(fmt.Sprintf("%s returned a non-JSON body", path), nil)
		}
		return out, nil
	}
	if m, ok := decoded.(map[string]any); ok {
		out.body = m
	}
	return out, nil
}

func (c *Client) get(ctx context.Context, path string) (response, error) {
	return c.do(ctx, http.MethodGet, path, nil, "request to "+path, true)
}

// PqKeyStatus is the ML-DSA-87 key an account has registered on chain.
type PqKeyStatus struct {
	Registered  bool
	AlgorithmID int
	PublicKey   []byte
	// KeyType is hybrid, pqc_only or classical_only.
	KeyType string
	// PossessionProven is true when the key was registered with a proof of possession.
	PossessionProven bool
}

func asString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// asInt reads a JSON number or numeric string; ok is false otherwise.
func asInt(v any) (int64, bool) {
	switch x := v.(type) {
	case json.Number:
		n, err := x.Int64()
		return n, err == nil
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		return n, err == nil
	case float64:
		return int64(x), true
	}
	return 0, false
}

// FetchPqKeyStatus reads /qorechain/pqc/v1/account/{address}.
func (c *Client) FetchPqKeyStatus(ctx context.Context, address string) (PqKeyStatus, error) {
	res, err := c.get(ctx, "/qorechain/pqc/v1/account/"+url.PathEscape(address))
	if err != nil {
		return PqKeyStatus{}, err
	}
	found, hasFound := res.body["found"].(bool)
	if (hasFound && !found) || res.status == http.StatusNotFound {
		return PqKeyStatus{}, nil
	}
	acc, _ := res.body["account"].(map[string]any)
	if res.status >= 400 || !found || acc == nil {
		return PqKeyStatus{}, unavailable(fmt.Sprintf("could not read the PQC key of %s (HTTP %d)", address, res.status), nil)
	}
	out := PqKeyStatus{}
	if s, ok := asString(acc["public_key"]); ok && s != "" {
		pk, err := qoresign.FromBase64(s)
		if err != nil {
			return PqKeyStatus{}, err
		}
		out.PublicKey = pk
		out.Registered = true
	}
	if n, ok := asInt(acc["algorithm_id"]); ok {
		out.AlgorithmID = int(n)
	}
	out.KeyType, _ = asString(acc["key_type"])
	out.PossessionProven, _ = acc["possession_proven"].(bool)
	return out, nil
}

// FetchAppliedPlanHeight returns the height at which an upgrade plan was applied, or 0.
func (c *Client) FetchAppliedPlanHeight(ctx context.Context, name string) (int64, error) {
	res, err := c.get(ctx, "/cosmos/upgrade/v1beta1/applied_plan/"+url.PathEscape(name))
	if err != nil {
		return 0, err
	}
	if res.status >= 400 {
		return 0, unavailable("could not read applied plan "+name, nil)
	}
	s, ok := asString(res.body["height"])
	if !ok || s == "" {
		return 0, nil
	}
	h, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, unavailable("applied plan "+name+" has an invalid height", nil)
	}
	return h, nil
}

// ResolveSignBytesVersion returns the hybrid sign-bytes version the network
// verifies now: v2 once v3.1.98 or v3.2.0 is applied; before that v1 on the
// networks that predate v2 (qorechain-vladi, qorechain-diana) and v2 on any
// other chain.
func (c *Client) ResolveSignBytesVersion(ctx context.Context, chainID string) (qoresign.SignBytesVersion, error) {
	applied := map[string]int64{}
	for _, name := range pqc.SignBytesV2Upgrades {
		h, err := c.FetchAppliedPlanHeight(ctx, name)
		if err != nil {
			return "", err
		}
		applied[name] = h
	}
	if pqc.SignBytesVersionForApplied(chainID, applied) == pqc.SignBytesV1 {
		return qoresign.SignBytesV1, nil
	}
	return qoresign.SignBytesV2, nil
}

// AssertPqLayerArgs are the inputs of AssertPqLayerMatchesRegisteredKey.
type AssertPqLayerArgs struct {
	ChainID       string
	Signer        string
	BodyBytes     []byte
	AuthInfoBytes []byte
}

// AssertPqLayerMatchesRegisteredKey checks a dApp-prepared body's ML-DSA-87
// layer against the key the signer has registered on chain, accepting v1 or
// v2 sign-bytes. It fails when the layer is missing, malformed or invalid,
// when the account has no key, or when the key cannot be read.
func (c *Client) AssertPqLayerMatchesRegisteredKey(ctx context.Context, args AssertPqLayerArgs) (qoresign.PqLayerResult, error) {
	status, err := c.FetchPqKeyStatus(ctx, args.Signer)
	if err != nil {
		return qoresign.PqLayerResult{}, err
	}
	if !status.Registered || len(status.PublicKey) == 0 {
		return qoresign.PqLayerResult{}, qoresign.NewError(qoresign.CodeKeyNotRegistered,
			args.Signer+" has no ML-DSA-87 key on the network", nil)
	}
	result, err := qoresign.VerifyPqLayer(qoresign.VerifyPqLayerArgs{
		ChainID:          args.ChainID,
		BodyBytes:        args.BodyBytes,
		AuthInfoBytes:    args.AuthInfoBytes,
		PqPublicKey:      status.PublicKey,
		SignBytesVersion: qoresign.SignBytesEither,
	})
	if err != nil {
		return qoresign.PqLayerResult{}, err
	}
	if !result.Valid {
		code := qoresign.CodePqSignatureInvalid
		switch result.Reason {
		case qoresign.ReasonMissing:
			code = qoresign.CodePqLayerMissing
		case qoresign.ReasonDuplicated:
			code = qoresign.CodePqLayerDuplicated
		}
		return qoresign.PqLayerResult{}, qoresign.NewError(code,
			fmt.Sprintf("the ML-DSA-87 layer is not valid for %s (%s)", args.Signer, result.Reason),
			map[string]any{"reason": string(result.Reason)})
	}
	return result, nil
}

// SiwqChainResult is a sign-in verified against the chain.
type SiwqChainResult struct {
	qoresign.SiwqFields
	PossessionProven bool
}

// VerifySiwqWithChain is qoresign.VerifySiwq against the ML-DSA-87 key the
// account has registered on chain (opts.PqPublicKey is ignored). The message
// must be for address.
func (c *Client) VerifySiwqWithChain(ctx context.Context, address string, opts qoresign.VerifySiwqOptions) (SiwqChainResult, error) {
	status, err := c.FetchPqKeyStatus(ctx, address)
	if err != nil {
		return SiwqChainResult{}, err
	}
	requirePq := opts.RequirePq == nil || *opts.RequirePq
	if requirePq && !status.Registered {
		return SiwqChainResult{}, qoresign.NewError(qoresign.CodeKeyNotRegistered,
			address+" has no ML-DSA-87 key on the network", nil)
	}
	opts.PqPublicKey = status.PublicKey
	fields, err := qoresign.VerifySiwq(opts)
	if err != nil {
		return SiwqChainResult{}, err
	}
	if fields.Address != address {
		return SiwqChainResult{}, qoresign.NewError(qoresign.CodeAddressMismatch,
			fmt.Sprintf("the message is for %s, not %s", fields.Address, address), nil)
	}
	return SiwqChainResult{SiwqFields: fields, PossessionProven: status.PossessionProven}, nil
}

// MessageChainResult is a message signature verified against the chain.
type MessageChainResult struct {
	PossessionProven bool
}

// VerifyMessageWithChain is qoresign.VerifyMessage against the ML-DSA-87 key
// opts.Signer has registered on chain (opts.PqPublicKey is ignored).
func (c *Client) VerifyMessageWithChain(ctx context.Context, opts qoresign.VerifyMessageOptions) (MessageChainResult, error) {
	status, err := c.FetchPqKeyStatus(ctx, opts.Signer)
	if err != nil {
		return MessageChainResult{}, err
	}
	requirePq := opts.RequirePq == nil || *opts.RequirePq
	if requirePq && !status.Registered {
		return MessageChainResult{}, qoresign.NewError(qoresign.CodeKeyNotRegistered,
			opts.Signer+" has no ML-DSA-87 key on the network", nil)
	}
	opts.PqPublicKey = status.PublicKey
	if err := qoresign.VerifyMessage(opts); err != nil {
		return MessageChainResult{}, err
	}
	return MessageChainResult{PossessionProven: status.PossessionProven}, nil
}

// ChainRefusal is a refusal reported by the network.
type ChainRefusal struct {
	Code      uint32
	Codespace string
	Log       string
}

// EventAttribute is one attribute of an ABCI event.
type EventAttribute struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Event is an ABCI event.
type Event struct {
	Type       string           `json:"type"`
	Attributes []EventAttribute `json:"attributes"`
}

// BalanceDeltas is the net balance change per address and denom.
type BalanceDeltas map[string]map[string]*big.Int

// SimulationResult is the outcome of SimulateTx.
type SimulationResult struct {
	GasUsed uint64
	// SuggestedGasLimit is the gas limit to sign with (see SuggestGasLimit).
	SuggestedGasLimit uint64
	// BalanceDeltas come from the coin_spent / coin_received events.
	BalanceDeltas BalanceDeltas
	Events        []Event
}

// Gas margins of SuggestGasLimit.
const (
	// HybridVerifyGas is the margin older nodes still need on top of the simulated gas of a hybrid transaction.
	HybridVerifyGas            = 40_000
	LegacyGasMultiplierPercent = 140
)

// SuggestGasLimit returns the gas limit for a simulated hybrid transaction.
//
// Nodes from v3.2.5 charge the ML-DSA-87 verification during simulation, so
// the result only needs a small margin: ceil(gasUsed * 1.02) + 2000. Older
// nodes leave part of it out of the simulation: ceil((gasUsed + 40000) * 1.4).
// On the native lane the fee is gas limit times price, so the tighter limit
// is cheaper.
func SuggestGasLimit(gasUsed uint64, exactSimulation bool) uint64 {
	if exactSimulation {
		return (gasUsed*102+99)/100 + 2000
	}
	return ((gasUsed+HybridVerifyGas)*LegacyGasMultiplierPercent + 99) / 100
}

// HasExactSimulation reports whether the node simulates the hybrid
// verification cost exactly (v3.2.5 and later).
func (c *Client) HasExactSimulation(ctx context.Context) (bool, error) {
	h, err := c.FetchAppliedPlanHeight(ctx, "v3.2.5")
	return h > 0, err
}

var refusalRe = regexp.MustCompile(`(?i)codespace[:= ]+(\w+)\s+code[:= ]+(\d+)`)

func parseRefusal(res response) ChainRefusal {
	log, ok := asString(res.body["message"])
	if !ok {
		var buf bytes.Buffer
		if json.Compact(&buf, res.raw) == nil && buf.Len() > 0 && buf.Bytes()[0] == '{' {
			log = buf.String()
		} else {
			b, _ := json.Marshal(res.body)
			log = string(b)
		}
	}
	out := ChainRefusal{Log: log}
	if m := refusalRe.FindStringSubmatch(log); m != nil {
		out.Codespace = m[1]
		if n, err := strconv.ParseUint(m[2], 10, 32); err == nil {
			out.Code = uint32(n)
		}
		return out
	}
	if n, ok := asInt(res.body["code"]); ok && n >= 0 && n <= 0xffffffff {
		out.Code = uint32(n)
	}
	return out
}

var coinRe = regexp.MustCompile(`^(\d+)(.+)$`)

func balanceDeltas(events []Event) BalanceDeltas {
	out := BalanceDeltas{}
	add := func(addr, amounts string, sign int) {
		for _, part := range strings.Split(amounts, ",") {
			m := coinRe.FindStringSubmatch(strings.TrimSpace(part))
			if m == nil {
				continue
			}
			n, ok := new(big.Int).SetString(m[1], 10)
			if !ok {
				continue
			}
			if sign < 0 {
				n.Neg(n)
			}
			if out[addr] == nil {
				out[addr] = map[string]*big.Int{}
			}
			if cur := out[addr][m[2]]; cur != nil {
				cur.Add(cur, n)
			} else {
				out[addr][m[2]] = n
			}
		}
	}
	attr := func(ev Event, k string) string {
		for _, a := range ev.Attributes {
			if a.Key == k {
				return a.Value
			}
		}
		return ""
	}
	for _, ev := range events {
		switch ev.Type {
		case "coin_spent":
			if who, amt := attr(ev, "spender"), attr(ev, "amount"); who != "" && amt != "" {
				add(who, amt, -1)
			}
		case "coin_received":
			if who, amt := attr(ev, "receiver"), attr(ev, "amount"); who != "" && amt != "" {
				add(who, amt, 1)
			}
		}
	}
	return out
}

func decodeEvents(v any) []Event {
	list, _ := v.([]any)
	out := make([]Event, 0, len(list))
	for _, item := range list {
		m, _ := item.(map[string]any)
		if m == nil {
			continue
		}
		ev := Event{}
		ev.Type, _ = asString(m["type"])
		attrs, _ := m["attributes"].([]any)
		for _, a := range attrs {
			am, _ := a.(map[string]any)
			if am == nil {
				continue
			}
			k, _ := asString(am["key"])
			val, _ := asString(am["value"])
			ev.Attributes = append(ev.Attributes, EventAttribute{Key: k, Value: val})
		}
		out = append(out, ev)
	}
	return out
}

// SimulateOptions tune SimulateTx.
type SimulateOptions struct {
	// ExactSimulation overrides the v3.2.5 detection when set.
	ExactSimulation *bool
}

// SimulateTx simulates a signed transaction. A refused simulation returns
// SIMULATION_FAILED with the network's refusal (code, codespace, log) in
// Details; treat it as a reason not to sign, never as a warning. opts may be nil.
func (c *Client) SimulateTx(ctx context.Context, txBytes []byte, opts *SimulateOptions) (SimulationResult, error) {
	res, err := c.do(ctx, http.MethodPost, "/cosmos/tx/v1beta1/simulate",
		map[string]string{"tx_bytes": qoresign.ToBase64(txBytes)}, "simulation request", false)
	if err != nil {
		return SimulationResult{}, err
	}
	if !res.ok() {
		r := parseRefusal(res)
		return SimulationResult{}, qoresign.NewError(qoresign.CodeSimulationFailed, "simulation refused: "+r.Log,
			map[string]any{"code": r.Code, "codespace": r.Codespace, "log": r.Log})
	}
	var gasUsed uint64
	if gi, ok := res.body["gas_info"].(map[string]any); ok && gi["gas_used"] != nil {
		var s string
		switch x := gi["gas_used"].(type) {
		case string:
			s = x
		case json.Number:
			s = x.String()
		}
		n, perr := strconv.ParseUint(s, 10, 64)
		if perr != nil {
			return SimulationResult{}, unavailable("simulation returned an invalid gas_used", nil)
		}
		gasUsed = n
	}
	var events []Event
	if result, ok := res.body["result"].(map[string]any); ok {
		events = decodeEvents(result["events"])
	} else {
		events = []Event{}
	}
	var exact bool
	if opts != nil && opts.ExactSimulation != nil {
		exact = *opts.ExactSimulation
	} else if exact, err = c.HasExactSimulation(ctx); err != nil {
		return SimulationResult{}, err
	}
	return SimulationResult{
		GasUsed:           gasUsed,
		SuggestedGasLimit: SuggestGasLimit(gasUsed, exact),
		BalanceDeltas:     balanceDeltas(events),
		Events:            events,
	}, nil
}

// BroadcastResult is the outcome of BroadcastTx.
type BroadcastResult struct {
	TxHash    string
	Code      uint32
	Codespace string
	Log       string
}

// BroadcastTx broadcasts a transaction in sync mode (it returns after the
// mempool check). A refusal is reported in the result, not as an error.
func (c *Client) BroadcastTx(ctx context.Context, txBytes []byte) (BroadcastResult, error) {
	res, err := c.do(ctx, http.MethodPost, "/cosmos/tx/v1beta1/txs",
		map[string]string{"tx_bytes": qoresign.ToBase64(txBytes), "mode": "BROADCAST_MODE_SYNC"}, "broadcast request", false)
	if err != nil {
		return BroadcastResult{}, err
	}
	tr, _ := res.body["tx_response"].(map[string]any)
	if tr == nil {
		r := parseRefusal(res)
		code := r.Code
		if code == 0 {
			code = 1
		}
		return BroadcastResult{Code: code, Codespace: r.Codespace, Log: r.Log}, nil
	}
	out := BroadcastResult{}
	out.TxHash = stringOf(tr["txhash"])
	if n, ok := asInt(tr["code"]); ok && n >= 0 && n <= 0xffffffff {
		out.Code = uint32(n)
	}
	out.Codespace = stringOf(tr["codespace"])
	out.Log = stringOf(tr["raw_log"])
	return out, nil
}

func stringOf(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case json.Number:
		return x.String()
	default:
		return fmt.Sprint(x)
	}
}

// IsSignBytesRefusal reports the refusal the network gives when the PQC layer
// was signed over the other sign-bytes version (codespace pqc, code 21).
func IsSignBytesRefusal(code uint32, codespace string) bool {
	return codespace == "pqc" && code == 21
}

// SubmitArgs are the inputs of SubmitWithSignBytesFallback.
type SubmitArgs struct {
	ChainID string
	// Sign returns the encoded transaction signed with the given sign-bytes version.
	Sign func(version qoresign.SignBytesVersion) ([]byte, error)
	// SignBytesVersion is the first version to try; empty resolves it from the network.
	SignBytesVersion qoresign.SignBytesVersion
}

// SubmitResult is the outcome of SubmitWithSignBytesFallback.
type SubmitResult struct {
	BroadcastResult
	// SignBytesVersion is the version of the last broadcast.
	SignBytesVersion qoresign.SignBytesVersion
}

// SubmitWithSignBytesFallback broadcasts a hybrid transaction, retrying once
// with the other sign-bytes version when the network refuses the one used.
// Sign is called with the version to use (the sequence is unchanged: a
// refusal at the mempool check does not consume it).
func (c *Client) SubmitWithSignBytesFallback(ctx context.Context, args SubmitArgs) (SubmitResult, error) {
	if args.Sign == nil {
		return SubmitResult{}, qoresign.NewError(qoresign.CodeInvalidArgument, "a sign function is required", nil)
	}
	first := args.SignBytesVersion
	if first == "" {
		v, err := c.ResolveSignBytesVersion(ctx, args.ChainID)
		if err != nil {
			return SubmitResult{}, err
		}
		first = v
	}
	version := first
	send := func(v qoresign.SignBytesVersion) (BroadcastResult, error) {
		tx, err := args.Sign(v)
		if err != nil {
			return BroadcastResult{}, err
		}
		return c.BroadcastTx(ctx, tx)
	}
	res, err := send(version)
	if err != nil {
		return SubmitResult{}, err
	}
	if res.Code != 0 && IsSignBytesRefusal(res.Code, res.Codespace) {
		if first == qoresign.SignBytesV1 {
			version = qoresign.SignBytesV2
		} else {
			version = qoresign.SignBytesV1
		}
		if res, err = send(version); err != nil {
			return SubmitResult{}, err
		}
	}
	return SubmitResult{BroadcastResult: res, SignBytesVersion: version}, nil
}

// FetchCommittedExtensionTypeURLs returns the extension type URLs of a
// committed transaction, for qoresign.EvaluateLayerState: nil when the
// transaction is not found (yet), a non-nil slice otherwise.
func (c *Client) FetchCommittedExtensionTypeURLs(ctx context.Context, txhash string) ([]string, error) {
	res, err := c.get(ctx, "/cosmos/tx/v1beta1/txs/"+url.PathEscape(txhash))
	if err != nil {
		return nil, err
	}
	if res.status == http.StatusNotFound {
		return nil, nil
	}
	if res.status >= 400 {
		return nil, unavailable("could not read transaction "+txhash, nil)
	}
	out := []string{}
	tx, _ := res.body["tx"].(map[string]any)
	body, _ := tx["body"].(map[string]any)
	exts, _ := body["extension_options"].([]any)
	for _, e := range exts {
		m, _ := e.(map[string]any)
		switch {
		case m == nil:
			out = append(out, "")
		case m["@type"] != nil:
			out = append(out, stringOf(m["@type"]))
		default:
			out = append(out, stringOf(m["type_url"]))
		}
	}
	return out, nil
}
