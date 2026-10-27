// SPDX-License-Identifier: Apache-2.0
//
// Sign In With QoreChain (SIWQ): EIP-4361 / SIWS-style sign-in messages,
// signed with the account's classical key (ADR-36, so any Keplr-compatible
// wallet can produce that part) and with its ML-DSA-87 key.
// Format: spec/siwq-v1.md.

package qoresign

import (
	"regexp"
	"strings"
	"time"
)

// SiwqPqDomain is the domain prefix of the ML-DSA-87 part of a SIWQ signature.
const SiwqPqDomain = "qorechain-siwq-v1|"

const siwqHeader = " wants you to sign in with your QoreChain account:"

// SiwqFields are the fields of a sign-in message. Empty optional fields are absent.
type SiwqFields struct {
	// Domain is the RFC 3986 authority requesting the sign-in, e.g. app.example.com.
	Domain string `json:"domain"`
	// Scheme is optional, e.g. https.
	Scheme string `json:"scheme,omitempty"`
	// Address is the qor1... account.
	Address   string `json:"address"`
	Statement string `json:"statement,omitempty"`
	URI       string `json:"uri"`
	// Version is "1" (empty means "1").
	Version string `json:"version,omitempty"`
	// ChainID is the chain id, e.g. qorechain-vladi.
	ChainID string `json:"chainId"`
	// Nonce is at least 8 alphanumeric characters, chosen by the server.
	Nonce string `json:"nonce"`
	// IssuedAt is an ISO 8601 timestamp.
	IssuedAt       string   `json:"issuedAt"`
	ExpirationTime string   `json:"expirationTime,omitempty"`
	NotBefore      string   `json:"notBefore,omitempty"`
	RequestID      string   `json:"requestId,omitempty"`
	Resources      []string `json:"resources,omitempty"`
}

func siwqCheck(cond bool, msg string) error {
	if !cond {
		return errorf(CodeSiwqMalformed, "%s", msg)
	}
	return nil
}

// isJSSpace matches the characters of the ECMAScript \s class.
func isJSSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

func trimJSSpace(s string) string { return strings.TrimFunc(s, isJSSpace) }

func isURIScheme(s string) bool { return schemeRe.MatchString(s) }

// isURI matches ^[a-zA-Z][a-zA-Z0-9+.-]*:\S+$ (the scheme cannot contain a colon,
// so the first colon ends it).
func isURI(s string) bool {
	i := strings.IndexByte(s, ':')
	if i < 0 || !isURIScheme(s[:i]) {
		return false
	}
	rest := s[i+1:]
	return rest != "" && strings.IndexFunc(rest, isJSSpace) < 0
}

var (
	schemeRe  = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*$`)
	chainIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	nonceRe   = regexp.MustCompile(`^[A-Za-z0-9]{8,}$`)
	isoRe     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$`)
)

func validateSiwq(f SiwqFields) error {
	if f.Domain == "" || strings.IndexFunc(f.Domain, func(r rune) bool { return r == '/' || isJSSpace(r) }) >= 0 {
		return siwqCheck(false, "domain must be a host (and optional port) without spaces or slashes")
	}
	if f.Scheme != "" && !isURIScheme(f.Scheme) {
		return siwqCheck(false, "invalid scheme")
	}
	if _, err := ParseAddress(f.Address); err != nil {
		return err
	}
	checks := []struct {
		ok  bool
		msg string
	}{
		{strings.HasPrefix(f.Address, "qor1"), "address must be the bech32 qor1 form"},
		{!strings.Contains(f.Statement, "\n"), "statement must be a single line"},
		{isURI(f.URI), "uri must be an absolute URI"},
		{f.Version == "" || f.Version == "1", "version must be 1"},
		{chainIDRe.MatchString(f.ChainID), "invalid chain id"},
		{nonceRe.MatchString(f.Nonce), "nonce must be at least 8 alphanumeric characters"},
		{isoRe.MatchString(f.IssuedAt), "issuedAt must be ISO 8601"},
		{f.ExpirationTime == "" || isoRe.MatchString(f.ExpirationTime), "expirationTime must be ISO 8601"},
		{f.NotBefore == "" || isoRe.MatchString(f.NotBefore), "notBefore must be ISO 8601"},
		{!strings.Contains(f.RequestID, "\n"), "requestId must be a single line"},
	}
	for _, c := range checks {
		if err := siwqCheck(c.ok, c.msg); err != nil {
			return err
		}
	}
	for _, r := range f.Resources {
		if err := siwqCheck(isURI(r), "resources must be URIs"); err != nil {
			return err
		}
	}
	return nil
}

// CreateSiwqMessage renders the sign-in message text.
func CreateSiwqMessage(f SiwqFields) (string, error) {
	if err := validateSiwq(f); err != nil {
		return "", err
	}
	var lines []string
	origin := f.Domain
	if f.Scheme != "" {
		origin = f.Scheme + "://" + f.Domain
	}
	lines = append(lines, origin+siwqHeader, f.Address, "")
	if f.Statement != "" {
		lines = append(lines, f.Statement)
	}
	lines = append(lines, "",
		"URI: "+f.URI,
		"Version: 1",
		"Chain ID: "+f.ChainID,
		"Nonce: "+f.Nonce,
		"Issued At: "+f.IssuedAt,
	)
	if f.ExpirationTime != "" {
		lines = append(lines, "Expiration Time: "+f.ExpirationTime)
	}
	if f.NotBefore != "" {
		lines = append(lines, "Not Before: "+f.NotBefore)
	}
	if f.RequestID != "" {
		lines = append(lines, "Request ID: "+f.RequestID)
	}
	if len(f.Resources) > 0 {
		lines = append(lines, "Resources:")
		for _, r := range f.Resources {
			lines = append(lines, "- "+r)
		}
	}
	return strings.Join(lines, "\n"), nil
}

// ParseSiwqMessage parses a sign-in message. The result re-renders to exactly
// the same text; anything else is refused.
func ParseSiwqMessage(text string) (SiwqFields, error) {
	lines := strings.Split(text, "\n")
	i := 0
	line := func(n int) (string, bool) {
		if n < len(lines) {
			return lines[n], true
		}
		return "", false
	}
	header, _ := line(i)
	i++
	if err := siwqCheck(strings.HasSuffix(header, siwqHeader), "missing SIWQ header line"); err != nil {
		return SiwqFields{}, err
	}
	origin := strings.TrimSuffix(header, siwqHeader)
	var scheme string
	if sep := strings.Index(origin, "://"); sep != -1 {
		scheme, origin = origin[:sep], origin[sep+3:]
	}
	address, _ := line(i)
	i++
	if l, ok := line(i); !ok || l != "" {
		return SiwqFields{}, siwqCheck(false, "expected an empty line after the address")
	}
	i++
	var statement string
	if l, ok := line(i); !ok || l != "" {
		statement = l
		i++
	}
	if l, ok := line(i); !ok || l != "" {
		return SiwqFields{}, siwqCheck(false, "expected an empty line before the fields")
	}
	i++
	take := func(label string, optional bool) (string, error) {
		if l, ok := line(i); ok && strings.HasPrefix(l, label+": ") {
			i++
			return l[len(label)+2:], nil
		}
		if !optional {
			return "", siwqCheck(false, `missing "`+label+`"`)
		}
		return "", nil
	}
	var f SiwqFields
	var version string
	var err error
	for _, t := range []struct {
		label    string
		optional bool
		dst      *string
	}{
		{"URI", false, &f.URI},
		{"Version", false, &version},
		{"Chain ID", false, &f.ChainID},
		{"Nonce", false, &f.Nonce},
		{"Issued At", false, &f.IssuedAt},
		{"Expiration Time", true, &f.ExpirationTime},
		{"Not Before", true, &f.NotBefore},
		{"Request ID", true, &f.RequestID},
	} {
		if *t.dst, err = take(t.label, t.optional); err != nil {
			return SiwqFields{}, err
		}
	}
	if l, ok := line(i); ok && l == "Resources:" {
		i++
		f.Resources = []string{}
		for i < len(lines) && strings.HasPrefix(lines[i], "- ") {
			f.Resources = append(f.Resources, lines[i][2:])
			i++
		}
	}
	if err := siwqCheck(i == len(lines), "unexpected trailing content"); err != nil {
		return SiwqFields{}, err
	}
	if err := siwqCheck(version == "1", "version must be 1"); err != nil {
		return SiwqFields{}, err
	}
	f.Domain, f.Scheme, f.Address, f.Statement, f.Version = origin, scheme, address, statement, "1"
	if err := validateSiwq(f); err != nil {
		return SiwqFields{}, err
	}
	again, err := CreateSiwqMessage(f)
	if err != nil {
		return SiwqFields{}, err
	}
	if err := siwqCheck(again == text, "message is not in canonical form"); err != nil {
		return SiwqFields{}, err
	}
	return f, nil
}

// Adr36SignBytes returns the ADR-36 sign document for arbitrary data, as
// Keplr-compatible wallets build it for signArbitrary, serialized with sorted
// keys and no whitespace.
func Adr36SignBytes(signer string, data []byte) []byte {
	return []byte(`{"account_number":"0","chain_id":"","fee":{"amount":[],"gas":"0"},"memo":"",` +
		`"msgs":[{"type":"sign/MsgSignData","value":{"data":"` + ToBase64(data) + `","signer":"` + signer + `"}}],` +
		`"sequence":"0"}`)
}

// SiwqPqSignBytes returns the bytes the ML-DSA-87 key signs for a sign-in message.
func SiwqPqSignBytes(message string) []byte {
	return []byte(SiwqPqDomain + message)
}

// SIWQ signature types.
const (
	// SiwqSignatureHybrid carries both parts.
	SiwqSignatureHybrid = "ml-dsa-87-hybrid"
	// SiwqSignatureClassical is a classical-only sign-in.
	SiwqSignatureClassical = "secp256k1"
)

// SiwqClassicalSignature is the classical part of a SIWQ signature.
type SiwqClassicalSignature struct {
	KeyType ClassicalKeyType `json:"keyType"`
	// PublicKey is the base64 compressed public key.
	PublicKey string `json:"publicKey"`
	// Signature is the base64 64-byte signature over the ADR-36 sign document.
	Signature string `json:"signature"`
}

// SiwqPqSignature is the ML-DSA-87 part of a SIWQ signature.
type SiwqPqSignature struct {
	AlgorithmID int `json:"algorithmId"`
	// Signature is the base64 ML-DSA-87 signature over "qorechain-siwq-v1|" + message.
	Signature string `json:"signature"`
}

// SiwqSignature is a sign-in signature, JSON-compatible with the other QoreSign implementations.
type SiwqSignature struct {
	// SignatureType is SiwqSignatureHybrid or SiwqSignatureClassical.
	SignatureType string                 `json:"signatureType"`
	Classical     SiwqClassicalSignature `json:"classical"`
	Pq            *SiwqPqSignature       `json:"pq,omitempty"`
}

// SignSiwqArgs are the inputs of SignSiwq.
type SignSiwqArgs struct {
	Message      string
	ClassicalKey ClassicalKey
	// PqKey is nil for a classical-only sign-in.
	PqKey  *PqKeyPair
	Hedged bool
}

// SignSiwq signs a sign-in message with the account's keys.
func SignSiwq(args SignSiwqArgs) (SiwqSignature, error) {
	fields, err := ParseSiwqMessage(args.Message)
	if err != nil {
		return SiwqSignature{}, err
	}
	owner, err := ClassicalKeyTypeFor(args.ClassicalKey.PublicKey, fields.Address)
	if err != nil {
		return SiwqSignature{}, err
	}
	if owner == "" {
		return SiwqSignature{}, errorf(CodeAddressMismatch, "the classical key does not control %s", fields.Address)
	}
	classical, err := ClassicalSign(args.ClassicalKey, Adr36SignBytes(fields.Address, []byte(args.Message)))
	if err != nil {
		return SiwqSignature{}, err
	}
	out := SiwqSignature{
		SignatureType: SiwqSignatureClassical,
		Classical: SiwqClassicalSignature{
			KeyType:   args.ClassicalKey.Type,
			PublicKey: ToBase64(args.ClassicalKey.PublicKey),
			Signature: ToBase64(classical),
		},
	}
	if args.PqKey != nil {
		sig, err := PqSign(args.PqKey.SecretKey, SiwqPqSignBytes(args.Message), args.Hedged)
		if err != nil {
			return SiwqSignature{}, err
		}
		out.SignatureType = SiwqSignatureHybrid
		out.Pq = &SiwqPqSignature{AlgorithmID: AlgorithmMLDSA87, Signature: ToBase64(sig)}
	}
	return out, nil
}

// VerifySiwqOptions are the inputs of VerifySiwq.
type VerifySiwqOptions struct {
	Message   string
	Signature SiwqSignature
	// Domain is the domain the server expects (the request's host).
	Domain string
	// Nonce is the nonce the server issued for this sign-in.
	Nonce string
	// ChainID is checked when set.
	ChainID string
	// PqPublicKey is the account's registered ML-DSA-87 public key. Required unless RequirePq is false.
	PqPublicKey []byte
	// RequirePq defaults to true (nil): a classical-only sign-in is refused.
	RequirePq *bool
	// Now defaults to the current time.
	Now time.Time
	// ClockSkew is the allowed skew for issuedAt and notBefore. Zero means
	// the default of 60 seconds; a negative value allows none.
	ClockSkew time.Duration
}

func parseISO(s string) (int64, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return 0, errorf(CodeSiwqMalformed, "invalid timestamp %q", s)
	}
	return t.UnixMilli(), nil
}

// VerifySiwq verifies a sign-in and returns its parsed fields.
func VerifySiwq(opts VerifySiwqOptions) (SiwqFields, error) {
	fields, err := ParseSiwqMessage(opts.Message)
	if err != nil {
		return SiwqFields{}, err
	}
	if fields.Domain != opts.Domain {
		return SiwqFields{}, errorf(CodeSiwqDomainMismatch, "message is for %s, expected %s", fields.Domain, opts.Domain)
	}
	if fields.Nonce != opts.Nonce {
		return SiwqFields{}, errorf(CodeSiwqNonceMismatch, "nonce does not match")
	}
	if opts.ChainID != "" && fields.ChainID != opts.ChainID {
		return SiwqFields{}, errorf(CodeSiwqChainMismatch, "message is for %s, expected %s", fields.ChainID, opts.ChainID)
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	nowMs := now.UnixMilli()
	skew := opts.ClockSkew
	if skew == 0 {
		skew = 60 * time.Second
	} else if skew < 0 {
		skew = 0
	}
	skewMs := skew.Milliseconds()
	if fields.ExpirationTime != "" {
		exp, err := parseISO(fields.ExpirationTime)
		if err != nil {
			return SiwqFields{}, err
		}
		if exp <= nowMs {
			return SiwqFields{}, errorf(CodeSiwqExpired, "the sign-in message has expired")
		}
	}
	if fields.NotBefore != "" {
		nb, err := parseISO(fields.NotBefore)
		if err != nil {
			return SiwqFields{}, err
		}
		if nb > nowMs+skewMs {
			return SiwqFields{}, errorf(CodeSiwqNotYetValid, "the sign-in message is not valid yet")
		}
	}
	issued, err := parseISO(fields.IssuedAt)
	if err != nil {
		return SiwqFields{}, err
	}
	if issued > nowMs+skewMs {
		return SiwqFields{}, errorf(CodeSiwqNotYetValid, "issuedAt is in the future")
	}

	sig := opts.Signature
	classicalPub, err1 := FromBase64(sig.Classical.PublicKey)
	classicalSig, err2 := FromBase64(sig.Classical.Signature)
	if err1 != nil || err2 != nil {
		return SiwqFields{}, errorf(CodeClassicalSignatureInvalid, "classical signature fields are not base64")
	}
	owner, err := ClassicalKeyTypeFor(classicalPub, fields.Address)
	if err != nil || owner == "" || owner != sig.Classical.KeyType {
		return SiwqFields{}, errorf(CodeAddressMismatch, "the classical key does not control %s", fields.Address)
	}
	adr36 := Adr36SignBytes(fields.Address, []byte(opts.Message))
	if !ClassicalVerify(owner, classicalPub, adr36, classicalSig) {
		return SiwqFields{}, errorf(CodeClassicalSignatureInvalid, "the classical signature does not verify")
	}

	requirePq := opts.RequirePq == nil || *opts.RequirePq
	if sig.Pq == nil {
		if requirePq {
			return SiwqFields{}, errorf(CodePqLayerMissing, "the sign-in carries no ML-DSA-87 signature")
		}
		return fields, nil
	}
	if sig.Pq.AlgorithmID != AlgorithmMLDSA87 {
		return SiwqFields{}, errorf(CodeUnsupportedAlgorithm, "unsupported algorithm %d", sig.Pq.AlgorithmID)
	}
	if len(opts.PqPublicKey) == 0 {
		return SiwqFields{}, errorf(CodeKeyNotRegistered, "pass the account's registered ML-DSA-87 public key")
	}
	pqSig, err := FromBase64(sig.Pq.Signature)
	if err != nil {
		return SiwqFields{}, errorf(CodePqSignatureInvalid, "ML-DSA-87 signature is not base64")
	}
	if !PqVerify(opts.PqPublicKey, SiwqPqSignBytes(opts.Message), pqSig) {
		return SiwqFields{}, errorf(CodePqSignatureInvalid, "the ML-DSA-87 signature does not verify")
	}
	return fields, nil
}
