// SPDX-License-Identifier: Apache-2.0
//
// Signing arbitrary messages (the signArbitrary of Keplr-compatible
// wallets): ADR-36 with the classical key, plus ML-DSA-87 over a
// domain-separated encoding. Format: spec/message-signing-v1.md.

package qoresign

// MessageDomain is the domain prefix of the ML-DSA-87 part of a message signature.
const MessageDomain = "qorechain-msg-v1|"

// ReservedPqDomains are the prefixes reserved for ML-DSA-87 signatures on
// QoreChain. Every off-chain signature QoreSign makes starts with its own
// domain, so it can never be mistaken for another one.
var ReservedPqDomains = []string{
	"qorechain-pqc-hybrid-v2",
	"qorechain-pqc-pop-v1|",
	"qorechain:pqc:recovery:v1",
	"qorechain-svm-auth-v2",
	SiwqPqDomain,
	MessageDomain,
}

func checkChainID(chainID string) error {
	if !chainIDRe.MatchString(chainID) {
		return errorf(CodeInvalidArgument, "invalid chain id %q", chainID)
	}
	return nil
}

// MessagePqSignBytes returns the bytes the ML-DSA-87 key signs:
// "qorechain-msg-v1|" + chainID + "|" followed by data.
func MessagePqSignBytes(chainID string, data []byte) ([]byte, error) {
	if err := checkChainID(chainID); err != nil {
		return nil, err
	}
	prefix := MessageDomain + chainID + "|"
	out := make([]byte, 0, len(prefix)+len(data))
	out = append(out, prefix...)
	return append(out, data...), nil
}

// Message signature types.
const (
	// MessageSignatureHybrid carries both parts.
	MessageSignatureHybrid = "ml-dsa-87-hybrid"
	// MessageSignatureClassical is a classical-only signature.
	MessageSignatureClassical = "secp256k1"
)

// MessageClassicalSignature is the classical part of a message signature.
type MessageClassicalSignature struct {
	KeyType ClassicalKeyType `json:"keyType"`
	// PublicKey is the base64 compressed public key.
	PublicKey string `json:"publicKey"`
	// Signature is the base64 64-byte signature over the ADR-36 sign document of the message.
	Signature string `json:"signature"`
}

// MessagePqSignature is the ML-DSA-87 part of a message signature.
type MessagePqSignature struct {
	AlgorithmID int `json:"algorithmId"`
	// Signature is the base64 ML-DSA-87 signature over MessagePqSignBytes.
	Signature string `json:"signature"`
}

// MessageSignature is a message signature, JSON-compatible with the other QoreSign implementations.
type MessageSignature struct {
	// SignatureType is MessageSignatureHybrid or MessageSignatureClassical.
	SignatureType string                    `json:"signatureType"`
	Classical     MessageClassicalSignature `json:"classical"`
	Pq            *MessagePqSignature       `json:"pq,omitempty"`
}

// SignMessageArgs are the inputs of SignMessage.
type SignMessageArgs struct {
	ChainID string
	// Signer is the qor1 account signing.
	Signer       string
	Data         []byte
	ClassicalKey ClassicalKey
	// PqKey is nil for a classical-only signature.
	PqKey  *PqKeyPair
	Hedged bool
}

// SignMessage signs arbitrary data with the account's keys.
func SignMessage(args SignMessageArgs) (MessageSignature, error) {
	addr, err := ParseAddress(args.Signer)
	if err != nil {
		return MessageSignature{}, err
	}
	signer := addr.Bech32
	owner, err := ClassicalKeyTypeFor(args.ClassicalKey.PublicKey, signer)
	if err != nil {
		return MessageSignature{}, err
	}
	if owner == "" {
		return MessageSignature{}, errorf(CodeAddressMismatch, "the classical key does not control %s", signer)
	}
	pqBytes, err := MessagePqSignBytes(args.ChainID, args.Data)
	if err != nil {
		return MessageSignature{}, err
	}
	classical, err := ClassicalSign(args.ClassicalKey, Adr36SignBytes(signer, args.Data))
	if err != nil {
		return MessageSignature{}, err
	}
	out := MessageSignature{
		SignatureType: MessageSignatureClassical,
		Classical: MessageClassicalSignature{
			KeyType:   args.ClassicalKey.Type,
			PublicKey: ToBase64(args.ClassicalKey.PublicKey),
			Signature: ToBase64(classical),
		},
	}
	if args.PqKey != nil {
		sig, err := PqSign(args.PqKey.SecretKey, pqBytes, args.Hedged)
		if err != nil {
			return MessageSignature{}, err
		}
		out.SignatureType = MessageSignatureHybrid
		out.Pq = &MessagePqSignature{AlgorithmID: AlgorithmMLDSA87, Signature: ToBase64(sig)}
	}
	return out, nil
}

// VerifyMessageOptions are the inputs of VerifyMessage.
type VerifyMessageOptions struct {
	ChainID string
	// Signer is the qor1 account that signed.
	Signer    string
	Data      []byte
	Signature MessageSignature
	// PqPublicKey is the ML-DSA-87 key registered on chain for Signer. Required unless RequirePq is false.
	PqPublicKey []byte
	// RequirePq defaults to true (nil): a classical-only signature is refused.
	RequirePq *bool
}

// VerifyMessage verifies a message signature. It fails unless the classical
// key controls Signer, its ADR-36 signature verifies and (unless RequirePq is
// false) the ML-DSA-87 signature verifies under PqPublicKey.
func VerifyMessage(opts VerifyMessageOptions) error {
	addr, err := ParseAddress(opts.Signer)
	if err != nil {
		return err
	}
	signer := addr.Bech32
	pqBytes, err := MessagePqSignBytes(opts.ChainID, opts.Data)
	if err != nil {
		return err
	}
	sig := opts.Signature
	classicalPub, err1 := FromBase64(sig.Classical.PublicKey)
	classicalSig, err2 := FromBase64(sig.Classical.Signature)
	if err1 != nil || err2 != nil {
		return errorf(CodeClassicalSignatureInvalid, "classical signature fields are not base64")
	}
	owner, err := ClassicalKeyTypeFor(classicalPub, signer)
	if err != nil || owner == "" || owner != sig.Classical.KeyType {
		return errorf(CodeAddressMismatch, "the classical key does not control %s", signer)
	}
	if !ClassicalVerify(owner, classicalPub, Adr36SignBytes(signer, opts.Data), classicalSig) {
		return errorf(CodeClassicalSignatureInvalid, "the classical signature does not verify")
	}

	requirePq := opts.RequirePq == nil || *opts.RequirePq
	if sig.Pq == nil {
		if requirePq {
			return errorf(CodePqLayerMissing, "the signature carries no ML-DSA-87 part")
		}
		return nil
	}
	if sig.Pq.AlgorithmID != AlgorithmMLDSA87 {
		return errorf(CodeUnsupportedAlgorithm, "unsupported algorithm %d", sig.Pq.AlgorithmID)
	}
	if len(opts.PqPublicKey) == 0 {
		return errorf(CodeKeyNotRegistered, "pass the account's registered ML-DSA-87 public key")
	}
	pqSig, err := FromBase64(sig.Pq.Signature)
	if err != nil {
		return errorf(CodePqSignatureInvalid, "ML-DSA-87 signature is not base64")
	}
	if !PqVerify(opts.PqPublicKey, pqBytes, pqSig) {
		return errorf(CodePqSignatureInvalid, "the ML-DSA-87 signature does not verify")
	}
	return nil
}
