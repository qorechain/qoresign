// SPDX-License-Identifier: Apache-2.0
//
// Hybrid transaction signing for QoreChain's native (Cosmos SDK) lane.
//
// A hybrid transaction carries two signatures:
//  1. an ML-DSA-87 signature over the hybrid sign-bytes, attached to the
//     TxBody as the /qorechain.pqc.v1.PQCHybridSignature extension option;
//  2. the usual secp256k1 SIGN_MODE_DIRECT signature over the FINAL body (the
//     one that carries the extension), in TxRaw.signatures.
//
// Hybrid sign-bytes, where B0 is the body WITHOUT the PQC extension and A the
// auth-info bytes:
//
//	v1: BE32(len B0) || B0 || BE32(len A) || A
//	v2: "qorechain-pqc-hybrid-v2" || BE64(len chainId) || chainId || v1
//
// Both public networks verify v2 since their v3.1.98/v3.2.0 upgrades; v1 is
// only needed to reproduce signatures from before those heights.

package qoresign

import (
	"crypto/sha256"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	pqc "github.com/qorechain/qorechain-pqc/go"
)

// SignBytesVersion names a hybrid sign-bytes form.
type SignBytesVersion string

const (
	SignBytesV1 SignBytesVersion = "v1"
	SignBytesV2 SignBytesVersion = "v2"
	// SignBytesEither is accepted by verification only: a signature over v1 or v2.
	SignBytesEither SignBytesVersion = "either"
)

// PqcHybridTypeURL is the type URL of the PQC extension option.
const PqcHybridTypeURL = "/qorechain.pqc.v1.PQCHybridSignature"

// HybridSignBytes returns the hybrid sign-bytes for bodyBytes (the PQC
// extension is removed first if present). An empty version means v2.
func HybridSignBytes(chainID string, bodyBytes, authInfoBytes []byte, version SignBytesVersion) ([]byte, error) {
	if version == "" {
		version = SignBytesV2
	}
	var v int
	switch version {
	case SignBytesV1:
		v = pqc.SignBytesV1
	case SignBytesV2:
		v = pqc.SignBytesV2
	default:
		return nil, errorf(CodeSignBytesVersionUnknown, "unknown sign-bytes version %q", string(version))
	}
	if chainID == "" {
		return nil, errorf(CodeInvalidArgument, "chainId is required")
	}
	b0, err := StripExtension(bodyBytes, PqcHybridTypeURL)
	if err != nil {
		return nil, err
	}
	out, err := pqc.HybridSignBytes(v, chainID, b0, authInfoBytes)
	if err != nil {
		return nil, errorf(CodeInvalidArgument, "%v", err)
	}
	return out, nil
}

// PqcHybridSignature is qorechain.pqc.v1.PQCHybridSignature.
type PqcHybridSignature struct {
	AlgorithmID uint64
	Signature   []byte
	// PublicKey is set only when the key is embedded for registration on first use.
	PublicKey []byte
}

// EncodePqcHybridSignature encodes a PqcHybridSignature.
func EncodePqcHybridSignature(sig PqcHybridSignature) []byte {
	return Concat(VarintField(1, sig.AlgorithmID), LenField(2, sig.Signature), LenField(3, sig.PublicKey))
}

// DecodePqcHybridSignature decodes a PqcHybridSignature.
func DecodePqcHybridSignature(b []byte) (PqcHybridSignature, error) {
	fields, err := ReadFields(b)
	if err != nil {
		return PqcHybridSignature{}, err
	}
	out := PqcHybridSignature{Signature: []byte{}}
	for _, f := range fields {
		switch {
		case f.Field == 1 && f.WireType == WireVarint:
			out.AlgorithmID = f.Varint
		case f.Field == 2 && f.WireType == WireLen:
			out.Signature = f.Bytes
		case f.Field == 3 && f.WireType == WireLen:
			out.PublicKey = f.Bytes
		}
	}
	return out, nil
}

// PqcLayers returns the PQC layers attached to a body (a valid transaction has exactly one).
func PqcLayers(bodyBytes []byte) ([]PqcHybridSignature, error) {
	exts, err := BodyExtensions(bodyBytes)
	if err != nil {
		return nil, err
	}
	var out []PqcHybridSignature
	for _, a := range exts {
		if a.TypeURL != PqcHybridTypeURL {
			continue
		}
		s, err := DecodePqcHybridSignature(a.Value)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// PqSign returns an ML-DSA-87 signature. It is deterministic unless hedged
// (the network accepts both).
func PqSign(secretKey, message []byte, hedged bool) ([]byte, error) {
	if err := requireLength(secretKey, MLDSA87SecretKeyLength, "ML-DSA-87 secret key"); err != nil {
		return nil, err
	}
	var sig []byte
	var err error
	if hedged {
		sig, err = pqc.MLDSA87.SignHedged(secretKey, message)
	} else {
		sig, err = pqc.MLDSA87.Sign(secretKey, message)
	}
	if err != nil {
		return nil, errorf(CodeInvalidArgument, "ML-DSA-87 signing failed: %v", err)
	}
	return sig, nil
}

// PqVerify verifies an ML-DSA-87 signature. It returns false on malformed input and never panics.
func PqVerify(publicKey, message, signature []byte) (ok bool) {
	if len(publicKey) != MLDSA87PublicKeyLength || len(signature) != MLDSA87SignatureLength {
		return false
	}
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return pqc.MLDSA87.Verify(publicKey, message, signature)
}

func classicalDigest(t ClassicalKeyType, msg []byte) []byte {
	if t == EthSecp256k1 {
		return keccak256(msg)
	}
	h := sha256.Sum256(msg)
	return h[:]
}

// ClassicalSign returns a 64-byte (r || s, low-S, RFC 6979) secp256k1
// signature over the key type's digest of message: SHA-256 for Secp256k1,
// KECCAK-256 for EthSecp256k1.
func ClassicalSign(key ClassicalKey, message []byte) ([]byte, error) {
	if err := requireLength(key.PrivateKey, 32, "secp256k1 private key"); err != nil {
		return nil, err
	}
	var k secp256k1.ModNScalar
	if overflow := k.SetByteSlice(key.PrivateKey); overflow || k.IsZero() {
		return nil, errorf(CodeInvalidArgument, "invalid secp256k1 private key")
	}
	priv := secp256k1.NewPrivateKey(&k)
	defer priv.Zero()
	compact := ecdsa.SignCompact(priv, classicalDigest(key.Type, message), true)
	return compact[1:], nil
}

// ClassicalVerify verifies a 64-byte low-S secp256k1 signature. It returns
// false on malformed input and never panics.
func ClassicalVerify(t ClassicalKeyType, publicKey, message, signature []byte) bool {
	if len(signature) != 64 {
		return false
	}
	pk, err := secp256k1.ParsePubKey(publicKey)
	if err != nil {
		return false
	}
	var r, s secp256k1.ModNScalar
	if r.SetByteSlice(signature[:32]) || s.SetByteSlice(signature[32:]) {
		return false
	}
	if r.IsZero() || s.IsZero() || s.IsOverHalfOrder() {
		return false
	}
	return ecdsa.NewSignature(&r, &s).Verify(classicalDigest(t, message), pk)
}

// SignPqLayerArgs are the inputs of SignPqLayer.
type SignPqLayerArgs struct {
	ChainID string
	// BodyBytes are the body bytes as the dApp built them; an existing PQC layer is replaced.
	BodyBytes        []byte
	AuthInfoBytes    []byte
	PqKey            PqKeyPair
	SignBytesVersion SignBytesVersion
	// IncludePublicKey embeds the public key so the network can register it on first use.
	IncludePublicKey bool
	Hedged           bool
}

// PqLayer is a body carrying an ML-DSA-87 layer.
type PqLayer struct {
	BodyBytes   []byte
	PqSignature []byte
}

// SignPqLayer adds the ML-DSA-87 layer to a transaction body. Use it when the
// classical signature is produced elsewhere (for example by a
// Keplr-compatible wallet's signDirect): the classical signer must sign the
// returned BodyBytes.
func SignPqLayer(args SignPqLayerArgs) (PqLayer, error) {
	b0, err := StripExtension(args.BodyBytes, PqcHybridTypeURL)
	if err != nil {
		return PqLayer{}, err
	}
	msg, err := HybridSignBytes(args.ChainID, b0, args.AuthInfoBytes, args.SignBytesVersion)
	if err != nil {
		return PqLayer{}, err
	}
	sig, err := PqSign(args.PqKey.SecretKey, msg, args.Hedged)
	if err != nil {
		return PqLayer{}, err
	}
	ext := PqcHybridSignature{AlgorithmID: AlgorithmMLDSA87, Signature: sig}
	if args.IncludePublicKey {
		ext.PublicKey = args.PqKey.PublicKey
	}
	body, err := AppendExtension(b0, Any{TypeURL: PqcHybridTypeURL, Value: EncodePqcHybridSignature(ext)})
	if err != nil {
		return PqLayer{}, err
	}
	return PqLayer{BodyBytes: body, PqSignature: sig}, nil
}

// SigningMode selects the signatures SignHybrid produces.
//   - ModeHybrid (default): ML-DSA-87 layer plus secp256k1.
//   - ModeClassicalOnly: no PQC layer, for the transaction that registers the account's PQC key.
//   - ModePqOnly: not accepted by the network for ordinary accounts; refused.
type SigningMode string

const (
	ModeHybrid        SigningMode = "hybrid"
	ModeClassicalOnly SigningMode = "classicalOnly"
	ModePqOnly        SigningMode = "pqOnly"
)

// SignHybridArgs are the inputs of SignHybrid.
type SignHybridArgs struct {
	ChainID       string
	AccountNumber uint64
	BodyBytes     []byte
	AuthInfoBytes []byte
	ClassicalKey  ClassicalKey
	// PqKey is required in ModeHybrid.
	PqKey            *PqKeyPair
	Mode             SigningMode
	SignBytesVersion SignBytesVersion
	IncludePublicKey bool
	Hedged           bool
}

// SignedTx is a signed native-lane transaction.
type SignedTx struct {
	// TxBytes is the encoded TxRaw, ready to broadcast.
	TxBytes            []byte
	BodyBytes          []byte
	AuthInfoBytes      []byte
	ClassicalSignature []byte
	// PqSignature is nil in ModeClassicalOnly.
	PqSignature []byte
}

// SignHybrid signs a native-lane transaction with both keys.
func SignHybrid(args SignHybridArgs) (SignedTx, error) {
	mode := args.Mode
	if mode == "" {
		mode = ModeHybrid
	}
	switch mode {
	case ModeHybrid, ModeClassicalOnly:
	case ModePqOnly:
		return SignedTx{}, errorf(CodeLaneNotAvailable,
			"PQ-only transactions are not accepted for ordinary accounts; use the hybrid mode")
	default:
		return SignedTx{}, errorf(CodeInvalidArgument, "unknown signing mode %q", string(mode))
	}
	body, err := StripExtension(args.BodyBytes, PqcHybridTypeURL)
	if err != nil {
		return SignedTx{}, err
	}
	var pqSig []byte
	if mode == ModeHybrid {
		if args.PqKey == nil {
			return SignedTx{}, errorf(CodeInvalidArgument, "hybrid mode needs PqKey")
		}
		layer, err := SignPqLayer(SignPqLayerArgs{
			ChainID:          args.ChainID,
			BodyBytes:        body,
			AuthInfoBytes:    args.AuthInfoBytes,
			PqKey:            *args.PqKey,
			SignBytesVersion: args.SignBytesVersion,
			IncludePublicKey: args.IncludePublicKey,
			Hedged:           args.Hedged,
		})
		if err != nil {
			return SignedTx{}, err
		}
		body, pqSig = layer.BodyBytes, layer.PqSignature
	}
	signDoc := EncodeSignDoc(body, args.AuthInfoBytes, args.ChainID, args.AccountNumber)
	classical, err := ClassicalSign(args.ClassicalKey, signDoc)
	if err != nil {
		return SignedTx{}, err
	}
	txBytes := EncodeTxRaw(TxRaw{BodyBytes: body, AuthInfoBytes: args.AuthInfoBytes, Signatures: [][]byte{classical}})
	return SignedTx{
		TxBytes:            txBytes,
		BodyBytes:          body,
		AuthInfoBytes:      args.AuthInfoBytes,
		ClassicalSignature: classical,
		PqSignature:        pqSig,
	}, nil
}
