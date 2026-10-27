// SPDX-License-Identifier: Apache-2.0
//
// Local verification of hybrid transactions, the way the network checks them.

package qoresign

// PqLayerReason says why a PQC layer did not verify.
type PqLayerReason string

const (
	ReasonMissing              PqLayerReason = "missing"
	ReasonDuplicated           PqLayerReason = "duplicated"
	ReasonUnsupportedAlgorithm PqLayerReason = "unsupported_algorithm"
	ReasonEmbeddedKeyMismatch  PqLayerReason = "embedded_key_mismatch"
	ReasonInvalidSignature     PqLayerReason = "invalid_signature"
)

// VerifyPqLayerArgs are the inputs of VerifyPqLayer.
type VerifyPqLayerArgs struct {
	ChainID       string
	BodyBytes     []byte
	AuthInfoBytes []byte
	// PqPublicKey is the account's registered ML-DSA-87 public key.
	PqPublicKey []byte
	// SignBytesVersion defaults to v2. SignBytesEither accepts a signature over v1 or v2 sign-bytes.
	SignBytesVersion SignBytesVersion
}

// PqLayerResult is the outcome of VerifyPqLayer.
type PqLayerResult struct {
	Valid bool
	// SignBytesVersion is the version the signature verified under (set when Valid).
	SignBytesVersion SignBytesVersion
	// Reason is set when not Valid.
	Reason PqLayerReason
}

// VerifyPqLayer checks the ML-DSA-87 layer of a body against a public key. A
// wallet should run it before adding its classical signature to a body a dApp
// prepared: a layer that does not verify protects nothing.
func VerifyPqLayer(args VerifyPqLayerArgs) (PqLayerResult, error) {
	layers, err := PqcLayers(args.BodyBytes)
	if err != nil {
		return PqLayerResult{}, err
	}
	if len(layers) == 0 {
		return PqLayerResult{Reason: ReasonMissing}, nil
	}
	if len(layers) > 1 {
		return PqLayerResult{Reason: ReasonDuplicated}, nil
	}
	layer := layers[0]
	if layer.AlgorithmID != AlgorithmMLDSA87 {
		return PqLayerResult{Reason: ReasonUnsupportedAlgorithm}, nil
	}
	if len(layer.PublicKey) > 0 && !equalBytes(layer.PublicKey, args.PqPublicKey) {
		return PqLayerResult{Reason: ReasonEmbeddedKeyMismatch}, nil
	}
	wanted := args.SignBytesVersion
	if wanted == "" {
		wanted = SignBytesV2
	}
	versions := []SignBytesVersion{wanted}
	if wanted == SignBytesEither {
		versions = []SignBytesVersion{SignBytesV2, SignBytesV1}
	}
	for _, v := range versions {
		msg, err := HybridSignBytes(args.ChainID, args.BodyBytes, args.AuthInfoBytes, v)
		if err != nil {
			return PqLayerResult{}, err
		}
		if PqVerify(args.PqPublicKey, msg, layer.Signature) {
			return PqLayerResult{Valid: true, SignBytesVersion: v}, nil
		}
	}
	return PqLayerResult{Reason: ReasonInvalidSignature}, nil
}

// VerifyHybridTxArgs are the inputs of VerifyHybridTx.
type VerifyHybridTxArgs struct {
	// TxBytes is the encoded TxRaw.
	TxBytes       []byte
	ChainID       string
	AccountNumber uint64
	// ClassicalPublicKey is the compressed secp256k1 public key of the (single) signer.
	ClassicalPublicKey []byte
	// ClassicalKeyType defaults to Secp256k1.
	ClassicalKeyType ClassicalKeyType
	// PqPublicKey is the registered ML-DSA-87 public key; nil checks the classical part only.
	PqPublicKey      []byte
	SignBytesVersion SignBytesVersion
}

// HybridTxResult is the outcome of VerifyHybridTx.
type HybridTxResult struct {
	// Valid is true when every requested check passed.
	Valid     bool
	Classical bool
	// Pq is nil when no PQ key was supplied.
	Pq *PqLayerResult
}

// VerifyHybridTx verifies a single-signer hybrid transaction (both signatures).
func VerifyHybridTx(args VerifyHybridTxArgs) (HybridTxResult, error) {
	tx, err := DecodeTxRaw(args.TxBytes)
	if err != nil {
		return HybridTxResult{}, err
	}
	if len(tx.Signatures) != 1 {
		return HybridTxResult{}, errorf(CodeInvalidArgument,
			"expected one signer, the transaction has %d", len(tx.Signatures))
	}
	t := args.ClassicalKeyType
	if t == "" {
		t = Secp256k1
	}
	signDoc := EncodeSignDoc(tx.BodyBytes, tx.AuthInfoBytes, args.ChainID, args.AccountNumber)
	classical := ClassicalVerify(t, args.ClassicalPublicKey, signDoc, tx.Signatures[0])
	if args.PqPublicKey == nil {
		return HybridTxResult{Valid: classical, Classical: classical}, nil
	}
	pq, err := VerifyPqLayer(VerifyPqLayerArgs{
		ChainID:          args.ChainID,
		BodyBytes:        tx.BodyBytes,
		AuthInfoBytes:    tx.AuthInfoBytes,
		PqPublicKey:      args.PqPublicKey,
		SignBytesVersion: args.SignBytesVersion,
	})
	if err != nil {
		return HybridTxResult{}, err
	}
	return HybridTxResult{Valid: classical && pq.Valid, Classical: classical, Pq: &pq}, nil
}
