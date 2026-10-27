// SPDX-License-Identifier: Apache-2.0
//
// Registering an account's ML-DSA-87 key (MsgRegisterPQCKeyV2) with a proof
// of possession.

package qoresign

import (
	"strconv"
)

// ProofOfPossessionDomain is the domain of the proof-of-possession message.
const ProofOfPossessionDomain = "qorechain-pqc-pop-v1"

// MsgRegisterPQCKeyV2TypeURL is the type URL of MsgRegisterPQCKeyV2.
const MsgRegisterPQCKeyV2TypeURL = "/qorechain.pqc.v1.MsgRegisterPQCKeyV2"

// ProofOfPossessionMessage returns the message a key signs to prove possession:
// "qorechain-pqc-pop-v1|<chain-id>|<algorithm-id>|<qor1 account>|<lowercase hex public key>".
// Pass AlgorithmMLDSA87 as algorithmID.
func ProofOfPossessionMessage(chainID, account string, algorithmID uint64, publicKey []byte) ([]byte, error) {
	if chainID == "" {
		return nil, errorf(CodeInvalidArgument, "chainId is required")
	}
	acc, err := ParseAddress(account)
	if err != nil {
		return nil, err
	}
	return []byte(ProofOfPossessionDomain + "|" + chainID + "|" + strconv.FormatUint(algorithmID, 10) + "|" +
		acc.Bech32 + "|" + ToHex(publicKey)), nil
}

// SignProofOfPossession signs the proof-of-possession message with pqKey.
func SignProofOfPossession(chainID, account string, pqKey PqKeyPair, hedged bool) ([]byte, error) {
	msg, err := ProofOfPossessionMessage(chainID, account, AlgorithmMLDSA87, pqKey.PublicKey)
	if err != nil {
		return nil, err
	}
	return PqSign(pqKey.SecretKey, msg, hedged)
}

// VerifyProofOfPossession checks a proof of possession. It fails only on an
// invalid chain id or account; a wrong proof returns false.
func VerifyProofOfPossession(chainID, account string, publicKey, proof []byte) (bool, error) {
	msg, err := ProofOfPossessionMessage(chainID, account, AlgorithmMLDSA87, publicKey)
	if err != nil {
		return false, err
	}
	return PqVerify(publicKey, msg, proof), nil
}

// IsDegeneratePqPublicKey reports a public key whose t1 part is all zero: it
// can be forged and is refused by the network.
func IsDegeneratePqPublicKey(publicKey []byte) bool {
	if len(publicKey) != MLDSA87PublicKeyLength {
		return false
	}
	for _, b := range publicKey[32:] {
		if b != 0 {
			return false
		}
	}
	return true
}

// RegisterPqKeyArgs are the inputs of BuildRegisterPqKeyMessage.
type RegisterPqKeyArgs struct {
	ChainID string
	Account string
	PqKey   PqKeyPair
	// ClassicalPublicKey is the 33-byte compressed secp256k1 key of the account.
	ClassicalPublicKey []byte
	Hedged             bool
}

// BuildRegisterPqKeyMessage builds MsgRegisterPQCKeyV2 for the account, with
// the proof of possession and the compressed classical key the network
// checks against the address. Sign the transaction that carries it in
// ModeClassicalOnly.
func BuildRegisterPqKeyMessage(args RegisterPqKeyArgs) (Any, error) {
	acc, err := ParseAddress(args.Account)
	if err != nil {
		return Any{}, err
	}
	if len(args.PqKey.PublicKey) != MLDSA87PublicKeyLength {
		return Any{}, errorf(CodeBadKeyLength, "ML-DSA-87 public key must be %d bytes", MLDSA87PublicKeyLength)
	}
	if IsDegeneratePqPublicKey(args.PqKey.PublicKey) {
		return Any{}, errorf(CodeInvalidArgument, "the public key's t1 part is all zero and would be forgeable")
	}
	owner, err := ClassicalKeyTypeFor(args.ClassicalPublicKey, acc.Bech32)
	if err != nil {
		return Any{}, err
	}
	if owner == "" {
		return Any{}, errorf(CodeAddressMismatch, "the classical public key does not control %s", acc.Bech32)
	}
	proof, err := SignProofOfPossession(args.ChainID, acc.Bech32, args.PqKey, args.Hedged)
	if err != nil {
		return Any{}, err
	}
	value := Concat(
		StringField(1, acc.Bech32),
		LenField(2, args.PqKey.PublicKey),
		VarintField(3, AlgorithmMLDSA87),
		LenField(4, args.ClassicalPublicKey),
		StringField(5, "hybrid"),
		LenField(6, proof),
	)
	return Any{TypeURL: MsgRegisterPQCKeyV2TypeURL, Value: value}, nil
}
