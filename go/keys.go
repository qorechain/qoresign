// SPDX-License-Identifier: Apache-2.0
//
// Accounts, classical keys and ML-DSA-87 key derivation.

package qoresign

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/cosmos/btcutil/bech32"
	bip39 "github.com/cosmos/go-bip39"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	pqc "github.com/qorechain/qorechain-pqc/go"
	//lint:ignore SA1019 RIPEMD-160 is part of the Cosmos SDK account address format.
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
)

// AccountPrefix is the bech32 prefix of QoreChain accounts.
const AccountPrefix = "qor"

// ML-DSA-87 sizes (FIPS 204, Table 2).
const (
	MLDSA87PublicKeyLength = 2592
	MLDSA87SecretKeyLength = 4896
	MLDSA87SignatureLength = 4627
	MLDSA87SeedLength      = 32
)

// AlgorithmMLDSA87 is the algorithm id of ML-DSA-87 in qorechain.pqc.v1 (named Dilithium5 on chain).
const AlgorithmMLDSA87 = 1

// ClassicalKeyType says how a classical key maps to an account:
//   - Secp256k1: Cosmos SDK accounts, address = RIPEMD160(SHA256(compressed key)), SLIP-44 coin type 118.
//   - EthSecp256k1: eth-native accounts, address = last 20 bytes of KECCAK256(uncompressed key),
//     the same 20 bytes behind the qor1 and 0x forms, coin type 60.
type ClassicalKeyType string

const (
	Secp256k1    ClassicalKeyType = "secp256k1"
	EthSecp256k1 ClassicalKeyType = "eth_secp256k1"
)

// ClassicalKey is a secp256k1 key and the account derivation it uses.
type ClassicalKey struct {
	Type ClassicalKeyType
	// PrivateKey is the 32-byte secp256k1 secret key.
	PrivateKey []byte
	// PublicKey is the 33-byte compressed public key.
	PublicKey []byte
}

// PqKeyPair is an ML-DSA-87 key pair.
type PqKeyPair struct {
	AlgorithmID int
	PublicKey   []byte
	SecretKey   []byte
}

// AccountAddress is an account's address in both forms.
type AccountAddress struct {
	// Bech32 is the qor1... form.
	Bech32 string
	// Hex is the EIP-55 checksummed hex form of the same 20 bytes.
	Hex string
	// Bytes are the raw 20 address bytes.
	Bytes []byte
}

// ClassicalPath is the default HD path of the classical key for account index.
func ClassicalPath(t ClassicalKeyType, index uint32) string {
	if t == EthSecp256k1 {
		return fmt.Sprintf("m/44'/60'/0'/0/%d", index)
	}
	return fmt.Sprintf("m/44'/118'/0'/0/%d", index)
}

func keccak256(data ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

func checksumHex(b []byte) string {
	lower := ToHex(b)
	hash := ToHex(keccak256([]byte(lower)))
	var sb strings.Builder
	sb.WriteString("0x")
	for i := 0; i < len(lower); i++ {
		c := lower[i]
		if hash[i] >= '8' && c >= 'a' && c <= 'f' {
			c -= 'a' - 'A'
		}
		sb.WriteByte(c)
	}
	return sb.String()
}

// AddressFromBytes builds both address forms from 20 address bytes.
func AddressFromBytes(b []byte) (AccountAddress, error) {
	if err := requireLength(b, 20, "address"); err != nil {
		return AccountAddress{}, err
	}
	words, err := bech32.ConvertBits(b, 8, 5, true)
	if err != nil {
		return AccountAddress{}, errorf(CodeInvalidAddress, "cannot encode address: %v", err)
	}
	enc, err := bech32.Encode(AccountPrefix, words)
	if err != nil {
		return AccountAddress{}, errorf(CodeInvalidAddress, "cannot encode address: %v", err)
	}
	return AccountAddress{Bech32: enc, Hex: checksumHex(b), Bytes: clone(b)}, nil
}

var hexAddressRe = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)

// ParseAddress parses a qor1... or 0x... address.
func ParseAddress(address string) (AccountAddress, error) {
	if hexAddressRe.MatchString(address) {
		b, err := FromHex(address)
		if err != nil {
			return AccountAddress{}, err
		}
		return AddressFromBytes(b)
	}
	hrp, words, err := bech32.Decode(address, 90)
	if err != nil {
		return AccountAddress{}, errorf(CodeInvalidAddress, "not a QoreChain address: %q", address)
	}
	if hrp != AccountPrefix {
		return AccountAddress{}, errorf(CodeInvalidAddress, "expected the %q prefix, got %q", AccountPrefix, hrp)
	}
	b, err := bech32.ConvertBits(words, 5, 8, false)
	if err != nil {
		return AccountAddress{}, errorf(CodeInvalidAddress, "not a QoreChain address: %q", address)
	}
	if len(b) != 20 {
		return AccountAddress{}, errorf(CodeInvalidAddress, "account addresses are 20 bytes, got %d", len(b))
	}
	return AddressFromBytes(b)
}

func parsePublicKey(publicKey []byte) (*secp256k1.PublicKey, error) {
	pk, err := secp256k1.ParsePubKey(publicKey)
	if err != nil {
		return nil, errorf(CodeInvalidArgument, "invalid secp256k1 public key: %v", err)
	}
	return pk, nil
}

// AddressFromPublicKey returns the account a classical public key controls.
func AddressFromPublicKey(publicKey []byte, t ClassicalKeyType) (AccountAddress, error) {
	pk, err := parsePublicKey(publicKey)
	if err != nil {
		return AccountAddress{}, err
	}
	if t == EthSecp256k1 {
		return AddressFromBytes(keccak256(pk.SerializeUncompressed()[1:])[12:])
	}
	sha := sha256.Sum256(pk.SerializeCompressed())
	r := ripemd160.New()
	r.Write(sha[:])
	return AddressFromBytes(r.Sum(nil))
}

// ClassicalKeyTypeFor returns which derivation a public key uses for address,
// or "" when the key belongs to neither. It fails on an invalid address or key.
func ClassicalKeyTypeFor(publicKey []byte, address string) (ClassicalKeyType, error) {
	target, err := ParseAddress(address)
	if err != nil {
		return "", err
	}
	for _, t := range []ClassicalKeyType{Secp256k1, EthSecp256k1} {
		a, err := AddressFromPublicKey(publicKey, t)
		if err != nil {
			return "", err
		}
		if equalBytes(a.Bytes, target.Bytes) {
			return t, nil
		}
	}
	return "", nil
}

// checkMnemonic accepts only the canonical form (lowercase words, single
// spaces, nothing around them): the mnemonic is part of the canonical
// derivation input, so a different spacing would silently give a different key.
func checkMnemonic(mnemonic string) (string, error) {
	if strings.Join(strings.Fields(mnemonic), " ") != mnemonic {
		return "", errorf(CodeInvalidMnemonic,
			"pass the mnemonic in canonical form: words separated by single spaces, no surrounding whitespace")
	}
	if _, err := bip39.MnemonicToByteArray(mnemonic); err != nil {
		return "", errorf(CodeInvalidMnemonic, "the mnemonic is not a valid BIP-39 English phrase")
	}
	return mnemonic, nil
}

// DeriveClassicalOptions selects the classical key to derive.
type DeriveClassicalOptions struct {
	// Type defaults to Secp256k1.
	Type ClassicalKeyType
	// Index is the account index on the default path; ignored when Path is set.
	Index uint32
	// Path overrides the default BIP-44 path.
	Path string
	// Passphrase is the optional BIP-39 passphrase.
	Passphrase string
}

const hardened = 0x80000000

func parseBip32Path(path string) ([]uint32, error) {
	parts := strings.Split(path, "/")
	if parts[0] != "m" && parts[0] != "M" {
		return nil, errorf(CodeHDInvalidPath, "path must start with \"m\": %s", path)
	}
	out := make([]uint32, 0, len(parts)-1)
	for _, p := range parts[1:] {
		var off uint32
		if strings.HasSuffix(p, "'") {
			off = hardened
			p = p[:len(p)-1]
		}
		if p == "" || strings.Trim(p, "0123456789") != "" {
			return nil, errorf(CodeHDInvalidPath, "invalid path segment %q", p)
		}
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil || n >= hardened {
			return nil, errorf(CodeHDInvalidPath, "path index out of range: %s", p)
		}
		out = append(out, uint32(n)+off)
	}
	return out, nil
}

// bip32Derive is standard BIP-32 private derivation on secp256k1.
func bip32Derive(seed []byte, path []uint32) ([]byte, error) {
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	mac.Write(seed)
	I := mac.Sum(nil)
	var k secp256k1.ModNScalar
	if overflow := k.SetByteSlice(I[:32]); overflow || k.IsZero() {
		return nil, errorf(CodeInvalidArgument, "derivation produced no private key")
	}
	chain := I[32:]
	for _, idx := range path {
		var data []byte
		if idx >= hardened {
			kb := k.Bytes()
			data = append([]byte{0}, kb[:]...)
		} else {
			data = secp256k1.NewPrivateKey(&k).PubKey().SerializeCompressed()
		}
		data = binary.BigEndian.AppendUint32(data, idx)
		mac := hmac.New(sha512.New, chain)
		mac.Write(data)
		I = mac.Sum(nil)
		var il secp256k1.ModNScalar
		if overflow := il.SetByteSlice(I[:32]); overflow {
			return nil, errorf(CodeInvalidArgument, "derivation produced no private key")
		}
		k.Add(&il)
		if k.IsZero() {
			return nil, errorf(CodeInvalidArgument, "derivation produced no private key")
		}
		chain = I[32:]
	}
	kb := k.Bytes()
	return kb[:], nil
}

// DeriveClassicalKey derives the classical key at a BIP-32/BIP-44 path from a BIP-39 mnemonic.
func DeriveClassicalKey(mnemonic string, opts DeriveClassicalOptions) (ClassicalKey, error) {
	t := opts.Type
	if t == "" {
		t = Secp256k1
	}
	m, err := checkMnemonic(mnemonic)
	if err != nil {
		return ClassicalKey{}, err
	}
	path := opts.Path
	if path == "" {
		path = ClassicalPath(t, opts.Index)
	}
	indexes, err := parseBip32Path(path)
	if err != nil {
		return ClassicalKey{}, err
	}
	priv, err := bip32Derive(bip39.NewSeed(m, opts.Passphrase), indexes)
	if err != nil {
		return ClassicalKey{}, err
	}
	return ClassicalKeyFromPrivate(priv, t)
}

// ClassicalKeyFromPrivate wraps an existing secp256k1 secret key.
func ClassicalKeyFromPrivate(privateKey []byte, t ClassicalKeyType) (ClassicalKey, error) {
	if err := requireLength(privateKey, 32, "secp256k1 private key"); err != nil {
		return ClassicalKey{}, err
	}
	if t == "" {
		t = Secp256k1
	}
	var k secp256k1.ModNScalar
	if overflow := k.SetByteSlice(privateKey); overflow || k.IsZero() {
		return ClassicalKey{}, errorf(CodeInvalidArgument, "invalid secp256k1 private key")
	}
	pub := secp256k1.NewPrivateKey(&k).PubKey().SerializeCompressed()
	return ClassicalKey{Type: t, PrivateKey: clone(privateKey), PublicKey: pub}, nil
}

// PqKeyFromSeed returns the key pair of a 32-byte ML-DSA-87 seed (FIPS 204 ML-DSA.KeyGen_internal).
func PqKeyFromSeed(seed []byte) (PqKeyPair, error) {
	if err := requireLength(seed, MLDSA87SeedLength, "ML-DSA-87 seed"); err != nil {
		return PqKeyPair{}, err
	}
	pub, sec, err := pqc.MLDSA87.KeygenFromSeed(seed)
	if err != nil {
		return PqKeyPair{}, errorf(CodeInvalidArgument, "ML-DSA-87 key generation failed: %v", err)
	}
	return PqKeyPair{AlgorithmID: AlgorithmMLDSA87, PublicKey: pub, SecretKey: sec}, nil
}

// CanonicalDerivationDomain is the domain of the canonical derivation.
const CanonicalDerivationDomain = "qorechain:pqc:v1"

// DeriveCanonicalPqKey returns the canonical ML-DSA-87 key of an account: the
// seed is SHAKE256("qorechain:pqc:v1|" + bech32Address + "|" + mnemonic, 32 bytes).
//
// This is the key QoreChain wallets and the QoreChain SDK derive today, so a
// wallet using it signs with the key that is already registered for the
// account. The key is bound to the address: the same mnemonic gives a
// different key for every account.
func DeriveCanonicalPqKey(mnemonic, address string) (PqKeyPair, error) {
	m, err := checkMnemonic(mnemonic)
	if err != nil {
		return PqKeyPair{}, err
	}
	account, err := ParseAddress(address)
	if err != nil {
		return PqKeyPair{}, err
	}
	seed := make([]byte, MLDSA87SeedLength)
	h := sha3.NewShake256()
	h.Write([]byte(CanonicalDerivationDomain + "|" + account.Bech32 + "|" + m))
	_, _ = h.Read(seed)
	return PqKeyFromSeed(seed)
}

// HDMasterKey is the HMAC key of the hardened-only HD derivation (draft).
const HDMasterKey = "qorechain-mldsa87-seed"

var digitsRe = regexp.MustCompile(`^\d+$`)

func parseHardenedPath(path string) ([]uint32, error) {
	parts := strings.Split(trimJSSpace(path), "/")
	if parts[0] != "m" {
		return nil, errorf(CodeHDInvalidPath, "path must start with \"m\": %s", path)
	}
	out := make([]uint32, 0, len(parts)-1)
	for _, p := range parts[1:] {
		if !strings.HasSuffix(p, "'") || !digitsRe.MatchString(p[:len(p)-1]) {
			if digitsRe.MatchString(p) {
				return nil, errorf(CodeHDNonHardened,
					"segment %q is not hardened; ML-DSA has no public child derivation, so every segment must be hardened", p)
			}
			return nil, errorf(CodeHDInvalidPath, "invalid path segment %q", p)
		}
		n, err := strconv.ParseUint(p[:len(p)-1], 10, 32)
		if err != nil || n >= hardened {
			return nil, errorf(CodeHDInvalidPath, "path index out of range: %s", p)
		}
		out = append(out, uint32(n)+hardened)
	}
	return out, nil
}

// DeriveHdOptions are the inputs of DeriveHdPqKey: a mnemonic or a raw seed, and a path.
type DeriveHdOptions struct {
	Mnemonic string
	// Seed is used instead of Mnemonic when set (16 to 64 bytes).
	Seed       []byte
	Path       string
	Passphrase string
}

// DeriveHdPqKey is the DRAFT hardened-only hierarchical derivation of
// ML-DSA-87 keys (see spec/hd-derivation-draft.md). Opt-in; the format may
// change before it is final.
//
// It uses the SLIP-10 construction with its own master key string:
// I = HMAC-SHA512("qorechain-mldsa87-seed", seed), then for each hardened
// index I = HMAC-SHA512(chainCode, 0x00 || k || ser32(i)). The ML-DSA-87
// seed is the final 32-byte k.
//
// Unlike DeriveCanonicalPqKey, the key is not bound to an address: it must be
// registered on chain for the account that will use it.
func DeriveHdPqKey(opts DeriveHdOptions) (PqKeyPair, error) {
	seed := opts.Seed
	if seed == nil {
		if opts.Mnemonic == "" {
			return PqKeyPair{}, errorf(CodeInvalidArgument, "a mnemonic or a seed is required")
		}
		m, err := checkMnemonic(opts.Mnemonic)
		if err != nil {
			return PqKeyPair{}, err
		}
		seed = bip39.NewSeed(m, opts.Passphrase)
	}
	if len(seed) < 16 || len(seed) > 64 {
		return PqKeyPair{}, errorf(CodeInvalidArgument, "seed must be 16 to 64 bytes")
	}
	indexes, err := parseHardenedPath(opts.Path)
	if err != nil {
		return PqKeyPair{}, err
	}
	mac := hmac.New(sha512.New, []byte(HDMasterKey))
	mac.Write(seed)
	I := mac.Sum(nil)
	k, c := I[:32], I[32:]
	for _, i := range indexes {
		data := make([]byte, 0, 37)
		data = append(data, 0)
		data = append(data, k...)
		data = binary.BigEndian.AppendUint32(data, i)
		mac := hmac.New(sha512.New, c)
		mac.Write(data)
		I = mac.Sum(nil)
		k, c = I[:32], I[32:]
	}
	return PqKeyFromSeed(k)
}

// DefaultHdPath is the default draft HD path for account index.
func DefaultHdPath(index, coinType uint32) string {
	return fmt.Sprintf("m/44'/%d'/%d'/0'/0'", coinType, index)
}
