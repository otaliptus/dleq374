package dleq

import "errors"

// Proof is a serialized BIP-374 DLEQ proof: e || s.
type Proof [64]byte

var (
	// ErrInvalidScalar indicates the provided secret scalar is zero or not a
	// canonical secp256k1 scalar.
	ErrInvalidScalar = errors.New("dleq: invalid scalar")

	// ErrInvalidPoint indicates a required point input is nil or not on the
	// secp256k1 curve.
	ErrInvalidPoint = errors.New("dleq: invalid point")

	// ErrInvalidGenerator indicates the supplied generator is nil or invalid.
	ErrInvalidGenerator = errors.New("dleq: invalid generator")

	// ErrZeroNonce indicates nonce derivation reduced to zero and proof
	// generation must fail per BIP-374.
	ErrZeroNonce = errors.New("dleq: derived zero nonce")

	// ErrInvalidProofLength indicates the encoded proof is not 64 bytes.
	ErrInvalidProofLength = errors.New("dleq: invalid proof length")

	errGeneratedProofFailedSelfVerify = errors.New("dleq: generated proof failed self-verification")
)

// ParseProof decodes a serialized BIP-374 proof.
func ParseProof(serialized []byte) (Proof, error) {
	var proof Proof
	if len(serialized) != len(proof) {
		return Proof{}, ErrInvalidProofLength
	}

	copy(proof[:], serialized)

	return proof, nil
}
