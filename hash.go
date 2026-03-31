package dleq

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var (
	tagAux       = []byte("BIP0374/aux")
	tagNonce     = []byte("BIP0374/nonce")
	tagChallenge = []byte("BIP0374/challenge")
)

func validatePoint(point *btcec.PublicKey) error {
	if point == nil || !point.IsOnCurve() {
		return ErrInvalidPoint
	}

	return nil
}

func validateGenerator(generator *btcec.PublicKey) error {
	if generator == nil || !generator.IsOnCurve() {
		return ErrInvalidGenerator
	}

	return nil
}

func taggedHash(tag []byte, parts ...[]byte) [32]byte {
	hash := chainhash.TaggedHash(tag, parts...)
	var result [32]byte
	copy(result[:], hash[:])

	return result
}

func xor32(left, right [32]byte) [32]byte {
	var result [32]byte
	for i := range result {
		result[i] = left[i] ^ right[i]
	}

	return result
}

func messageBytes(message *[32]byte) []byte {
	if message == nil {
		return nil
	}

	return message[:]
}

func challengeHash(
	A, B, C, G, R1, R2 *btcec.PublicKey, message *[32]byte,
) [32]byte {
	parts := [][]byte{
		A.SerializeCompressed(),
		B.SerializeCompressed(),
		C.SerializeCompressed(),
		G.SerializeCompressed(),
		R1.SerializeCompressed(),
		R2.SerializeCompressed(),
	}
	if message != nil {
		parts = append(parts, message[:])
	}

	return taggedHash(tagChallenge, parts...)
}

func nonceHash(
	t [32]byte, A, C *btcec.PublicKey, message *[32]byte,
) [32]byte {
	parts := [][]byte{
		t[:],
		A.SerializeCompressed(),
		C.SerializeCompressed(),
	}
	if message != nil {
		parts = append(parts, message[:])
	}

	return taggedHash(tagNonce, parts...)
}

func parseSecretScalar(secret [32]byte) (btcec.ModNScalar, error) {
	var scalar btcec.ModNScalar
	if scalar.SetBytes(&secret) != 0 || scalar.IsZero() {
		return btcec.ModNScalar{}, ErrInvalidScalar
	}

	return scalar, nil
}

func scalarFromHash(hash [32]byte) btcec.ModNScalar {
	var scalar btcec.ModNScalar
	scalar.SetBytes(&hash)

	return scalar
}

// scalarMultiplyNonConst uses btcd's current variable-time scalar
// multiplication primitive.
//
// WARNING: Callers must not use this with secret scalars in environments where
// timing/cache/EM side-channel attackers are in scope.
func scalarMultiplyNonConst(point *btcec.PublicKey, scalar *btcec.ModNScalar) secp.JacobianPoint {
	var (
		pointJacobian  secp.JacobianPoint
		resultJacobian secp.JacobianPoint
	)

	point.AsJacobian(&pointJacobian)
	secp.ScalarMultNonConst(scalar, &pointJacobian, &resultJacobian)

	return resultJacobian
}

func jacobianToPublicKey(point *secp.JacobianPoint) (*btcec.PublicKey, bool) {
	if isInfinity(point) {
		return nil, false
	}

	var affine secp.JacobianPoint
	affine.Set(point)
	affine.ToAffine()

	if isInfinity(&affine) {
		return nil, false
	}

	return btcec.NewPublicKey(&affine.X, &affine.Y), true
}

func isInfinity(point *secp.JacobianPoint) bool {
	return (point.X.IsZero() && point.Y.IsZero()) || point.Z.IsZero()
}

func negatePoint(point *secp.JacobianPoint) secp.JacobianPoint {
	result := *point
	if isInfinity(&result) {
		return result
	}

	result.ToAffine()
	result.Y.Negate(1)
	result.Y.Normalize()

	return result
}

func subtractPoints(left, right *secp.JacobianPoint) secp.JacobianPoint {
	negatedRight := negatePoint(right)

	var result secp.JacobianPoint
	secp.AddNonConst(left, &negatedRight, &result)

	return result
}
