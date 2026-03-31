package dleq

import (
	"crypto/subtle"

	"github.com/btcsuite/btcd/btcec/v2"
)

// VerifyProof checks whether proof is a valid BIP-374 proof for the statement
// A = a*G and C = a*B for some secret scalar a.
func VerifyProof(
	A, B, C *btcec.PublicKey, proof Proof, G *btcec.PublicKey,
	message *[32]byte,
) bool {
	if validatePoint(A) != nil ||
		validatePoint(B) != nil ||
		validatePoint(C) != nil ||
		validateGenerator(G) != nil {
		return false
	}

	var eBytes [32]byte
	copy(eBytes[:], proof[:32])

	var sBytes [32]byte
	copy(sBytes[:], proof[32:])

	var s btcec.ModNScalar
	if s.SetBytes(&sBytes) != 0 {
		return false
	}

	eScalar := scalarFromHash(eBytes)

	sG := scalarMultiplyNonConst(G, &s)
	eA := scalarMultiplyNonConst(A, &eScalar)
	R1 := subtractPoints(&sG, &eA)
	if isInfinity(&R1) {
		return false
	}

	sB := scalarMultiplyNonConst(B, &s)
	eC := scalarMultiplyNonConst(C, &eScalar)
	R2 := subtractPoints(&sB, &eC)
	if isInfinity(&R2) {
		return false
	}

	R1Pub, ok := jacobianToPublicKey(&R1)
	if !ok {
		return false
	}
	R2Pub, ok := jacobianToPublicKey(&R2)
	if !ok {
		return false
	}

	expectedChallenge := challengeHash(A, B, C, G, R1Pub, R2Pub, message)

	return subtle.ConstantTimeCompare(eBytes[:], expectedChallenge[:]) == 1
}
