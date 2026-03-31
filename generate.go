package dleq

import "github.com/btcsuite/btcd/btcec/v2"

// GenerateProof constructs a BIP-374 DLEQ proof for the statement
// A = a*G and C = a*B, where secret is the 32-byte big-endian encoding of a.
//
// WARNING: proof generation currently uses btcd's variable-time scalar
// multiplication internally. It must not be used where private-key
// side-channel attacks are in scope.
func GenerateProof(
	secret [32]byte, B *btcec.PublicKey, auxRand [32]byte,
	G *btcec.PublicKey, message *[32]byte,
) (Proof, error) {
	if err := validatePoint(B); err != nil {
		return Proof{}, err
	}
	if err := validateGenerator(G); err != nil {
		return Proof{}, err
	}

	a, err := parseSecretScalar(secret)
	if err != nil {
		return Proof{}, err
	}

	AJacobian := scalarMultiplyNonConst(G, &a)
	A, ok := jacobianToPublicKey(&AJacobian)
	if !ok {
		return Proof{}, ErrInvalidGenerator
	}

	CJacobian := scalarMultiplyNonConst(B, &a)
	C, ok := jacobianToPublicKey(&CJacobian)
	if !ok {
		return Proof{}, ErrInvalidPoint
	}

	t := xor32(secret, taggedHash(tagAux, auxRand[:]))
	nonceInput := nonceHash(t, A, C, message)

	var k btcec.ModNScalar
	k.SetBytes(&nonceInput)
	if k.IsZero() {
		return Proof{}, ErrZeroNonce
	}

	R1Jacobian := scalarMultiplyNonConst(G, &k)
	R1, ok := jacobianToPublicKey(&R1Jacobian)
	if !ok {
		return Proof{}, ErrInvalidGenerator
	}

	R2Jacobian := scalarMultiplyNonConst(B, &k)
	R2, ok := jacobianToPublicKey(&R2Jacobian)
	if !ok {
		return Proof{}, ErrInvalidPoint
	}

	eBytes := challengeHash(A, B, C, G, R1, R2, message)
	eScalar := scalarFromHash(eBytes)

	var s btcec.ModNScalar
	s.Mul2(&eScalar, &a)
	s.Add(&k)

	var proof Proof
	copy(proof[:32], eBytes[:])
	sBytes := s.Bytes()
	copy(proof[32:], sBytes[:])

	if !VerifyProof(A, B, C, proof, G, message) {
		return Proof{}, errGeneratedProofFailedSelfVerify
	}

	return proof, nil
}
