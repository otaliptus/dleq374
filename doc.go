// Package dleq implements BIP-374 DLEQ proofs over secp256k1.
//
// WARNING: proof generation currently relies on btcd's variable-time scalar
// multiplication primitives. It is suitable for correctness and interoperability
// work, but callers should not use GenerateProof in environments where
// private-key timing/cache/EM side-channel attackers are in scope.
package dleq
