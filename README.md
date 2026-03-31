# dleq374

Go implementation of [BIP-374](https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki) DLEQ proofs over secp256k1.

```bash
go get github.com/otaliptus/dleq374
```

## Usage

```go
import dleq "github.com/otaliptus/dleq374"

// generate
proof, err := dleq.GenerateProof(secret, B, auxRand, G, message)

// verify
ok := dleq.VerifyProof(A, B, C, proof, G, message)
```

A DLEQ proof shows that the same secret scalar `a` was used in both `A = a*G` and `C = a*B`, without revealing `a`. BIP-375 uses this to prove ECDH shares in silent payment PSBTs.

## Warning

Proof generation uses btcd's variable-time scalar multiplication. Do not use `GenerateProof` where private-key side-channel attacks are in scope.

## Test Vectors

Tests run against the [BIP-374 reference vectors](https://github.com/bitcoin/bips/blob/master/bip-0374/reference.py).
