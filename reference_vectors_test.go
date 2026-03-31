package dleq

import (
	"encoding/csv"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

type generateVector struct {
	Index       string
	PointG      string
	ScalarA     string
	PointB      string
	AuxRandR    string
	Message     string
	ResultProof string
	Comment     string
}

type verifyVector struct {
	Index         string
	PointG        string
	PointA        string
	PointB        string
	PointC        string
	Proof         string
	Message       string
	ResultSuccess string
	Comment       string
}

func TestGenerateProofReferenceVectors(t *testing.T) {
	for _, vector := range loadGenerateVectors(t) {
		t.Run(vector.Index+"_"+sanitizeTestName(vector.Comment), func(t *testing.T) {
			B := parsePoint(t, vector.PointB)
			G := parsePoint(t, vector.PointG)
			secret := decode32(t, vector.ScalarA)
			auxRand := decode32(t, vector.AuxRandR)
			message := decodeOptional32(t, vector.Message)

			proof, err := GenerateProof(secret, B, auxRand, G, message)
			if vector.ResultProof == "INVALID" {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, mustDecodeHex(t, vector.ResultProof), proof[:])
		})
	}
}

func TestVerifyProofReferenceVectors(t *testing.T) {
	for _, vector := range loadVerifyVectors(t) {
		t.Run(vector.Index+"_"+sanitizeTestName(vector.Comment), func(t *testing.T) {
			A := parsePoint(t, vector.PointA)
			B := parsePoint(t, vector.PointB)
			C := parsePoint(t, vector.PointC)
			G := parsePoint(t, vector.PointG)
			message := decodeOptional32(t, vector.Message)
			proof, err := ParseProof(mustDecodeHex(t, vector.Proof))
			require.NoError(t, err)

			ok := VerifyProof(A, B, C, proof, G, message)
			require.Equal(t, vector.ResultSuccess == "TRUE", ok)
		})
	}
}

func TestGenerateProofMessageAffectsNonceWithZeroAuxRand(t *testing.T) {
	B := parsePoint(
		t,
		"021cb81121a00f89769903305a367ad3cc02d5b402b12c026e06ac94bde28cd608",
	)
	G := parsePoint(
		t,
		"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
	)
	secret := decode32(
		t,
		"cfb9a7ecc49bea4f2e2ee34c38a6f48b5cd5bd06f4e4d4ffb45905b3d26db842",
	)
	var auxRand [32]byte
	messageOne := decodeOptional32(
		t,
		"22616bb5fb2d7c68270f305122f2a09e833239c4b1c9a04e285119fb606ac794",
	)
	messageTwo := decodeOptional32(
		t,
		"22616bb5fb6d7c68270f305122f2a09e833239c4b1c9a04e285119fb606ac794",
	)

	proofOne, err := GenerateProof(secret, B, auxRand, G, messageOne)
	require.NoError(t, err)

	proofTwo, err := GenerateProof(secret, B, auxRand, G, messageTwo)
	require.NoError(t, err)

	require.NotEqual(t, proofOne, proofTwo)
}

func TestParseProofRejectsWrongLength(t *testing.T) {
	_, err := ParseProof([]byte{0x01, 0x02})
	require.ErrorIs(t, err, ErrInvalidProofLength)
}

func loadGenerateVectors(t *testing.T) []generateVector {
	t.Helper()

	file, err := os.Open(filepath.Join(testdataDir(t), "test_vectors_generate_proof.csv"))
	require.NoError(t, err)
	defer file.Close()

	reader := csv.NewReader(file)
	rows, err := reader.ReadAll()
	require.NoError(t, err)
	require.Len(t, rows, 12)

	var vectors []generateVector
	for i, row := range rows {
		if i == 0 {
			continue
		}

		vectors = append(vectors, generateVector{
			Index:       row[0],
			PointG:      row[1],
			ScalarA:     row[2],
			PointB:      row[3],
			AuxRandR:    row[4],
			Message:     row[5],
			ResultProof: row[6],
			Comment:     row[7],
		})
	}

	return vectors
}

func loadVerifyVectors(t *testing.T) []verifyVector {
	t.Helper()

	file, err := os.Open(filepath.Join(testdataDir(t), "test_vectors_verify_proof.csv"))
	require.NoError(t, err)
	defer file.Close()

	reader := csv.NewReader(file)
	rows, err := reader.ReadAll()
	require.NoError(t, err)
	require.Len(t, rows, 16)

	var vectors []verifyVector
	for i, row := range rows {
		if i == 0 {
			continue
		}

		vectors = append(vectors, verifyVector{
			Index:         row[0],
			PointG:        row[1],
			PointA:        row[2],
			PointB:        row[3],
			PointC:        row[4],
			Proof:         row[5],
			Message:       row[6],
			ResultSuccess: row[7],
			Comment:       row[8],
		})
	}

	return vectors
}

func testdataDir(t *testing.T) string {
	t.Helper()

	_, currentFile, _, ok := runtime.Caller(0)
	require.True(t, ok)

	return filepath.Join(filepath.Dir(currentFile), "testdata")
}

func decode32(t *testing.T, value string) [32]byte {
	t.Helper()

	raw := mustDecodeHex(t, value)
	require.Len(t, raw, 32)

	var result [32]byte
	copy(result[:], raw)

	return result
}

func decodeOptional32(t *testing.T, value string) *[32]byte {
	t.Helper()

	if value == "" {
		return nil
	}

	var result [32]byte
	raw := mustDecodeHex(t, value)
	require.Len(t, raw, 32)
	copy(result[:], raw)

	return &result
}

func parsePoint(t *testing.T, value string) *btcec.PublicKey {
	t.Helper()

	if value == "" || value == "INFINITY" {
		return nil
	}

	point, err := btcec.ParsePubKey(mustDecodeHex(t, value))
	require.NoError(t, err)

	return point
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()

	raw, err := hex.DecodeString(value)
	require.NoError(t, err)

	return raw
}

func sanitizeTestName(name string) string {
	var out []rune
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			out = append(out, r)
		case r >= 'A' && r <= 'Z':
			out = append(out, r)
		case r >= '0' && r <= '9':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}

	return string(out)
}
