package bip375_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	psbt "github.com/otaliptus/psbt-v2"
)

type testVectors struct {
	Version string          `json:"version"`
	Invalid []invalidVector `json:"invalid"`
	Valid   []validVector   `json:"valid"`
}

type invalidVector struct {
	Description string `json:"description"`
	PSBT        string `json:"psbt"`
}

type validVector struct {
	Description string `json:"description"`
	PSBT        string `json:"psbt"`
}

var structuralInvalidDescriptions = map[string]bool{
	"psbt structure: missing PSBT_OUT_SP_V0_INFO field when PSBT_OUT_SP_V0_LABEL set": true,
	"psbt structure: incorrect byte length for PSBT_OUT_SP_V0_INFO field":             true,
	"psbt structure: incorrect byte length for PSBT_IN_SP_ECDH_SHARE field":           true,
	"psbt structure: incorrect byte length for PSBT_IN_SP_DLEQ field":                 true,
	"psbt structure: missing PSBT_OUT_SCRIPT field when sending to non-sp output":     true,
	"psbt structure: empty PSBT_OUT_SCRIPT field when sending to non-sp output":       true,
}

func loadVectors(t *testing.T) testVectors {
	t.Helper()

	data, err := os.ReadFile("../bip375_test_vectors.json")
	if err != nil {
		t.Fatalf("load vectors: %v", err)
	}

	var vectors testVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if vectors.Version != "1.1" {
		t.Fatalf("unexpected vector version %q", vectors.Version)
	}

	return vectors
}

func decodePSBT(t *testing.T, b64 string) []byte {
	t.Helper()

	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}

	return raw
}

func TestStructuralInvalidVectors(t *testing.T) {
	vectors := loadVectors(t)

	tested := 0
	for _, vector := range vectors.Invalid {
		if !structuralInvalidDescriptions[vector.Description] {
			continue
		}

		tested++
		t.Run(vector.Description, func(t *testing.T) {
			if _, err := psbt.NewFromRawBytes(
				bytes.NewReader(decodePSBT(t, vector.PSBT)), false,
			); err == nil {
				t.Fatalf("expected parse failure")
			}
		})
	}

	if tested != len(structuralInvalidDescriptions) {
		t.Fatalf("tested %d structural invalid vectors, want %d",
			tested, len(structuralInvalidDescriptions))
	}
}

func TestValidVectorsRoundTrip(t *testing.T) {
	vectors := loadVectors(t)

	tested := 0
	for _, vector := range vectors.Valid {
		tested++
		t.Run(vector.Description, func(t *testing.T) {
			raw := decodePSBT(t, vector.PSBT)

			pkt, err := psbt.NewFromRawBytes(bytes.NewReader(raw), false)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}

			var buf bytes.Buffer
			if err := pkt.Serialize(&buf); err != nil {
				t.Fatalf("serialize: %v", err)
			}

			pkt2, err := psbt.NewFromRawBytes(bytes.NewReader(buf.Bytes()), false)
			if err != nil {
				t.Fatalf("re-parse: %v", err)
			}

			var buf2 bytes.Buffer
			if err := pkt2.Serialize(&buf2); err != nil {
				t.Fatalf("re-serialize: %v", err)
			}

			if !bytes.Equal(buf.Bytes(), buf2.Bytes()) {
				t.Fatalf("round-trip mismatch")
			}
		})
	}

	if tested != 18 {
		t.Fatalf("expected 18 valid vectors, got %d", tested)
	}
}

func TestBIP375FieldPresence(t *testing.T) {
	vectors := loadVectors(t)

	for _, vector := range vectors.Valid {
		t.Run(vector.Description, func(t *testing.T) {
			raw := decodePSBT(t, vector.PSBT)

			pkt, err := psbt.NewFromRawBytes(bytes.NewReader(raw), false)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}

			hasSPOutput := false
			for _, out := range pkt.Outputs {
				if out.SPV0Info == nil {
					continue
				}

				hasSPOutput = true
				if len(out.SPV0Info.ScanKey) != 33 {
					t.Fatalf("SPV0Info.ScanKey len = %d, want 33",
						len(out.SPV0Info.ScanKey))
				}
				if len(out.SPV0Info.SpendKey) != 33 {
					t.Fatalf("SPV0Info.SpendKey len = %d, want 33",
						len(out.SPV0Info.SpendKey))
				}
			}
			if !hasSPOutput {
				return
			}

			hasShares := len(pkt.GlobalSPECDHShares) > 0
			for _, in := range pkt.Inputs {
				if len(in.SPECDHShares) > 0 {
					hasShares = true
					break
				}
			}
			if !hasShares {
				// In-progress vectors may not have shares yet.
				return
			}
		})
	}
}
