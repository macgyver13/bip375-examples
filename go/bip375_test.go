package bip375_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	psbt "github.com/otaliptus/psbt-v2"
	"github.com/otaliptus/psbt-v2/sp"
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
	Description     string `json:"description"`
	PSBT            string `json:"psbt"`
	ExpectedOutputs []struct {
		OutputIndex     int  `json:"output_index"`
		IsSilentPayment bool `json:"is_silent_payment"`
	} `json:"expected_outputs"`
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

func parsePacket(t *testing.T, b64 string) *psbt.Packet {
	t.Helper()

	packet, err := psbt.NewFromRawBytes(bytes.NewReader(decodePSBT(t, b64)), false)
	if err != nil {
		t.Fatalf("parse PSBT: %v", err)
	}

	return packet
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

func TestSemanticInvalidVectors(t *testing.T) {
	vectors := loadVectors(t)

	tested := 0
	for _, vector := range vectors.Invalid {
		if structuralInvalidDescriptions[vector.Description] {
			continue
		}

		tested++
		t.Run(vector.Description, func(t *testing.T) {
			packet, err := psbt.NewFromRawBytes(
				bytes.NewReader(decodePSBT(t, vector.PSBT)), false,
			)
			if err != nil {
				t.Fatalf("unexpected parse failure for semantic invalid vector: %v", err)
			}

			if err := sp.ValidateExtractable(packet); err == nil {
				t.Fatalf("expected semantic validation failure")
			}
		})
	}

	want := len(vectors.Invalid) - len(structuralInvalidDescriptions)
	if tested != want {
		t.Fatalf("tested %d semantic invalid vectors, want %d", tested, want)
	}
}

func TestValidVectorsRoundTrip(t *testing.T) {
	vectors := loadVectors(t)

	tested := 0
	for _, vector := range vectors.Valid {
		tested++
		t.Run(vector.Description, func(t *testing.T) {
			packet := parsePacket(t, vector.PSBT)

			var buf bytes.Buffer
			if err := packet.Serialize(&buf); err != nil {
				t.Fatalf("serialize: %v", err)
			}

			packet2, err := psbt.NewFromRawBytes(bytes.NewReader(buf.Bytes()), false)
			if err != nil {
				t.Fatalf("re-parse: %v", err)
			}

			var buf2 bytes.Buffer
			if err := packet2.Serialize(&buf2); err != nil {
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

func TestValidVectorsMaterialize(t *testing.T) {
	vectors := loadVectors(t)

	tested := 0
	for _, vector := range vectors.Valid {
		if !strings.HasPrefix(vector.Description, "can finalize:") {
			continue
		}

		tested++
		t.Run(vector.Description, func(t *testing.T) {
			packet := parsePacket(t, vector.PSBT)

			originalScripts := make(map[int][]byte)
			for i := range packet.Outputs {
				if packet.Outputs[i].SPV0Info == nil {
					continue
				}

				originalScripts[i] = append([]byte(nil), packet.Outputs[i].Script...)
				packet.Outputs[i].Script = nil
			}

			if err := sp.MaterializeOutputs(packet); err != nil {
				t.Fatalf("MaterializeOutputs: %v", err)
			}

			for _, output := range vector.ExpectedOutputs {
				if !output.IsSilentPayment {
					continue
				}

				if !bytes.Equal(
					packet.Outputs[output.OutputIndex].Script,
					originalScripts[output.OutputIndex],
				) {
					t.Fatalf("output %d script mismatch", output.OutputIndex)
				}
			}
		})
	}

	if tested != 13 {
		t.Fatalf("expected 13 finalize vectors, got %d", tested)
	}
}
