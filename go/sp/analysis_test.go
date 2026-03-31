package sp

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	psbt "github.com/otaliptus/psbt-v2"
)

type bip375Vectors struct {
	Version string                `json:"version"`
	Valid   []bip375ValidVector   `json:"valid"`
	Invalid []bip375InvalidVector `json:"invalid"`
}

type bip375ValidVector struct {
	Description        string                 `json:"description"`
	PSBT               string                 `json:"psbt"`
	InputKeys          []bip375VectorInputKey `json:"input_keys"`
	ExpectedECDHShares []struct {
		ScanKey    string `json:"scan_key"`
		ECDHResult string `json:"ecdh_result"`
		DLEQProof  string `json:"dleq_proof"`
		InputIndex *int   `json:"input_index,omitempty"`
	} `json:"expected_ecdh_shares"`
	ExpectedOutputs []struct {
		OutputIndex     int    `json:"output_index"`
		Amount          int64  `json:"amount"`
		IsSilentPayment bool   `json:"is_silent_payment"`
		Script          string `json:"script,omitempty"`
		SPInfo          string `json:"sp_info,omitempty"`
	} `json:"expected_outputs"`
}

type bip375VectorInputKey struct {
	InputIndex int    `json:"input_index"`
	PrivateKey string `json:"private_key"`
}

type bip375InvalidVector struct {
	Description string `json:"description"`
	PSBT        string `json:"psbt"`
}

func loadVectors(t *testing.T) bip375Vectors {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}

	path := filepath.Join(filepath.Dir(file), "..", "testdata", "bip375_test_vectors.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}

	var vectors bip375Vectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}

	return vectors
}

func decodePacket(t *testing.T, b64 string) *psbt.Packet {
	t.Helper()

	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}

	packet, err := psbt.NewFromRawBytes(bytes.NewReader(raw), false)
	if err != nil {
		t.Fatalf("parse packet: %v", err)
	}

	return packet
}

func vectorByDescription(t *testing.T, description string) *bip375ValidVector {
	t.Helper()

	vectors := loadVectors(t)
	for i := range vectors.Valid {
		if vectors.Valid[i].Description == description {
			return &vectors.Valid[i]
		}
	}

	t.Fatalf("vector %q not found", description)
	return nil
}

func invalidVectorByDescription(t *testing.T,
	description string) *bip375InvalidVector {
	t.Helper()

	vectors := loadVectors(t)
	for i := range vectors.Invalid {
		if vectors.Invalid[i].Description == description {
			return &vectors.Invalid[i]
		}
	}

	t.Fatalf("invalid vector %q not found", description)
	return nil
}

func TestAnalyzePacketMixedInputEligibility(t *testing.T) {
	tests := []string{
		"can finalize: two mixed input types - only eligible inputs contribute ECDH shares (P2SH excluded)",
		"can finalize: two mixed input types - only eligible inputs contribute ECDH shares (NUMS point excluded)",
	}

	for _, description := range tests {
		t.Run(description, func(t *testing.T) {
			vector := vectorByDescription(t, description)
			analysis, err := AnalyzePacket(decodePacket(t, vector.PSBT))
			if err != nil {
				t.Fatalf("AnalyzePacket: %v", err)
			}

			wantIndices := make([]int, 0, len(vector.ExpectedECDHShares))
			seen := make(map[int]bool)
			for _, share := range vector.ExpectedECDHShares {
				if share.InputIndex == nil || seen[*share.InputIndex] {
					continue
				}

				wantIndices = append(wantIndices, *share.InputIndex)
				seen[*share.InputIndex] = true
			}

			if len(analysis.EligibleInputs) != len(wantIndices) {
				t.Fatalf("eligible inputs = %d, want %d",
					len(analysis.EligibleInputs), len(wantIndices))
			}

			for i, want := range wantIndices {
				if analysis.EligibleInputs[i].Index != want {
					t.Fatalf("eligible input %d = %d, want %d",
						i, analysis.EligibleInputs[i].Index, want)
				}
			}
		})
	}
}

func TestAnalyzePacketAssignsKBySpendKeyThenIndex(t *testing.T) {
	tests := []string{
		"can finalize: three sp outputs (same scan key) - each output has distinct k value",
		"can finalize: three sp outputs (same scan key) / two regular outputs - k value must not follow output index",
	}

	for _, description := range tests {
		t.Run(description, func(t *testing.T) {
			vector := vectorByDescription(t, description)
			analysis, err := AnalyzePacket(decodePacket(t, vector.PSBT))
			if err != nil {
				t.Fatalf("AnalyzePacket: %v", err)
			}

			group := analysis.OutputGroups[0]
			lastSpend := ""
			lastIndex := -1
			for k, output := range group.SilentOutputs {
				if output.K != uint32(k) {
					t.Fatalf("output %d k = %d, want %d",
						output.Index, output.K, k)
				}

				spendHex := hex.EncodeToString(output.SpendKeyBytes)
				if lastSpend > spendHex {
					t.Fatalf("spend-key order regressed: %s before %s",
						lastSpend, spendHex)
				}
				if lastSpend == spendHex && lastIndex > output.Index {
					t.Fatalf("index tiebreak regressed: %d before %d",
						lastIndex, output.Index)
				}

				lastSpend = spendHex
				lastIndex = output.Index
			}
		})
	}
}

func TestAnalyzePacketInputHashDeterministic(t *testing.T) {
	vector := vectorByDescription(t,
		"can finalize: two inputs single-signer - using global ECDH share",
	)
	packet := decodePacket(t, vector.PSBT)

	first, err := AnalyzePacket(packet)
	if err != nil {
		t.Fatalf("AnalyzePacket(first): %v", err)
	}
	second, err := AnalyzePacket(packet)
	if err != nil {
		t.Fatalf("AnalyzePacket(second): %v", err)
	}

	if first.InputHash != second.InputHash {
		t.Fatalf("input hash mismatch: %x != %x",
			first.InputHash[:], second.InputHash[:])
	}
	if !bytes.Equal(
		first.SummedInputKey.SerializeCompressed(),
		second.SummedInputKey.SerializeCompressed(),
	) {
		t.Fatalf("summed input key mismatch")
	}
}
