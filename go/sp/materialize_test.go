package sp

import (
	"bytes"
	"encoding/base64"
	"testing"

	psbt "github.com/otaliptus/psbt-v2"
)

func TestMaterializeOutputsFromFinalizeVectors(t *testing.T) {
	vectors := loadVectors(t)

	tested := 0
	for i := range vectors.Valid {
		vector := &vectors.Valid[i]
		if len(vector.ExpectedECDHShares) == 0 || !hasFinalizePrefix(vector.Description) {
			continue
		}

		tested++
		t.Run(vector.Description, func(t *testing.T) {
			packet := decodePacket(t, vector.PSBT)
			originalScripts := make(map[int][]byte)
			for index := range packet.Outputs {
				if packet.Outputs[index].SPV0Info != nil {
					originalScripts[index] = append([]byte(nil), packet.Outputs[index].Script...)
					packet.Outputs[index].Script = nil
				}
			}

			if err := MaterializeOutputs(packet); err != nil {
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

	if tested != 12 {
		t.Fatalf("expected 12 finalize-capable vectors, got %d", tested)
	}
}

func TestMaterializeOutputsRejectsIncompleteCoverage(t *testing.T) {
	tests := []string{
		"in progress: no ECDH shares - no PSBT_OUT_SCRIPT",
		"in progress: partial ECDH coverage - no PSBT_OUT_SCRIPT",
		"in progress: one input/two sp outputs (different scan keys) - missing ECDH share for output 0 scan key",
	}

	for _, description := range tests {
		t.Run(description, func(t *testing.T) {
			vector := vectorByDescription(t, description)
			if err := MaterializeOutputs(decodePacket(t, vector.PSBT)); err == nil {
				t.Fatalf("expected incomplete coverage failure")
			}
		})
	}
}

func TestValidateExtractableRejectsInvalidVectors(t *testing.T) {
	tests := []string{
		"psbt structure: PSBT_GLOBAL_TX_MODIFIABLE with PSBT_OUT_SCRIPT set",
		"ecdh coverage: PSBT_OUT_SCRIPT set - no eligible inputs",
		"ecdh coverage: PSBT_OUT_SCRIPT set - Input 0 missing PSBT_IN_SP_ECDH_SHARE",
		"ecdh coverage: input missing public key for DLEQ verification",
		"ecdh coverage: one input/three sp outputs (different scan keys) - Output 1 missing ECDH share for scan key",
		"ecdh coverage: two inputs/two sp outputs (different scan keys) - full coverage input 0 / partial coverage input 1",
		"ecdh coverage: two inputs/one sp output (two scan keys) - Input 1 missing ECDH share for scan key",
		"ecdh coverage: ineligible P2TR input with NUMS point with PSBT_IN_SP_ECDH_SHARE set",
		"input eligibility: segwit version greater than 1 in transaction inputs with silent payments output",
		"output scripts: computed output script mismatch in PSBT_OUT_SCRIPT field from transaction inputs",
		"output scripts: two sp outputs (same scan key/different spend keys) - outputs are not sorted lexicographically by spend key",
		"output scripts: three sp outputs (same scan/spend keys) - output scripts are computed with swapped k values",
	}

	for _, description := range tests {
		t.Run(description, func(t *testing.T) {
			vector := invalidVectorByDescription(t, description)
			raw, err := base64.StdEncoding.DecodeString(vector.PSBT)
			if err != nil {
				t.Fatalf("decode base64: %v", err)
			}

			packet, err := psbt.NewFromRawBytes(bytes.NewReader(raw), false)
			if err != nil {
				t.Fatalf("parse packet: %v", err)
			}

			if err := ValidateExtractable(packet); err == nil {
				t.Fatalf("expected extractable validation failure")
			}
		})
	}
}

func TestParserRejectsInvalidSilentPaymentVectors(t *testing.T) {
	tests := []string{
		"ecdh coverage: ineligible P2SH multisig input with PSBT_IN_SP_ECDH_SHARE set",
	}

	for _, description := range tests {
		t.Run(description, func(t *testing.T) {
			vector := invalidVectorByDescription(t, description)
			raw, err := base64.StdEncoding.DecodeString(vector.PSBT)
			if err != nil {
				t.Fatalf("decode base64: %v", err)
			}

			if _, err := psbt.NewFromRawBytes(bytes.NewReader(raw), false); err == nil {
				t.Fatalf("expected parser rejection")
			}
		})
	}
}

func TestExtractValidatesSilentPaymentScripts(t *testing.T) {
	vector := vectorByDescription(t,
		"can finalize: one P2WPKH input single-signer",
	)
	packet := decodePacket(t, vector.PSBT)
	for i := range packet.Outputs {
		if packet.Outputs[i].SPV0Info != nil {
			packet.Outputs[i].Script = nil
		}
	}

	if _, err := Extract(packet); err == nil {
		t.Fatalf("expected missing script failure")
	}
	if err := MaterializeOutputs(packet); err != nil {
		t.Fatalf("MaterializeOutputs: %v", err)
	}
	if err := psbt.MaybeFinalizeAll(packet); err != nil {
		t.Fatalf("MaybeFinalizeAll: %v", err)
	}
	if _, err := Extract(packet); err != nil {
		t.Fatalf("Extract: %v", err)
	}
}

func hasFinalizePrefix(description string) bool {
	return len(description) >= len("can finalize:") &&
		description[:len("can finalize:")] == "can finalize:"
}
