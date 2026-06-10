package sp

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestAddSharesAndProofsGlobal(t *testing.T) {
	vector := vectorByDescription(t,
		"can finalize: two inputs single-signer - using global ECDH share",
	)
	packet := decodePacket(t, vector.PSBT)
	packet.GlobalSPECDHShares = nil
	packet.GlobalSPDLEQProofs = nil
	for i := range packet.Inputs {
		packet.Inputs[i].SPECDHShares = nil
		packet.Inputs[i].SPDLEQProofs = nil
	}

	owned := ownedInputsFromVector(t, vector)
	if err := AddSharesAndProofs(packet, owned); err != nil {
		t.Fatalf("AddSharesAndProofs: %v", err)
	}

	if len(packet.GlobalSPECDHShares) != 1 {
		t.Fatalf("global shares = %d, want 1", len(packet.GlobalSPECDHShares))
	}
	if len(packet.GlobalSPDLEQProofs) != 1 {
		t.Fatalf("global proofs = %d, want 1", len(packet.GlobalSPDLEQProofs))
	}
	if len(packet.Inputs[0].SPECDHShares) != 0 || len(packet.Inputs[1].SPECDHShares) != 0 {
		t.Fatalf("expected global mode only")
	}

	expectedShare, _ := hex.DecodeString(vector.ExpectedECDHShares[0].ECDHResult)
	if !bytes.Equal(packet.GlobalSPECDHShares[0].Share, expectedShare) {
		t.Fatalf("global share mismatch")
	}
	if err := VerifySharesAndProofs(packet); err != nil {
		t.Fatalf("VerifySharesAndProofs: %v", err)
	}
}

func TestAddSharesAndProofsPerInput(t *testing.T) {
	vector := vectorByDescription(t,
		"can finalize: two inputs single-signer - using per-input ECDH shares",
	)
	packet := decodePacket(t, vector.PSBT)
	packet.GlobalSPECDHShares = nil
	packet.GlobalSPDLEQProofs = nil
	for i := range packet.Inputs {
		packet.Inputs[i].SPECDHShares = nil
		packet.Inputs[i].SPDLEQProofs = nil
	}

	owned := ownedInputsFromVector(t, vector)[:1]
	if err := AddSharesAndProofs(packet, owned); err != nil {
		t.Fatalf("AddSharesAndProofs: %v", err)
	}

	if len(packet.GlobalSPECDHShares) != 0 || len(packet.GlobalSPDLEQProofs) != 0 {
		t.Fatalf("expected per-input mode")
	}
	if len(packet.Inputs[0].SPECDHShares) != 1 || len(packet.Inputs[0].SPDLEQProofs) != 1 {
		t.Fatalf("expected owned input share+proof")
	}
	if len(packet.Inputs[1].SPECDHShares) != 0 || len(packet.Inputs[1].SPDLEQProofs) != 0 {
		t.Fatalf("expected untouched non-owned input")
	}

	expectedShare, _ := hex.DecodeString(vector.ExpectedECDHShares[0].ECDHResult)
	if !bytes.Equal(packet.Inputs[0].SPECDHShares[0].Share, expectedShare) {
		t.Fatalf("per-input share mismatch")
	}
	if err := VerifySharesAndProofs(packet); err != nil {
		t.Fatalf("VerifySharesAndProofs: %v", err)
	}
}

func TestVerifySharesAndProofsRejectsInvalidVectors(t *testing.T) {
	tests := []string{
		"ecdh coverage: PSBT_IN_SP_DLEQ missing for input with ECDH share",
		"ecdh coverage: PSBT_GLOBAL_SP_DLEQ missing with global ECDH share",
		"ecdh coverage: invalid proof set for PSBT_IN_SP_DLEQ field",
		"ecdh coverage: invalid proof set for PSBT_GLOBAL_SP_DLEQ field",
	}

	for _, description := range tests {
		t.Run(description, func(t *testing.T) {
			vector := invalidVectorByDescription(t, description)
			packet := decodePacket(t, vector.PSBT)
			if err := VerifySharesAndProofs(packet); err == nil {
				t.Fatalf("expected share/proof validation failure")
			}
		})
	}
}

func TestValidateReadyToSign(t *testing.T) {
	inProgress := vectorByDescription(t,
		"in progress: no ECDH shares - no PSBT_OUT_SCRIPT",
	)
	if err := ValidateReadyToSign(decodePacket(t, inProgress.PSBT)); err == nil {
		t.Fatalf("expected missing script failure")
	}

	invalid := invalidVectorByDescription(t,
		"input eligibility: non-SIGHASH_ALL signature on input with silent payments output",
	)
	if err := ValidateReadyToSign(decodePacket(t, invalid.PSBT)); err == nil {
		t.Fatalf("expected sighash failure")
	}
}

func ownedInputsFromVector(t *testing.T, vector *bip375ValidVector) []OwnedInput {
	t.Helper()

	owned := make([]OwnedInput, 0, len(vector.InputKeys))
	for _, input := range vector.InputKeys {
		var secret [32]byte
		decoded, err := hex.DecodeString(input.PrivateKey)
		if err != nil {
			t.Fatalf("decode private key: %v", err)
		}
		copy(secret[:], decoded)
		owned = append(owned, OwnedInput{
			Index:  input.InputIndex,
			Secret: secret,
		})
	}

	return owned
}
