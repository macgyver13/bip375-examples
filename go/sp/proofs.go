package sp

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	dleq "github.com/otaliptus/dleq374"
	psbt "github.com/otaliptus/psbt-v2"
)

func findGlobalShare(pkt *psbt.Packet, scanKey []byte) *psbt.SilentPaymentECDHShare {
	for i := range pkt.GlobalSPECDHShares {
		if bytes.Equal(pkt.GlobalSPECDHShares[i].ScanKey, scanKey) {
			return &pkt.GlobalSPECDHShares[i]
		}
	}

	return nil
}

func findGlobalProof(pkt *psbt.Packet, scanKey []byte) *psbt.SilentPaymentDLEQProof {
	for i := range pkt.GlobalSPDLEQProofs {
		if bytes.Equal(pkt.GlobalSPDLEQProofs[i].ScanKey, scanKey) {
			return &pkt.GlobalSPDLEQProofs[i]
		}
	}

	return nil
}

func findInputShare(pkt *psbt.Packet, index int,
	scanKey []byte) *psbt.SilentPaymentECDHShare {

	for i := range pkt.Inputs[index].SPECDHShares {
		if bytes.Equal(pkt.Inputs[index].SPECDHShares[i].ScanKey, scanKey) {
			return &pkt.Inputs[index].SPECDHShares[i]
		}
	}

	return nil
}

func findInputProof(pkt *psbt.Packet, index int,
	scanKey []byte) *psbt.SilentPaymentDLEQProof {

	for i := range pkt.Inputs[index].SPDLEQProofs {
		if bytes.Equal(pkt.Inputs[index].SPDLEQProofs[i].ScanKey, scanKey) {
			return &pkt.Inputs[index].SPDLEQProofs[i]
		}
	}

	return nil
}

func hasAnyPerInputMaterial(pkt *psbt.Packet, analysis *Analysis,
	scanKey []byte) bool {

	for _, input := range analysis.EligibleInputs {
		if findInputShare(pkt, input.Index, scanKey) != nil ||
			findInputProof(pkt, input.Index, scanKey) != nil {

			return true
		}
	}

	return false
}

func verifyProofPair(A, B *btcec.PublicKey, shareBytes,
	proofBytes []byte) error {

	sharePoint, err := btcec.ParsePubKey(shareBytes)
	if err != nil {
		return fmt.Errorf("%w: parse share: %v", ErrInvalidProof, err)
	}
	proof, err := dleq.ParseProof(proofBytes)
	if err != nil {
		return fmt.Errorf("%w: parse proof: %v", ErrInvalidProof, err)
	}
	if !dleq.VerifyProof(A, B, sharePoint, proof, btcec.Generator(), nil) {
		return ErrInvalidProof
	}

	return nil
}
