package sp

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	psbt "github.com/otaliptus/psbt-v2"
)

// MaterializeOutputs computes and sets missing PSBT_OUT_SCRIPT values for
// silent-payment outputs once share coverage is complete.
func MaterializeOutputs(pkt *psbt.Packet) error {
	analysis, err := AnalyzePacket(pkt)
	if err != nil {
		return err
	}
	if err := VerifySharesAndProofs(pkt); err != nil {
		return err
	}

	inputHashScalar := scalarFromHash32(analysis.InputHash)
	didSetScript := false
	for _, group := range analysis.OutputGroups {
		sharePoint, err := aggregateSharePoint(pkt, analysis, group)
		if err != nil {
			return err
		}

		sharedSecretPoint := scalarMultiply(sharePoint, &inputHashScalar)
		sharedSecretPubKey, ok := jacobianToPublicKey(&sharedSecretPoint)
		if !ok {
			return fmt.Errorf("invalid shared secret point")
		}
		sharedSecret := sharedSecretPubKey.SerializeCompressed()

		for _, output := range group.SilentOutputs {
			script, err := deriveOutputScript(output, sharedSecret)
			if err != nil {
				return err
			}

			if len(pkt.Outputs[output.Index].Script) == 0 {
				pkt.Outputs[output.Index].Script = script
				didSetScript = true
				continue
			}
			if !bytes.Equal(pkt.Outputs[output.Index].Script, script) {
				return fmt.Errorf("%w at output %d",
					ErrOutputScriptMismatch, output.Index)
			}
		}
	}

	if didSetScript && pkt.TxModifiable != nil {
		*pkt.TxModifiable &^= 0x03
	}

	return nil
}

// ValidateExtractable verifies the silent-payment specific preconditions before
// delegating to the base PSBT extractor.
func ValidateExtractable(pkt *psbt.Packet) error {
	if !hasSilentPaymentOutputs(pkt) {
		return nil
	}
	if err := validateSigHashPolicy(pkt); err != nil {
		return err
	}
	if err := VerifySharesAndProofs(pkt); err != nil {
		return err
	}

	analysis, err := AnalyzePacket(pkt)
	if err != nil {
		return err
	}
	inputHashScalar := scalarFromHash32(analysis.InputHash)
	for _, group := range analysis.OutputGroups {
		sharePoint, err := aggregateSharePoint(pkt, analysis, group)
		if err != nil {
			return err
		}

		sharedSecretPoint := scalarMultiply(sharePoint, &inputHashScalar)
		sharedSecretPubKey, ok := jacobianToPublicKey(&sharedSecretPoint)
		if !ok {
			return fmt.Errorf("invalid shared secret point")
		}
		sharedSecret := sharedSecretPubKey.SerializeCompressed()

		for _, output := range group.SilentOutputs {
			if len(pkt.Outputs[output.Index].Script) == 0 {
				return fmt.Errorf("%w at output %d",
					ErrOutputScriptsMissing, output.Index)
			}

			wantScript, err := deriveOutputScript(output, sharedSecret)
			if err != nil {
				return err
			}
			if !bytes.Equal(pkt.Outputs[output.Index].Script, wantScript) {
				return fmt.Errorf("%w at output %d",
					ErrOutputScriptMismatch, output.Index)
			}
		}
	}

	if pkt.TxModifiable != nil && (*pkt.TxModifiable&0x03) != 0 {
		return ErrTxModifiableSet
	}

	return nil
}

// Extract verifies the silent-payment fields and then delegates to the base
// PSBT extractor.
func Extract(pkt *psbt.Packet) (*wire.MsgTx, error) {
	if err := ValidateExtractable(pkt); err != nil {
		return nil, err
	}

	return psbt.Extract(pkt)
}

func aggregateSharePoint(pkt *psbt.Packet, analysis *Analysis,
	group *OutputGroup) (*btcec.PublicKey, error) {

	if globalShare := findGlobalShare(pkt, group.ScanKeyBytes); globalShare != nil {
		return btcec.ParsePubKey(globalShare.Share)
	}

	var sum btcec.JacobianPoint
	haveAny := false
	for _, input := range analysis.EligibleInputs {
		inputShare := findInputShare(pkt, input.Index, group.ScanKeyBytes)
		if inputShare == nil {
			return nil, fmt.Errorf("%w for input %d scan key %x",
				ErrIncompleteShareCoverage, input.Index, group.ScanKeyBytes)
		}

		sharePoint, err := btcec.ParsePubKey(inputShare.Share)
		if err != nil {
			return nil, err
		}

		var shareJacobian btcec.JacobianPoint
		sharePoint.AsJacobian(&shareJacobian)
		if !haveAny {
			sum = shareJacobian
			haveAny = true
			continue
		}

		var next btcec.JacobianPoint
		btcec.AddNonConst(&sum, &shareJacobian, &next)
		sum = next
	}
	if !haveAny {
		return nil, ErrIncompleteShareCoverage
	}

	sharePubKey, ok := jacobianToPublicKey(&sum)
	if !ok {
		return nil, ErrIncompleteShareCoverage
	}

	return sharePubKey, nil
}

func deriveOutputScript(output *SilentOutput, sharedSecret []byte) ([]byte, error) {
	tweakHash := taggedHashBIP352SharedSecret(sharedSecret, output.K)
	tweakScalar := scalarFromHash32(tweakHash)

	var spendJacobian btcec.JacobianPoint
	output.SpendKey.AsJacobian(&spendJacobian)
	tweakPoint := scalarBaseMultiply(&tweakScalar)

	var destination btcec.JacobianPoint
	btcec.AddNonConst(&spendJacobian, &tweakPoint, &destination)
	destinationPubKey, ok := jacobianToPublicKey(&destination)
	if !ok {
		return nil, fmt.Errorf("invalid destination point for output %d", output.Index)
	}

	return txscript.PayToTaprootScript(destinationPubKey)
}

func scalarFromHash32(hash chainhash.Hash) btcec.ModNScalar {
	var scalar btcec.ModNScalar
	scalar.SetBytes((*[32]byte)(&hash))
	return scalar
}
