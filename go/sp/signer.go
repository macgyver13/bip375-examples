package sp

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	dleq "github.com/otaliptus/dleq374"
	psbt "github.com/otaliptus/psbt-v2"
)

// OwnedInput declares that the caller controls the given eligible input.
type OwnedInput struct {
	Index  int
	Secret [32]byte
}

type ownedEligibleInput struct {
	Eligible *EligibleInput
	Secret   [32]byte
	Scalar   btcec.ModNScalar
}

// AddSharesAndProofs adds the missing BIP-375 ECDH shares and DLEQ proofs for
// the owned eligible inputs in pkt.
func AddSharesAndProofs(pkt *psbt.Packet, owned []OwnedInput) error {
	analysis, err := AnalyzePacket(pkt)
	if err != nil {
		return err
	}
	if err := validateSigHashPolicy(pkt); err != nil {
		return err
	}

	ownedInputs, err := ownedEligibleInputs(analysis, owned)
	if err != nil {
		return err
	}
	if len(ownedInputs) == 0 {
		return VerifySharesAndProofs(pkt)
	}

	allEligibleOwned := len(ownedInputs) == len(analysis.EligibleInputs)
	for _, group := range analysis.OutputGroups {
		globalShare := findGlobalShare(pkt, group.ScanKeyBytes)
		globalProof := findGlobalProof(pkt, group.ScanKeyBytes)

		switch {
		case globalShare != nil || globalProof != nil:
			if allEligibleOwned {
				if err := upsertGlobalProof(
					pkt, analysis, group, globalShare, globalProof,
					sumOwnedScalars(ownedInputs),
				); err != nil {
					return err
				}
			}

		case allEligibleOwned && !hasAnyPerInputMaterial(pkt, analysis, group.ScanKeyBytes):
			if err := upsertGlobalProof(
				pkt, analysis, group, nil, nil, sumOwnedScalars(ownedInputs),
			); err != nil {
				return err
			}

		default:
			for _, ownedInput := range ownedInputs {
				if err := upsertInputProof(
					pkt, ownedInput, group,
					findInputShare(pkt, ownedInput.Eligible.Index, group.ScanKeyBytes),
					findInputProof(pkt, ownedInput.Eligible.Index, group.ScanKeyBytes),
				); err != nil {
					return err
				}
			}
		}
	}

	return VerifySharesAndProofs(pkt)
}

// VerifySharesAndProofs verifies every share/proof pair already present in pkt.
func VerifySharesAndProofs(pkt *psbt.Packet) error {
	analysis, err := AnalyzePacket(pkt)
	if err != nil {
		if err == ErrNoSilentPaymentOutputs {
			return nil
		}
		return err
	}
	if err := verifyUnexpectedInputMaterial(pkt, analysis); err != nil {
		return err
	}

	for _, group := range analysis.OutputGroups {
		globalShare := findGlobalShare(pkt, group.ScanKeyBytes)
		globalProof := findGlobalProof(pkt, group.ScanKeyBytes)
		if (globalShare == nil) != (globalProof == nil) {
			if globalShare == nil {
				return fmt.Errorf("%w for scan key %x", ErrMissingShare, group.ScanKeyBytes)
			}
			return fmt.Errorf("%w for scan key %x", ErrMissingProof, group.ScanKeyBytes)
		}
		if globalShare != nil {
			if err := verifyProofPair(
				analysis.SummedInputKey, group.ScanKey, globalShare.Share,
				globalProof.Proof,
			); err != nil {
				return err
			}
		}

		for _, input := range analysis.EligibleInputs {
			inputShare := findInputShare(pkt, input.Index, group.ScanKeyBytes)
			inputProof := findInputProof(pkt, input.Index, group.ScanKeyBytes)
			if (inputShare == nil) != (inputProof == nil) {
				if inputShare == nil {
					return fmt.Errorf("%w for input %d scan key %x",
						ErrMissingShare, input.Index, group.ScanKeyBytes)
				}
				return fmt.Errorf("%w for input %d scan key %x",
					ErrMissingProof, input.Index, group.ScanKeyBytes)
			}
			if inputShare == nil {
				continue
			}

			if err := verifyProofPair(
				input.PublicKey, group.ScanKey, inputShare.Share,
				inputProof.Proof,
			); err != nil {
				return fmt.Errorf("input %d: %w", input.Index, err)
			}
		}
	}

	return nil
}

// ValidateReadyToSign enforces the signer-side silent-payment rules that can
// be checked from packet state alone.
func ValidateReadyToSign(pkt *psbt.Packet) error {
	if !hasSilentPaymentOutputs(pkt) {
		return nil
	}
	if err := validateSigHashPolicy(pkt); err != nil {
		return err
	}

	for _, output := range pkt.Outputs {
		if output.SPV0Info == nil {
			continue
		}
		if len(output.Script) == 0 {
			return ErrOutputScriptsMissing
		}
	}

	return nil
}

func ownedEligibleInputs(analysis *Analysis,
	owned []OwnedInput) ([]*ownedEligibleInput, error) {

	ownedByIndex := make(map[int]*ownedEligibleInput, len(owned))
	for _, input := range owned {
		if _, ok := ownedByIndex[input.Index]; ok {
			return nil, fmt.Errorf("%w: %d", ErrDuplicateOwnedInput, input.Index)
		}

		eligible := analysis.EligibleInputsByIdx[input.Index]
		if eligible == nil {
			return nil, fmt.Errorf("input %d is not a silent payment eligible input", input.Index)
		}

		scalar, publicKey, err := parseSecret(input.Secret)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(publicKey.SerializeCompressed(), eligible.PublicKeyBytes) {
			return nil, fmt.Errorf("%w for input %d", ErrOwnedInputMismatch, input.Index)
		}

		ownedByIndex[input.Index] = &ownedEligibleInput{
			Eligible: eligible,
			Secret:   input.Secret,
			Scalar:   scalar,
		}
	}

	ordered := make([]*ownedEligibleInput, 0, len(ownedByIndex))
	for _, eligible := range analysis.EligibleInputs {
		ownedInput := ownedByIndex[eligible.Index]
		if ownedInput != nil {
			ordered = append(ordered, ownedInput)
		}
	}

	return ordered, nil
}

func upsertGlobalProof(pkt *psbt.Packet, analysis *Analysis, group *OutputGroup,
	existingShare *psbt.SilentPaymentECDHShare,
	existingProof *psbt.SilentPaymentDLEQProof,
	secret btcec.ModNScalar) error {

	shareBytes, proofBytes, err := generateShareAndProof(secret, group.ScanKey)
	if err != nil {
		return err
	}
	if existingShare != nil {
		if !bytes.Equal(existingShare.Share, shareBytes) {
			return fmt.Errorf("global share mismatch for scan key %x", group.ScanKeyBytes)
		}
	} else {
		pkt.GlobalSPECDHShares = append(pkt.GlobalSPECDHShares,
			psbt.SilentPaymentECDHShare{
				ScanKey: append([]byte(nil), group.ScanKeyBytes...),
				Share:   shareBytes,
			},
		)
	}

	if existingProof != nil {
		if err := verifyProofPair(
			analysis.SummedInputKey, group.ScanKey, shareBytes, existingProof.Proof,
		); err != nil {
			return err
		}
		return nil
	}

	pkt.GlobalSPDLEQProofs = append(pkt.GlobalSPDLEQProofs,
		psbt.SilentPaymentDLEQProof{
			ScanKey: append([]byte(nil), group.ScanKeyBytes...),
			Proof:   proofBytes,
		},
	)

	return nil
}

func upsertInputProof(pkt *psbt.Packet, owned *ownedEligibleInput,
	group *OutputGroup, existingShare *psbt.SilentPaymentECDHShare,
	existingProof *psbt.SilentPaymentDLEQProof) error {

	shareBytes, proofBytes, err := generateShareAndProof(owned.Scalar, group.ScanKey)
	if err != nil {
		return err
	}
	if existingShare != nil {
		if !bytes.Equal(existingShare.Share, shareBytes) {
			return fmt.Errorf("input %d share mismatch for scan key %x",
				owned.Eligible.Index, group.ScanKeyBytes)
		}
	} else {
		pkt.Inputs[owned.Eligible.Index].SPECDHShares = append(
			pkt.Inputs[owned.Eligible.Index].SPECDHShares,
			psbt.SilentPaymentECDHShare{
				ScanKey: append([]byte(nil), group.ScanKeyBytes...),
				Share:   shareBytes,
			},
		)
	}

	if existingProof != nil {
		if err := verifyProofPair(
			owned.Eligible.PublicKey, group.ScanKey, shareBytes, existingProof.Proof,
		); err != nil {
			return err
		}
		return nil
	}

	pkt.Inputs[owned.Eligible.Index].SPDLEQProofs = append(
		pkt.Inputs[owned.Eligible.Index].SPDLEQProofs,
		psbt.SilentPaymentDLEQProof{
			ScanKey: append([]byte(nil), group.ScanKeyBytes...),
			Proof:   proofBytes,
		},
	)

	return nil
}

func validateSigHashPolicy(pkt *psbt.Packet) error {
	for i, input := range pkt.Inputs {
		if input.SighashType != 0 && input.SighashType != txscript.SigHashAll {
			return fmt.Errorf("%w for input %d", ErrSigHashAllRequired, i)
		}
	}

	return nil
}

func hasSilentPaymentOutputs(pkt *psbt.Packet) bool {
	for _, output := range pkt.Outputs {
		if output.SPV0Info != nil {
			return true
		}
	}

	return false
}

func parseSecret(secret [32]byte) (btcec.ModNScalar, *btcec.PublicKey, error) {
	var scalar btcec.ModNScalar
	if scalar.SetBytes(&secret) != 0 || scalar.IsZero() {
		return btcec.ModNScalar{}, nil, fmt.Errorf("invalid input secret scalar")
	}

	privKey := btcec.PrivKeyFromScalar(&scalar)
	return scalar, privKey.PubKey(), nil
}

func sumOwnedScalars(inputs []*ownedEligibleInput) btcec.ModNScalar {
	var total btcec.ModNScalar
	for _, input := range inputs {
		total.Add(&input.Scalar)
	}

	return total
}

func generateShareAndProof(secret btcec.ModNScalar,
	scanKey *btcec.PublicKey) ([]byte, []byte, error) {

	sharePoint := scalarMultiply(scanKey, &secret)
	sharePubKey, ok := jacobianToPublicKey(&sharePoint)
	if !ok {
		return nil, nil, fmt.Errorf("invalid ecdh share point")
	}

	var auxRand [32]byte
	if _, err := rand.Read(auxRand[:]); err != nil {
		return nil, nil, err
	}

	secretBytes := secret.Bytes()
	proof, err := dleq.GenerateProof(
		secretBytes, scanKey, auxRand, btcec.Generator(), nil,
	)
	if err != nil {
		return nil, nil, err
	}

	return sharePubKey.SerializeCompressed(), proof[:], nil
}
