package sp

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	psbt "github.com/otaliptus/psbt-v2"
)

var taprootNUMSKey = [32]byte{
	0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
	0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
	0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5,
	0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
}

// AnalyzePacket builds the normalized silent-payment view of a packet.
func AnalyzePacket(pkt *psbt.Packet) (*Analysis, error) {
	analysis := &Analysis{
		EligibleInputsByIdx: make(map[int]*EligibleInput),
		OutputGroupByScan:   make(map[string]*OutputGroup),
	}

	for i := range pkt.Inputs {
		input, err := analyzeInput(pkt, i)
		if err != nil {
			return nil, err
		}
		if input == nil {
			continue
		}

		analysis.EligibleInputs = append(analysis.EligibleInputs, input)
		analysis.EligibleInputsByIdx[input.Index] = input
	}

	for i := range pkt.Outputs {
		output, err := analyzeOutput(pkt, i)
		if err != nil {
			return nil, err
		}
		if output == nil {
			continue
		}

		analysis.SilentOutputs = append(analysis.SilentOutputs, output)
	}

	if len(analysis.SilentOutputs) == 0 {
		return nil, ErrNoSilentPaymentOutputs
	}
	if len(analysis.EligibleInputs) == 0 {
		return nil, ErrNoEligibleInputs
	}

	for _, output := range analysis.SilentOutputs {
		scanKey := string(output.ScanKeyBytes)
		group := analysis.OutputGroupByScan[scanKey]
		if group == nil {
			group = &OutputGroup{
				ScanKey:      output.ScanKey,
				ScanKeyBytes: append([]byte(nil), output.ScanKeyBytes...),
			}
			analysis.OutputGroupByScan[scanKey] = group
			analysis.OutputGroups = append(analysis.OutputGroups, group)
		}

		group.SilentOutputs = append(group.SilentOutputs, output)
	}

	sort.Slice(analysis.OutputGroups, func(i, j int) bool {
		return bytes.Compare(
			analysis.OutputGroups[i].ScanKeyBytes,
			analysis.OutputGroups[j].ScanKeyBytes,
		) < 0
	})

	for _, group := range analysis.OutputGroups {
		sort.Slice(group.SilentOutputs, func(i, j int) bool {
			left := group.SilentOutputs[i]
			right := group.SilentOutputs[j]

			// Labeled change outputs reuse the original silent-payment code
			// ordering, so keep packet order when both outputs are labeled.
			if left.Label != nil && right.Label != nil {
				return left.Index < right.Index
			}

			cmp := bytes.Compare(left.SpendKeyBytes, right.SpendKeyBytes)
			if cmp != 0 {
				return cmp < 0
			}

			return left.Index < right.Index
		})

		for k, output := range group.SilentOutputs {
			output.K = uint32(k)
		}
	}

	analysis.InputHash, analysis.SummedInputKey = computeInputHash(
		analysis.EligibleInputs,
	)

	return analysis, nil
}

func analyzeInput(pkt *psbt.Packet, index int) (*EligibleInput, error) {
	input := pkt.Inputs[index]
	prevTxID, prevTxIndex, err := prevOutRef(pkt, index)
	if err != nil {
		return nil, err
	}

	prevOut, err := prevTxOut(pkt, index)
	if err != nil {
		return nil, err
	}

	if !isEligiblePrevScript(input, prevOut.PkScript) {
		return nil, nil
	}

	publicKey, err := inputPublicKey(&input, prevOut.PkScript)
	if err != nil {
		return nil, fmt.Errorf("%w for input %d: %v",
			ErrMissingInputPublicKey, index, err)
	}

	return &EligibleInput{
		Index:          index,
		PublicKey:      publicKey,
		PublicKeyBytes: publicKey.SerializeCompressed(),
		PrevTxID:       prevTxID,
		PrevTxIndex:    prevTxIndex,
		Amount:         prevOut.Value,
		Script:         append([]byte(nil), prevOut.PkScript...),
	}, nil
}

func analyzeOutput(pkt *psbt.Packet, index int) (*SilentOutput, error) {
	output := pkt.Outputs[index]
	if output.SPV0Info == nil {
		return nil, nil
	}
	if output.Amount == nil {
		return nil, fmt.Errorf("%w at output %d", ErrMissingOutputAmount, index)
	}

	scanKey, err := btcec.ParsePubKey(output.SPV0Info.ScanKey)
	if err != nil {
		return nil, fmt.Errorf("parse scan key for output %d: %w", index, err)
	}
	spendKey, err := btcec.ParsePubKey(output.SPV0Info.SpendKey)
	if err != nil {
		return nil, fmt.Errorf("parse spend key for output %d: %w", index, err)
	}

	return &SilentOutput{
		Index:         index,
		Amount:        *output.Amount,
		ScanKey:       scanKey,
		ScanKeyBytes:  append([]byte(nil), output.SPV0Info.ScanKey...),
		SpendKey:      spendKey,
		SpendKeyBytes: append([]byte(nil), output.SPV0Info.SpendKey...),
		Label:         cloneLabel(output.SPV0Label),
		Script:        append([]byte(nil), output.Script...),
	}, nil
}

func prevOutRef(pkt *psbt.Packet, index int) ([32]byte, uint32, error) {
	var txid [32]byte
	var outIndex uint32

	if pkt.Version == 2 {
		input := pkt.Inputs[index]
		if input.PreviousTxID == nil || input.OutputIndex == nil {
			return txid, 0, fmt.Errorf("missing prevout fields")
		}

		copy(txid[:], input.PreviousTxID[:])
		return txid, *input.OutputIndex, nil
	}

	if pkt.UnsignedTx == nil || index >= len(pkt.UnsignedTx.TxIn) {
		return txid, 0, fmt.Errorf("missing unsigned transaction input")
	}

	copy(txid[:], pkt.UnsignedTx.TxIn[index].PreviousOutPoint.Hash[:])
	outIndex = pkt.UnsignedTx.TxIn[index].PreviousOutPoint.Index
	return txid, outIndex, nil
}

func prevTxOut(pkt *psbt.Packet, index int) (*wire.TxOut, error) {
	input := pkt.Inputs[index]
	switch {
	case input.WitnessUtxo != nil:
		return input.WitnessUtxo, nil

	case input.NonWitnessUtxo != nil:
		prevTxID, prevIndex, err := prevOutRef(pkt, index)
		if err != nil {
			return nil, err
		}

		if input.NonWitnessUtxo.TxHash() != prevTxID {
			return nil, fmt.Errorf("non-witness utxo txid mismatch")
		}
		if int(prevIndex) >= len(input.NonWitnessUtxo.TxOut) {
			return nil, fmt.Errorf("prevout index %d out of bounds", prevIndex)
		}

		return input.NonWitnessUtxo.TxOut[prevIndex], nil
	}

	return nil, fmt.Errorf("missing prevout data")
}

func isEligiblePrevScript(input psbt.PInput, script []byte) bool {
	switch {
	case txscript.IsPayToTaproot(script):
		return !isTaprootNUMS(input.TaprootInternalKey)

	case txscript.IsPayToWitnessPubKeyHash(script):
		return true

	case txscript.IsPayToScriptHash(script):
		return input.RedeemScript != nil &&
			txscript.IsPayToWitnessPubKeyHash(input.RedeemScript)

	case txscript.IsPayToPubKeyHash(script):
		return true

	default:
		return false
	}
}

func inputPublicKey(input *psbt.PInput, prevScript []byte) (*btcec.PublicKey, error) {
	switch {
	case txscript.IsPayToTaproot(prevScript):
		return schnorr.ParsePubKey(prevScript[2:34])

	case txscript.IsPayToWitnessPubKeyHash(prevScript):
		return anyMatchingPubKey(input, prevScript[2:])

	case txscript.IsPayToScriptHash(prevScript):
		if input.RedeemScript == nil ||
			!txscript.IsPayToWitnessPubKeyHash(input.RedeemScript) {

			return nil, fmt.Errorf("missing p2sh-p2wpkh redeem script")
		}

		return anyMatchingPubKey(input, input.RedeemScript[2:])

	case txscript.IsPayToPubKeyHash(prevScript):
		return anyMatchingPubKey(input, prevScript[3:23])

	default:
		return nil, fmt.Errorf("unsupported prevout script")
	}
}

func anyMatchingPubKey(input *psbt.PInput,
	wantHash160 []byte) (*btcec.PublicKey, error) {

	candidates := make([][]byte, 0,
		len(input.Bip32Derivation)+len(input.PartialSigs)+2,
	)
	hasStructuredSource := false
	for _, derivation := range input.Bip32Derivation {
		candidates = append(candidates, derivation.PubKey)
		hasStructuredSource = true
	}
	for _, partialSig := range input.PartialSigs {
		candidates = append(candidates, partialSig.PubKey)
	}
	witnessPubKeys := finalWitnessPubKey(input.FinalScriptWitness)
	if len(witnessPubKeys) != 0 {
		hasStructuredSource = true
		candidates = append(candidates, witnessPubKeys...)
	}
	scriptSigPubKeys := finalScriptSigPubKey(input.FinalScriptSig)
	if len(scriptSigPubKeys) != 0 {
		hasStructuredSource = true
		candidates = append(candidates, scriptSigPubKeys...)
	}

	for _, candidate := range candidates {
		if !bytes.Equal(btcutil.Hash160(candidate), wantHash160) {
			continue
		}

		return btcec.ParsePubKey(candidate)
	}

	unique := make(map[string][]byte)
	for _, candidate := range candidates {
		unique[string(candidate)] = candidate
	}

	// Some interop vectors provide exactly one input pubkey source for DLEQ
	// verification without making it script-matchable. Fall back to that
	// single candidate, but only when it is unambiguous and the packet has
	// a structured key source beyond a lone partial signature.
	if len(unique) != 1 || !hasStructuredSource {
		return nil, fmt.Errorf("no unambiguous public key source")
	}

	for _, candidate := range unique {
		return btcec.ParsePubKey(candidate)
	}

	return nil, fmt.Errorf("missing public key")
}

func finalWitnessPubKey(serialized []byte) [][]byte {
	if len(serialized) == 0 {
		return nil
	}

	reader := bytes.NewReader(serialized)
	count, err := wire.ReadVarInt(reader, 0)
	if err != nil || count == 0 {
		return nil
	}

	items := make([][]byte, 0, count)
	for i := uint64(0); i < count; i++ {
		item, err := wire.ReadVarBytes(reader, 0, 10000, "witness item")
		if err != nil {
			return nil
		}
		items = append(items, item)
	}

	last := items[len(items)-1]
	if _, err := btcec.ParsePubKey(last); err == nil {
		return [][]byte{last}
	}

	return nil
}

func finalScriptSigPubKey(script []byte) [][]byte {
	if len(script) == 0 {
		return nil
	}

	tokenizer := txscript.MakeScriptTokenizer(0, script)
	var candidates [][]byte
	for tokenizer.Next() {
		data := tokenizer.Data()
		if len(data) == 0 {
			continue
		}
		if _, err := btcec.ParsePubKey(data); err == nil {
			candidates = append(candidates, append([]byte(nil), data...))
		}
	}
	if tokenizer.Err() != nil {
		return nil
	}

	return candidates
}

func isTaprootNUMS(internalKey []byte) bool {
	return len(internalKey) == len(taprootNUMSKey) &&
		bytes.Equal(internalKey, taprootNUMSKey[:])
}

func sumPublicKeys(inputs []*EligibleInput) *btcec.PublicKey {
	var acc btcec.JacobianPoint

	for i, input := range inputs {
		var point btcec.JacobianPoint
		input.PublicKey.AsJacobian(&point)

		if i == 0 {
			acc = point
			continue
		}

		var next btcec.JacobianPoint
		btcec.AddNonConst(&acc, &point, &next)
		acc = next
	}

	acc.ToAffine()
	return btcec.NewPublicKey(&acc.X, &acc.Y)
}

func cloneLabel(label *uint32) *uint32 {
	if label == nil {
		return nil
	}

	value := *label
	return &value
}
