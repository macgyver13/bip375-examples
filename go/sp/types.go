package sp

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// Analysis is the normalized silent-payment view of a PSBT packet.
type Analysis struct {
	EligibleInputs      []*EligibleInput
	EligibleInputsByIdx map[int]*EligibleInput
	SilentOutputs       []*SilentOutput
	OutputGroups        []*OutputGroup
	OutputGroupByScan   map[string]*OutputGroup
	SummedInputKey      *btcec.PublicKey
	InputHash           chainhash.Hash
}

// EligibleInput is an input that contributes to silent-payment derivation.
type EligibleInput struct {
	Index          int
	PublicKey      *btcec.PublicKey
	PublicKeyBytes []byte
	PrevTxID       chainhash.Hash
	PrevTxIndex    uint32
	Amount         int64
	Script         []byte
}

// OutPointKey serializes the input outpoint in transaction order.
func (in *EligibleInput) OutPointKey() [36]byte {
	var key [36]byte
	copy(key[:32], in.PrevTxID[:])
	key[32] = byte(in.PrevTxIndex)
	key[33] = byte(in.PrevTxIndex >> 8)
	key[34] = byte(in.PrevTxIndex >> 16)
	key[35] = byte(in.PrevTxIndex >> 24)
	return key
}

// SilentOutput is a silent-payment output with its k ordering already assigned.
type SilentOutput struct {
	Index         int
	Amount        int64
	ScanKey       *btcec.PublicKey
	ScanKeyBytes  []byte
	SpendKey      *btcec.PublicKey
	SpendKeyBytes []byte
	Label         *uint32
	Script        []byte
	K             uint32
}

// OutputGroup groups silent-payment outputs that share the same scan key.
type OutputGroup struct {
	ScanKey       *btcec.PublicKey
	ScanKeyBytes  []byte
	SilentOutputs []*SilentOutput
}
