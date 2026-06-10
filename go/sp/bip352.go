package sp

import (
	"bytes"
	"encoding/binary"
	"sort"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

var (
	tagBIP352Inputs       = []byte("BIP0352/Inputs")
	tagBIP352SharedSecret = []byte("BIP0352/SharedSecret")
)

func computeInputHash(inputs []*EligibleInput) (chainhash.Hash, *btcec.PublicKey) {
	smallest := smallestEligibleInput(inputs)
	summed := sumPublicKeys(inputs)
	outPointKey := smallest.OutPointKey()

	return *chainhash.TaggedHash(
		tagBIP352Inputs, outPointKey[:],
		summed.SerializeCompressed(),
	), summed
}

func taggedHashBIP352SharedSecret(sharedSecret []byte, k uint32) chainhash.Hash {
	var index [4]byte
	binary.BigEndian.PutUint32(index[:], k)

	return *chainhash.TaggedHash(
		tagBIP352SharedSecret, sharedSecret, index[:],
	)
}

func smallestEligibleInput(inputs []*EligibleInput) *EligibleInput {
	sorted := append([]*EligibleInput(nil), inputs...)
	sort.Slice(sorted, func(i, j int) bool {
		left := sorted[i].OutPointKey()
		right := sorted[j].OutPointKey()
		return bytes.Compare(left[:], right[:]) < 0
	})

	return sorted[0]
}
