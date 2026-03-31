package sp

import (
	"fmt"

	psbt "github.com/otaliptus/psbt-v2"
)

func verifyUnexpectedInputMaterial(pkt *psbt.Packet, analysis *Analysis) error {
	for index := range pkt.Inputs {
		if analysis.EligibleInputsByIdx[index] != nil {
			continue
		}
		if len(pkt.Inputs[index].SPECDHShares) != 0 ||
			len(pkt.Inputs[index].SPDLEQProofs) != 0 {

			return fmt.Errorf("%w on input %d", ErrUnexpectedInputMaterial, index)
		}
	}

	return nil
}
