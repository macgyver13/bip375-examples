package sp

import "errors"

var (
	ErrNoSilentPaymentOutputs  = errors.New("packet has no silent payment outputs")
	ErrMissingInputPublicKey   = errors.New("eligible input missing public key")
	ErrNoEligibleInputs        = errors.New("packet has no eligible silent payment inputs")
	ErrMissingOutputAmount     = errors.New("silent payment output missing amount")
	ErrDuplicateOwnedInput     = errors.New("duplicate owned input")
	ErrOwnedInputMismatch      = errors.New("owned input secret does not match packet public key")
	ErrMissingShare            = errors.New("missing silent payment share")
	ErrMissingProof            = errors.New("missing silent payment proof")
	ErrInvalidProof            = errors.New("invalid silent payment proof")
	ErrSigHashAllRequired      = errors.New("silent payment inputs require SIGHASH_ALL")
	ErrOutputScriptsMissing    = errors.New("silent payment outputs are missing PSBT_OUT_SCRIPT")
	ErrIncompleteShareCoverage = errors.New("incomplete silent payment share coverage")
	ErrOutputScriptMismatch    = errors.New("silent payment output script mismatch")
	ErrTxModifiableSet         = errors.New("tx modifiable flags must be cleared once silent payment scripts are set")
	ErrUnexpectedInputMaterial = errors.New("ineligible input carries silent payment fields")
)
