module github.com/macgyver13/bip375-examples/go

go 1.22

require github.com/otaliptus/psbt-v2 v0.1.0

require (
	github.com/btcsuite/btcd v0.24.2 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.3.4 // indirect
	github.com/btcsuite/btcd/btcutil v1.1.6 // indirect
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0 // indirect
	github.com/btcsuite/btclog v1.0.0 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	golang.org/x/crypto v0.33.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
)

replace github.com/otaliptus/psbt-v2 => ../../psbt-v2
