# Go

Go BIP-375 implementation using:
- [`github.com/otaliptus/psbt-v2`](https://github.com/otaliptus/psbt-v2) — PSBTv2 with BIP-375 field support
- [`github.com/otaliptus/dleq374`](https://github.com/otaliptus/dleq374) — BIP-374 DLEQ proofs

## Packages

| Package | What it does |
|---------|-------------|
| `go/` | Top-level tests against the shared v1.1 test vectors (parsing, round-trip, structural validation) |
| `go/sp/` | BIP-352/BIP-375 silent payment workflow: packet analysis, ECDH share/proof generation and verification, output script materialization, extraction checks |

## Run

```bash
cd go
go test -v -count=1 ./...
```

## Test Vectors

- `../bip375_test_vectors.json` — shared v1.1 vectors used by the top-level tests (same file Python and Rust use)
- `testdata/bip375_test_vectors.json` — v1.2 vectors used by the `sp/` package tests (includes `input_keys` and `expected_ecdh_shares` fields needed for signer/materializer tests)
