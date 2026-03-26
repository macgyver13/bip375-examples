# Go

Go BIP-375 vectors using [`github.com/otaliptus/psbt-v2`](https://github.com/otaliptus/psbt-v2) package.

## Run

```bash
cd go
go test -v -count=1
```

The tests read `../bip375_test_vectors.json` and cover:

- structural invalid vectors
- semantic invalid vectors
- valid vector round-trip stability
- output script materialization for `can finalize:` vectors
