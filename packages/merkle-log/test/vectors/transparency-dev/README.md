# RFC 6962 test vectors (transparency-dev/merkle)

Vendored from https://github.com/transparency-dev/merkle at commit
`75a6539d7b48af0d529236f24487d2814fd1dca7` (Apache License 2.0, see `LICENSE`). Test data only; never
bundled or published.

- `trees.json`: `LeafInputs()` and `RootHashes()` (index = tree size, 0 = empty
  tree) from `testonly/constants.go`.
- `inclusion.json`: every probe under `testdata/inclusion/`.
- `consistency.json`: every probe under `testdata/consistency/`.

The probe files store byte fields as base64; they are converted to lowercase
hex here, with no other change. Hash function: SHA-256 (RFC 6962).
