# @qrauth/merkle-log

RFC 9162 Merkle tree hash, inclusion proofs and consistency proofs for QRAuth
Trust Records (ADR-0009 D1; the log hashes with SHA-256). Pure TypeScript, MIT licensed. The only runtime
dependency is [`@noble/hashes`](https://github.com/paulmillr/noble-hashes).
It runs in Node and in browsers.

The construction is RFC 9162 §2.1, identical to RFC 6962 §2.1:

- leaf hash `HASH(0x00 || entry)`;
- interior node `HASH(0x01 || left || right)`;
- the tree splits at the largest power of two smaller than the size, with no
  padding;
- the empty tree's root is `HASH()` of the empty string.

## API

```ts
import {
  sha3_256Hasher, sha256Hasher, createHasher,
  rootHash, inclusionProof, consistencyProof,
  verifyInclusion, verifyConsistency, constantTimeEqual,
} from '@qrauth/merkle-log';
```

| Export | Signature | Notes |
|---|---|---|
| `sha256Hasher` | `MerkleHasher` | SHA-256. The Trust Records log uses this (ADR-0009 D1); RFC 6962/9162-compatible. |
| `sha3_256Hasher` | `MerkleHasher` | SHA3-256, for other uses. |
| `createHasher` | `(hash: (data: Uint8Array) => Uint8Array, size: number) => MerkleHasher` | Wraps any fixed-length hash. |
| `MerkleHasher` | `{ size; emptyRoot(); hashLeaf(data); hashChildren(left, right) }` | Applies the `0x00` / `0x01` domain separation. |
| `rootHash` | `(hasher, leafHashes) => Uint8Array` | MTH over leaf hashes (outputs of `hashLeaf`). |
| `inclusionProof` | `(hasher, leafHashes, leafIndex) => Uint8Array[]` | RFC 9162 §2.1.3.1 audit path. Throws `RangeError` when the index is out of range. |
| `consistencyProof` | `(hasher, leafHashes, oldSize) => Uint8Array[]` | RFC 9162 §2.1.4.1. Returns `[]` when `oldSize` is 0 or equals the size. Throws `RangeError` when `oldSize` is larger than the tree. |
| `verifyInclusion` | `(hasher, { leafIndex, treeSize, leafHash, proof, root }) => boolean` | RFC 9162 §2.1.3.2. |
| `verifyConsistency` | `(hasher, { oldSize, newSize, oldRoot, newRoot, proof }) => boolean` | RFC 9162 §2.1.4.2. |
| `constantTimeEqual` | `(a, b) => boolean` | Byte comparison with no early exit. |

### Verification rules

- **Malformed input.** The verifiers never throw. They return `false` for:
  - a size or index that is not a non-negative safe integer (below 2^53);
  - an index that is not less than the tree size;
  - any hash or proof node that is not exactly `hasher.size` bytes;
  - a proof of the wrong length.
- **Root comparison.** Roots are compared with `constantTimeEqual`.
- **Empty tree.** A consistency proof from the empty tree (`oldSize` 0) is rejected. RFC 9162 defines consistency only for `0 < oldSize`, and every tree extends the empty tree.
- **Equal sizes.** When the sizes are equal, the proof must be empty and the roots must be equal.
- **Size and root together.** Take `treeSize` and `root` from the same signed tree head. As in RFC 9162, a proof does not by itself fix the tree size. For example, a proof for leaf 0 of a 3-leaf tree also satisfies the algorithm for size 4 against the 3-leaf root. Because leaf and node hashes are domain-separated, no 4-leaf tree has that root.
- **Deviation from the reference.** There is one deliberate difference from the transparency-dev reference implementation: roots that are not one hash long are rejected even when the sizes are equal.

Proof generation works on an in-memory list of leaf hashes (O(n) per proof).

## Tests

- All RFC 6962 reference vectors from
  [transparency-dev/merkle](https://github.com/transparency-dev/merkle):
  - roots for sizes 0–8;
  - 98 inclusion probes and 98 consistency probes;
  - generated proofs equal the reference proofs.
- Property tests with fast-check on both hashers (SHA-256 and SHA3-256):
  - every generated inclusion and consistency proof verifies;
  - any single-bit change to a leaf, root or proof node fails;
  - a wrong index fails;
  - a wrong size fails against that size's root;
  - a dropped, appended or reordered proof node fails.
- Edge cases: the empty tree, a single leaf, equal sizes, unsafe integers and wrong hash lengths.

```sh
npm test -w packages/merkle-log
```
