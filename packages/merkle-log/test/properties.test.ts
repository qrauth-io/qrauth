import { beforeEach, describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
  consistencyProof,
  inclusionProof,
  rootHash,
  sha256Hasher,
  sha3_256Hasher,
  verifyConsistency,
  verifyInclusion,
  type MerkleHasher,
} from '../src/index.js';

/**
 * Property tests on both bundled hashers (SHA-256 is the Trust Records log
 * hasher, ADR-0009 D1):
 * every generated proof verifies, and any single-bit tamper, wrong index or
 * wrong size fails. Leaves are distinct (each leaf input starts with its
 * index), so a "wrong" input never accidentally names the same leaf.
 */

const HASHERS: Array<[string, MerkleHasher]> = [
  ['SHA-256', sha256Hasher],
  ['SHA3-256', sha3_256Hasher],
];
let hasher: MerkleHasher = sha256Hasher;
const MAX_SIZE = 70;

function leavesFor(size: number, salt: number): Uint8Array[] {
  return Array.from({ length: size }, (_, i) =>
    hasher.hashLeaf(new TextEncoder().encode(`leaf:${salt}:${i}`)),
  );
}

function flipBit(bytes: Uint8Array, bit: number): Uint8Array {
  const out = Uint8Array.from(bytes);
  out[Math.floor(bit / 8) % out.length] ^= 1 << (bit % 8);
  return out;
}

const treeArb = fc.record({ size: fc.integer({ min: 1, max: MAX_SIZE }), salt: fc.nat() });

describe.each(HASHERS)('%s', (_name, h) => {
  beforeEach(() => {
    hasher = h;
  });

  describe('inclusion proofs', () => {
    it('every generated proof verifies, for every leaf of every tree', () => {
      fc.assert(
        fc.property(treeArb, ({ size, salt }) => {
          const leaves = leavesFor(size, salt);
          const root = rootHash(hasher, leaves);
          for (let i = 0; i < size; i++) {
            const proof = inclusionProof(hasher, leaves, i);
            expect(verifyInclusion(hasher, { leafIndex: i, treeSize: size, leafHash: leaves[i], proof, root })).toBe(true);
          }
        }),
        { numRuns: 60 },
      );
    });

    it('a single flipped bit in the leaf, the root or any proof node fails', () => {
      fc.assert(
        fc.property(treeArb, fc.nat(), fc.nat(), fc.nat({ max: 255 }), ({ size, salt }, pick, where, bit) => {
          const leaves = leavesFor(size, salt);
          const root = rootHash(hasher, leaves);
          const i = pick % size;
          const proof = inclusionProof(hasher, leaves, i);
          const target = where % (proof.length + 2);
          const args = { leafIndex: i, treeSize: size, leafHash: leaves[i], proof, root };
          if (target === 0) args.leafHash = flipBit(leaves[i], bit);
          else if (target === 1) args.root = flipBit(root, bit);
          else args.proof = proof.map((p, k) => (k === target - 2 ? flipBit(p, bit) : p));
          expect(verifyInclusion(hasher, args)).toBe(false);
        }),
        { numRuns: 400 },
      );
    });

    it('a wrong index fails', () => {
      fc.assert(
        fc.property(treeArb, fc.nat(), fc.integer({ min: 1, max: MAX_SIZE }), ({ size, salt }, pick, delta) => {
          const leaves = leavesFor(size, salt);
          const root = rootHash(hasher, leaves);
          const i = pick % size;
          const proof = inclusionProof(hasher, leaves, i);
          for (const leafIndex of [i + delta, i - delta].filter((x) => x >= 0 && x !== i)) {
            expect(verifyInclusion(hasher, { leafIndex, treeSize: size, leafHash: leaves[i], proof, root })).toBe(false);
          }
        }),
        { numRuns: 300 },
      );
    });

    it('a wrong tree size fails against the root of a tree of that size', () => {
      fc.assert(
        fc.property(treeArb, fc.nat(), fc.integer({ min: 1, max: MAX_SIZE }), ({ size, salt }, pick, delta) => {
          const leaves = leavesFor(size + delta, salt);
          const i = pick % size;
          const proof = inclusionProof(hasher, leaves.slice(0, size), i);
          for (const treeSize of [size + delta, size - delta].filter((x) => x > 0 && x !== size)) {
            const root = rootHash(hasher, leaves.slice(0, treeSize));
            expect(verifyInclusion(hasher, { leafIndex: i, treeSize, leafHash: leaves[i], proof, root })).toBe(false);
          }
        }),
        { numRuns: 300 },
      );
    });

    it('documents RFC 9162 behaviour: tree size is bound by the signed head, not by the proof', () => {
      // A size-3 proof for leaf 0 also satisfies the algorithm for size 4
      // against the size-3 root (the reference implementation agrees). No
      // size-4 tree has that root (leaf and node hashes are domain-separated),
      // so callers must take treeSize and root from the same signed tree head.
      const leaves = leavesFor(3, 0);
      const root3 = rootHash(hasher, leaves);
      const proof = inclusionProof(hasher, leaves, 0);
      expect(verifyInclusion(hasher, { leafIndex: 0, treeSize: 4, leafHash: leaves[0], proof, root: root3 })).toBe(true);
      const root4 = rootHash(hasher, [...leaves, hasher.hashLeaf(new Uint8Array([9]))]);
      expect(verifyInclusion(hasher, { leafIndex: 0, treeSize: 4, leafHash: leaves[0], proof, root: root4 })).toBe(false);
    });

    it('a dropped, appended or reordered proof node fails', () => {
      fc.assert(
        fc.property(fc.record({ size: fc.integer({ min: 3, max: MAX_SIZE }), salt: fc.nat() }), fc.nat(), ({ size, salt }, pick) => {
          const leaves = leavesFor(size, salt);
          const root = rootHash(hasher, leaves);
          const i = pick % size;
          const proof = inclusionProof(hasher, leaves, i);
          const base = { leafIndex: i, treeSize: size, leafHash: leaves[i], root };
          expect(verifyInclusion(hasher, { ...base, proof: proof.slice(1) })).toBe(false);
          expect(verifyInclusion(hasher, { ...base, proof: proof.slice(0, -1) })).toBe(false);
          expect(verifyInclusion(hasher, { ...base, proof: [...proof, root] })).toBe(false);
          if (proof.length >= 2) {
            expect(verifyInclusion(hasher, { ...base, proof: [proof[1], proof[0], ...proof.slice(2)] })).toBe(false);
          }
        }),
        { numRuns: 200 },
      );
    });
  });

  describe('consistency proofs', () => {
    it('every generated proof verifies, for every old size of every tree', () => {
      fc.assert(
        fc.property(treeArb, ({ size, salt }) => {
          const leaves = leavesFor(size, salt);
          const newRoot = rootHash(hasher, leaves);
          for (let m = 1; m <= size; m++) {
            const proof = consistencyProof(hasher, leaves, m);
            const oldRoot = rootHash(hasher, leaves.slice(0, m));
            expect(verifyConsistency(hasher, { oldSize: m, newSize: size, oldRoot, newRoot, proof })).toBe(true);
          }
        }),
        { numRuns: 60 },
      );
    });

    it('a single flipped bit in either root or any proof node fails', () => {
      fc.assert(
        fc.property(fc.record({ size: fc.integer({ min: 2, max: MAX_SIZE }), salt: fc.nat() }), fc.nat(), fc.nat(), fc.nat({ max: 255 }), ({ size, salt }, pick, where, bit) => {
          const leaves = leavesFor(size, salt);
          const m = 1 + (pick % (size - 1));
          const proof = consistencyProof(hasher, leaves, m);
          const args = {
            oldSize: m,
            newSize: size,
            oldRoot: rootHash(hasher, leaves.slice(0, m)),
            newRoot: rootHash(hasher, leaves),
            proof,
          };
          const target = where % (proof.length + 2);
          if (target === 0) args.oldRoot = flipBit(args.oldRoot, bit);
          else if (target === 1) args.newRoot = flipBit(args.newRoot, bit);
          else args.proof = proof.map((p, k) => (k === target - 2 ? flipBit(p, bit) : p));
          expect(verifyConsistency(hasher, args)).toBe(false);
        }),
        { numRuns: 400 },
      );
    });

    it('a wrong old size or new size fails against the roots of trees of those sizes', () => {
      fc.assert(
        fc.property(fc.record({ size: fc.integer({ min: 2, max: MAX_SIZE }), salt: fc.nat() }), fc.nat(), fc.integer({ min: 1, max: MAX_SIZE }), ({ size, salt }, pick, delta) => {
          const leaves = leavesFor(size + delta, salt);
          const m = 1 + (pick % (size - 1));
          const proof = consistencyProof(hasher, leaves.slice(0, size), m);
          const rootOf = (n: number) => rootHash(hasher, leaves.slice(0, n));
          for (const oldSize of [m + delta, m - delta].filter((x) => x > 0 && x !== m && x <= size)) {
            expect(
              verifyConsistency(hasher, { oldSize, newSize: size, oldRoot: rootOf(oldSize), newRoot: rootOf(size), proof }),
            ).toBe(false);
          }
          for (const newSize of [size + delta, size - delta].filter((x) => x >= m && x !== size)) {
            expect(
              verifyConsistency(hasher, { oldSize: m, newSize, oldRoot: rootOf(m), newRoot: rootOf(newSize), proof }),
            ).toBe(false);
          }
        }),
        { numRuns: 300 },
      );
    });

    it('a root of a different tree of the same size fails', () => {
      fc.assert(
        fc.property(fc.record({ size: fc.integer({ min: 2, max: MAX_SIZE }), salt: fc.nat() }), fc.nat(), ({ size, salt }, pick) => {
          const leaves = leavesFor(size, salt);
          const other = leavesFor(size, salt + 1);
          const m = 1 + (pick % (size - 1));
          const proof = consistencyProof(hasher, leaves, m);
          expect(
            verifyConsistency(hasher, {
              oldSize: m,
              newSize: size,
              oldRoot: rootHash(hasher, other.slice(0, m)),
              newRoot: rootHash(hasher, leaves),
              proof,
            }),
          ).toBe(false);
        }),
        { numRuns: 200 },
      );
    });
  });

  describe('edge cases', () => {
    let leaf: Uint8Array;
    beforeEach(() => {
      leaf = hasher.hashLeaf(new TextEncoder().encode('only'));
    });

    it('the empty tree has the empty-input hash as its root and contains nothing', () => {
      expect(rootHash(hasher, [])).toEqual(hasher.emptyRoot());
      expect(
        verifyInclusion(hasher, { leafIndex: 0, treeSize: 0, leafHash: leaf, proof: [], root: hasher.emptyRoot() }),
      ).toBe(false);
      expect(() => inclusionProof(hasher, [], 0)).toThrow(RangeError);
    });

    it('a single-leaf tree has the leaf hash as its root and an empty proof', () => {
      expect(rootHash(hasher, [leaf])).toEqual(leaf);
      expect(inclusionProof(hasher, [leaf], 0)).toEqual([]);
      expect(verifyInclusion(hasher, { leafIndex: 0, treeSize: 1, leafHash: leaf, proof: [], root: leaf })).toBe(true);
      expect(verifyInclusion(hasher, { leafIndex: 0, treeSize: 1, leafHash: leaf, proof: [leaf], root: leaf })).toBe(false);
    });

    it('consistency from the empty tree is rejected (RFC 9162 requires 0 < m)', () => {
      const leaves = leavesFor(4, 7);
      expect(consistencyProof(hasher, leaves, 0)).toEqual([]);
      expect(
        verifyConsistency(hasher, { oldSize: 0, newSize: 4, oldRoot: hasher.emptyRoot(), newRoot: rootHash(hasher, leaves), proof: [] }),
      ).toBe(false);
    });

    it('equal sizes need an empty proof and equal roots', () => {
      const leaves = leavesFor(5, 3);
      const root = rootHash(hasher, leaves);
      expect(consistencyProof(hasher, leaves, 5)).toEqual([]);
      expect(verifyConsistency(hasher, { oldSize: 5, newSize: 5, oldRoot: root, newRoot: root, proof: [] })).toBe(true);
      expect(verifyConsistency(hasher, { oldSize: 5, newSize: 5, oldRoot: root, newRoot: root, proof: [root] })).toBe(false);
      expect(
        verifyConsistency(hasher, { oldSize: 5, newSize: 5, oldRoot: root, newRoot: flipBit(root, 0), proof: [] }),
      ).toBe(false);
    });

    it('rejects sizes and indices that are not safe non-negative integers', () => {
      const args = { leafIndex: 0, treeSize: 1, leafHash: leaf, proof: [], root: leaf };
      for (const bad of [-1, 0.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53, 2 ** 64]) {
        expect(verifyInclusion(hasher, { ...args, leafIndex: bad })).toBe(false);
        expect(verifyInclusion(hasher, { ...args, treeSize: bad })).toBe(false);
        expect(verifyConsistency(hasher, { oldSize: bad, newSize: 1, oldRoot: leaf, newRoot: leaf, proof: [] })).toBe(false);
        expect(verifyConsistency(hasher, { oldSize: 1, newSize: bad, oldRoot: leaf, newRoot: leaf, proof: [] })).toBe(false);
      }
    });

    it('rejects hashes of the wrong length', () => {
      const short = leaf.slice(0, 31);
      expect(verifyInclusion(hasher, { leafIndex: 0, treeSize: 1, leafHash: short, proof: [], root: short })).toBe(false);
      const leaves = leavesFor(4, 1);
      const proof = inclusionProof(hasher, leaves, 1);
      const root = rootHash(hasher, leaves);
      expect(
        verifyInclusion(hasher, { leafIndex: 1, treeSize: 4, leafHash: leaves[1], proof: [proof[0], new Uint8Array([...proof[1], 0])], root }),
      ).toBe(false);
    });

    it('proof generation rejects out-of-range arguments and malformed leaf hashes', () => {
      const leaves = leavesFor(4, 2);
      expect(() => inclusionProof(hasher, leaves, 4)).toThrow(RangeError);
      expect(() => inclusionProof(hasher, leaves, -1)).toThrow(RangeError);
      expect(() => consistencyProof(hasher, leaves, 5)).toThrow(RangeError);
      expect(() => rootHash(hasher, [leaves[0], leaves[1].slice(1)])).toThrow(RangeError);
    });
  });
});
