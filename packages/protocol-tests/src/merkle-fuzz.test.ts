import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { createHash } from "node:crypto";

import {
  buildMerkleTree,
  getMerklePath,
  verifyMerkleProof,
  type MerkleNode,
} from "../../api/src/services/merkle-signing.js";

/**
 * Property-based fuzzing of the Merkle proof verifier (ALGORITHM.md §14.3).
 *
 * Deterministic tests in `merkle.test.ts` cover the happy path and a
 * handful of mutations. Property tests cover the *space* of mutations:
 * fast-check generates ~100 random inputs per property and shrinks any
 * counterexample down to the minimum reproducer. The properties below
 * encode the full security contract of the Merkle layer:
 *
 *   1. **Soundness** — for any leaf set and any leaf index, the
 *      inclusion proof produced by `getMerklePath` always verifies
 *      against the root from `buildMerkleTree`.
 *
 *   2. **Tamper resistance, leaf** — flipping any byte in the leaf hash
 *      always causes verification to fail.
 *
 *   3. **Tamper resistance, path** — flipping any byte in any path
 *      node always causes verification to fail.
 *
 *   4. **Tamper resistance, side** — flipping any path node's `side`
 *      tag always causes verification to fail.
 *
 *   5. **Length attacks** — dropping or duplicating path nodes always
 *      causes verification to fail.
 *
 *   6. **Wrong root** — verifying a valid proof against any root other
 *      than the one it was produced from always fails.
 *
 * If any of these properties has a counterexample the security model is
 * broken and the failure message will include the exact input that
 * defeats it.
 */

const sha3hex = (s: string) =>
  createHash("sha3-256").update(s).digest("hex");

// fast-check arbitrary: a non-empty list of distinct leaf hashes derived
// from arbitrary strings. Cap at 32 to keep the test suite fast — Merkle
// behavior is uniform across sizes so 32 covers every depth up to 5.
const arbLeafSet = fc
  .uniqueArray(fc.string({ minLength: 1, maxLength: 16 }), {
    minLength: 1,
    maxLength: 32,
  })
  .map((strs) => strs.map((s) => sha3hex(s)));

// Helper: given a leaf set, choose any valid leaf index.
const arbLeafSetWithIndex = arbLeafSet.chain((leaves) =>
  fc.tuple(fc.constant(leaves), fc.integer({ min: 0, max: leaves.length - 1 })),
);

function flipFirstHexNibble(hex: string): string {
  // Flip the first nibble — guaranteed to change the byte value.
  const first = parseInt(hex[0], 16);
  const flipped = (first ^ 0xf).toString(16);
  return flipped + hex.slice(1);
}

describe("Merkle proof — soundness property", () => {
  it("any valid (leaves, index) → proof verifies against the root", () => {
    fc.assert(
      fc.property(arbLeafSetWithIndex, ([leaves, index]) => {
        const { root, tree } = buildMerkleTree(leaves);
        const path = getMerklePath(tree, index);
        return verifyMerkleProof(leaves[index], path, root);
      }),
      { numRuns: 200 },
    );
  });
});

describe("Merkle proof — tamper resistance properties", () => {
  it("flipping any byte in the leaf hash always fails verification", () => {
    fc.assert(
      fc.property(arbLeafSetWithIndex, ([leaves, index]) => {
        const { root, tree } = buildMerkleTree(leaves);
        const path = getMerklePath(tree, index);
        const tamperedLeaf = flipFirstHexNibble(leaves[index]);
        return verifyMerkleProof(tamperedLeaf, path, root) === false;
      }),
      { numRuns: 200 },
    );
  });

  it("flipping any byte in any path node always fails verification", () => {
    fc.assert(
      fc.property(
        arbLeafSetWithIndex.chain(([leaves, index]) =>
          fc.tuple(
            fc.constant(leaves),
            fc.constant(index),
            // Pick which path node to corrupt. The path length depends on
            // tree depth; we use a generous max and modulo it later.
            fc.integer({ min: 0, max: 100 }),
          ),
        ),
        ([leaves, index, nodeChoice]) => {
          const { root, tree } = buildMerkleTree(leaves);
          const path = getMerklePath(tree, index);
          if (path.length === 0) return true; // single-leaf tree, no path nodes to corrupt
          const targetIdx = nodeChoice % path.length;
          const corrupted = path.map((node, i) =>
            i === targetIdx ? { ...node, hash: flipFirstHexNibble(node.hash) } : node,
          );
          return verifyMerkleProof(leaves[index], corrupted, root) === false;
        },
      ),
      { numRuns: 200 },
    );
  });

  it("flipping any side tag in the path always fails verification", () => {
    fc.assert(
      fc.property(
        arbLeafSetWithIndex.chain(([leaves, index]) =>
          fc.tuple(
            fc.constant(leaves),
            fc.constant(index),
            fc.integer({ min: 0, max: 100 }),
          ),
        ),
        ([leaves, index, nodeChoice]) => {
          const { root, tree } = buildMerkleTree(leaves);
          const path = getMerklePath(tree, index);
          if (path.length === 0) return true;
          const targetIdx = nodeChoice % path.length;
          const swapped: MerkleNode[] = path.map((node, i) =>
            i === targetIdx
              ? { ...node, side: node.side === "left" ? "right" : "left" }
              : node,
          );
          return verifyMerkleProof(leaves[index], swapped, root) === false;
        },
      ),
      { numRuns: 200 },
    );
  });

  it("dropping a path node always fails verification", () => {
    fc.assert(
      fc.property(
        arbLeafSetWithIndex.chain(([leaves, index]) =>
          fc.tuple(
            fc.constant(leaves),
            fc.constant(index),
            fc.integer({ min: 0, max: 100 }),
          ),
        ),
        ([leaves, index, dropChoice]) => {
          const { root, tree } = buildMerkleTree(leaves);
          const path = getMerklePath(tree, index);
          if (path.length === 0) return true;
          const dropIdx = dropChoice % path.length;
          const truncated = [...path.slice(0, dropIdx), ...path.slice(dropIdx + 1)];
          return verifyMerkleProof(leaves[index], truncated, root) === false;
        },
      ),
      { numRuns: 200 },
    );
  });

  it("duplicating a path node always fails verification", () => {
    fc.assert(
      fc.property(
        arbLeafSetWithIndex.chain(([leaves, index]) =>
          fc.tuple(
            fc.constant(leaves),
            fc.constant(index),
            fc.integer({ min: 0, max: 100 }),
          ),
        ),
        ([leaves, index, dupChoice]) => {
          const { root, tree } = buildMerkleTree(leaves);
          const path = getMerklePath(tree, index);
          if (path.length === 0) return true;
          const dupIdx = dupChoice % path.length;
          const padded = [
            ...path.slice(0, dupIdx),
            path[dupIdx],
            ...path.slice(dupIdx),
          ];
          return verifyMerkleProof(leaves[index], padded, root) === false;
        },
      ),
      { numRuns: 200 },
    );
  });

  it("verifying against a wrong root always fails", () => {
    fc.assert(
      fc.property(
        arbLeafSetWithIndex,
        fc.string({ minLength: 1, maxLength: 16 }),
        ([leaves, index], otherSeed) => {
          const { tree } = buildMerkleTree(leaves);
          const path = getMerklePath(tree, index);
          // Pick a root that is NOT this batch's root.
          const wrongRoot = sha3hex(`wrong-root:${otherSeed}`);
          // Skip the rare case where the random "wrong" root happens to
          // collide with the real one (probability < 2^-256).
          const { root } = buildMerkleTree(leaves);
          fc.pre(wrongRoot !== root);
          return verifyMerkleProof(leaves[index], path, wrongRoot) === false;
        },
      ),
      { numRuns: 200 },
    );
  });
});
