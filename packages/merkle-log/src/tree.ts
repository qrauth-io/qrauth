import { isIndex } from './bytes.js';
import type { MerkleHasher } from './hasher.js';

/**
 * Merkle Tree Hash and proof generation over an in-memory list of leaf
 * hashes, as defined in RFC 9162 §2.1 (identical to RFC 6962 §2.1). Leaf
 * hashes are HASH(0x00 || entry), produced with `hasher.hashLeaf`.
 *
 * Inputs are never modified; every returned hash is a new array.
 */

/** Largest power of two strictly smaller than n (n > 1). */
function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function assertLeafHashes(hasher: MerkleHasher, leafHashes: readonly Uint8Array[]): void {
  if (!isIndex(leafHashes.length)) {
    throw new RangeError('too many leaves');
  }
  leafHashes.forEach((h, i) => {
    if (h.length !== hasher.size) {
      throw new RangeError(`leaf hash ${i} is ${h.length} bytes, expected ${hasher.size}`);
    }
  });
}

/** MTH(D[start:end]). */
function subtreeRoot(hasher: MerkleHasher, leaves: readonly Uint8Array[], start: number, end: number): Uint8Array {
  const n = end - start;
  if (n === 0) return hasher.emptyRoot();
  if (n === 1) return leaves[start].slice();
  const k = splitPoint(n);
  return hasher.hashChildren(subtreeRoot(hasher, leaves, start, start + k), subtreeRoot(hasher, leaves, start + k, end));
}

/** PATH(m, D[start:end]) — RFC 9162 §2.1.3.1. */
function path(hasher: MerkleHasher, leaves: readonly Uint8Array[], m: number, start: number, end: number): Uint8Array[] {
  const n = end - start;
  if (n === 1) return [];
  const k = splitPoint(n);
  if (m < k) {
    return [...path(hasher, leaves, m, start, start + k), subtreeRoot(hasher, leaves, start + k, end)];
  }
  return [...path(hasher, leaves, m - k, start + k, end), subtreeRoot(hasher, leaves, start, start + k)];
}

/** SUBPROOF(m, D[start:end], complete) — RFC 9162 §2.1.4.1. */
function subproof(
  hasher: MerkleHasher,
  leaves: readonly Uint8Array[],
  m: number,
  start: number,
  end: number,
  complete: boolean,
): Uint8Array[] {
  const n = end - start;
  if (m === n) {
    return complete ? [] : [subtreeRoot(hasher, leaves, start, end)];
  }
  const k = splitPoint(n);
  if (m <= k) {
    return [...subproof(hasher, leaves, m, start, start + k, complete), subtreeRoot(hasher, leaves, start + k, end)];
  }
  return [...subproof(hasher, leaves, m - k, start + k, end, false), subtreeRoot(hasher, leaves, start, start + k)];
}

/** Root hash (MTH) of the tree whose leaves have the given hashes. */
export function rootHash(hasher: MerkleHasher, leafHashes: readonly Uint8Array[]): Uint8Array {
  assertLeafHashes(hasher, leafHashes);
  return subtreeRoot(hasher, leafHashes, 0, leafHashes.length);
}

/**
 * Inclusion proof (audit path) for the leaf at `leafIndex` in the tree of
 * all `leafHashes`. Throws RangeError for an index outside the tree.
 */
export function inclusionProof(
  hasher: MerkleHasher,
  leafHashes: readonly Uint8Array[],
  leafIndex: number,
): Uint8Array[] {
  assertLeafHashes(hasher, leafHashes);
  if (!isIndex(leafIndex) || leafIndex >= leafHashes.length) {
    throw new RangeError(`leaf index ${leafIndex} is outside a tree of size ${leafHashes.length}`);
  }
  return path(hasher, leafHashes, leafIndex, 0, leafHashes.length);
}

/**
 * Consistency proof from the tree of the first `oldSize` leaves to the tree
 * of all `leafHashes`. Empty when oldSize is 0 or equals the tree size
 * (RFC 9162 defines proofs only for 0 < oldSize < size). Throws RangeError
 * when oldSize is larger than the tree.
 */
export function consistencyProof(
  hasher: MerkleHasher,
  leafHashes: readonly Uint8Array[],
  oldSize: number,
): Uint8Array[] {
  assertLeafHashes(hasher, leafHashes);
  const n = leafHashes.length;
  if (!isIndex(oldSize) || oldSize > n) {
    throw new RangeError(`old size ${oldSize} is outside a tree of size ${n}`);
  }
  if (oldSize === 0 || oldSize === n) return [];
  return subproof(hasher, leafHashes, oldSize, 0, n, true);
}
