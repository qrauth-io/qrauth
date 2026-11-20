import { constantTimeEqual, half, isIndex, isOdd, isPowerOfTwo } from './bytes.js';
import type { MerkleHasher } from './hasher.js';

/**
 * Proof verification as specified in RFC 9162 §2.1.3.2 (inclusion) and
 * §2.1.4.2 (consistency). Every function returns false for any malformed
 * input (bad size or index, wrong hash length, wrong proof length) and never
 * throws. Root comparisons are constant-time.
 */

export interface InclusionCheck {
  leafIndex: number;
  treeSize: number;
  leafHash: Uint8Array;
  proof: readonly Uint8Array[];
  root: Uint8Array;
}

export interface ConsistencyCheck {
  oldSize: number;
  newSize: number;
  oldRoot: Uint8Array;
  newRoot: Uint8Array;
  proof: readonly Uint8Array[];
}

function allHashSized(hasher: MerkleHasher, hashes: readonly Uint8Array[]): boolean {
  return hashes.every((h) => h instanceof Uint8Array && h.length === hasher.size);
}

/** Shift fn and sn right together while fn is even and non-zero. */
function shiftWhileEven(fn: number, sn: number): [number, number] {
  let f = fn;
  let s = sn;
  while (!isOdd(f) && f !== 0) {
    f = half(f);
    s = half(s);
  }
  return [f, s];
}

/** True when `proof` proves `leafHash` is leaf `leafIndex` of the tree with `root`. */
export function verifyInclusion(hasher: MerkleHasher, check: InclusionCheck): boolean {
  const { leafIndex, treeSize, leafHash, proof, root } = check;
  if (!isIndex(leafIndex) || !isIndex(treeSize) || leafIndex >= treeSize) return false;
  if (!allHashSized(hasher, [leafHash, root, ...proof])) return false;

  let fn = leafIndex;
  let sn = treeSize - 1;
  let r = leafHash;
  for (const p of proof) {
    if (sn === 0) return false;
    if (isOdd(fn) || fn === sn) {
      r = hasher.hashChildren(p, r);
      if (!isOdd(fn)) [fn, sn] = shiftWhileEven(fn, sn);
    } else {
      r = hasher.hashChildren(r, p);
    }
    fn = half(fn);
    sn = half(sn);
  }
  return sn === 0 && constantTimeEqual(r, root);
}

/**
 * True when `proof` shows the tree of `newSize` leaves with `newRoot` is an
 * append-only extension of the tree of `oldSize` leaves with `oldRoot`.
 *
 * A proof from the empty tree (oldSize 0) is rejected: RFC 9162 defines
 * consistency only for 0 < oldSize, and any tree extends the empty tree.
 * Equal sizes need an empty proof and equal roots.
 */
export function verifyConsistency(hasher: MerkleHasher, check: ConsistencyCheck): boolean {
  const { oldSize, newSize, oldRoot, newRoot, proof } = check;
  if (!isIndex(oldSize) || !isIndex(newSize)) return false;
  if (!allHashSized(hasher, [oldRoot, newRoot, ...proof])) return false;
  if (oldSize === 0 || oldSize > newSize) return false;
  if (oldSize === newSize) return proof.length === 0 && constantTimeEqual(oldRoot, newRoot);
  if (proof.length === 0) return false;

  // Step 2: when oldSize is a power of two, the old root is the first node.
  const nodes = isPowerOfTwo(oldSize) ? [oldRoot, ...proof] : [...proof];

  let fn = oldSize - 1;
  let sn = newSize - 1;
  while (isOdd(fn)) {
    fn = half(fn);
    sn = half(sn);
  }

  let fr = nodes[0];
  let sr = nodes[0];
  for (const c of nodes.slice(1)) {
    if (sn === 0) return false;
    if (isOdd(fn) || fn === sn) {
      fr = hasher.hashChildren(c, fr);
      sr = hasher.hashChildren(c, sr);
      if (!isOdd(fn)) [fn, sn] = shiftWhileEven(fn, sn);
    } else {
      sr = hasher.hashChildren(sr, c);
    }
    fn = half(fn);
    sn = half(sn);
  }

  const oldMatches = constantTimeEqual(fr, oldRoot);
  const newMatches = constantTimeEqual(sr, newRoot);
  return sn === 0 && oldMatches && newMatches;
}
