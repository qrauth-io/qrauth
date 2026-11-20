import { sha256 } from '@noble/hashes/sha2.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { concatBytes } from './bytes.js';

/**
 * Merkle Tree Hash domain separation (RFC 9162 §2.1.1): leaves are hashed
 * with a 0x00 prefix and interior nodes with a 0x01 prefix, so a node hash
 * can never be presented as a leaf hash or the reverse.
 */
const LEAF_PREFIX = new Uint8Array([0x00]);
const NODE_PREFIX = new Uint8Array([0x01]);

export type HashFunction = (data: Uint8Array) => Uint8Array;

export interface MerkleHasher {
  /** Output length of the hash function in bytes. */
  readonly size: number;
  /** Root of the empty tree: HASH() of the empty string. */
  emptyRoot(): Uint8Array;
  /** Leaf hash: HASH(0x00 || data). */
  hashLeaf(data: Uint8Array): Uint8Array;
  /** Interior node hash: HASH(0x01 || left || right). */
  hashChildren(left: Uint8Array, right: Uint8Array): Uint8Array;
}

/**
 * Build a Merkle hasher from a hash function with a fixed output length.
 * Throws RangeError when the function returns a different length, or when
 * a child hash passed to hashChildren has the wrong length.
 */
export function createHasher(hash: HashFunction, size: number): MerkleHasher {
  if (!Number.isInteger(size) || size <= 0) {
    throw new RangeError(`hash size must be a positive integer, got ${size}`);
  }

  const digest = (data: Uint8Array): Uint8Array => {
    const out = hash(data);
    if (out.length !== size) {
      throw new RangeError(`hash function returned ${out.length} bytes, expected ${size}`);
    }
    return out;
  };

  let empty: Uint8Array | null = null;

  return Object.freeze({
    size,
    emptyRoot(): Uint8Array {
      empty ??= digest(new Uint8Array(0));
      return empty.slice();
    },
    hashLeaf(data: Uint8Array): Uint8Array {
      return digest(concatBytes(LEAF_PREFIX, data));
    },
    hashChildren(left: Uint8Array, right: Uint8Array): Uint8Array {
      if (left.length !== size || right.length !== size) {
        throw new RangeError(`child hashes must be ${size} bytes`);
      }
      return digest(concatBytes(NODE_PREFIX, left, right));
    },
  });
}

/** SHA3-256 Merkle hasher (general use; the Trust Records log uses SHA-256). */
export const sha3_256Hasher: MerkleHasher = createHasher(sha3_256, 32);

/** SHA-256 Merkle hasher: the Trust Records log (ADR-0009 D1), RFC 6962/9162-compatible. */
export const sha256Hasher: MerkleHasher = createHasher(sha256, 32);
