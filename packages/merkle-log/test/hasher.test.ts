import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
  constantTimeEqual,
  createHasher,
  inclusionProof,
  rootHash,
  sha256Hasher,
  sha3_256Hasher,
  verifyInclusion,
} from '../src/index.js';

const nodeHash = (alg: string) => (data: Uint8Array) => new Uint8Array(createHash(alg).update(data).digest());

describe('domain separation (RFC 9162 §2.1.1)', () => {
  it('hashes leaves as H(0x00 || data) and nodes as H(0x01 || left || right)', () => {
    const data = new TextEncoder().encode('abc');
    const left = sha3_256Hasher.hashLeaf(new Uint8Array([1]));
    const right = sha3_256Hasher.hashLeaf(new Uint8Array([2]));
    const sha3 = nodeHash('sha3-256');

    expect(sha3_256Hasher.hashLeaf(data)).toEqual(sha3(new Uint8Array([0x00, ...data])));
    expect(sha3_256Hasher.hashChildren(left, right)).toEqual(sha3(new Uint8Array([0x01, ...left, ...right])));
  });

  it('a node can never be passed off as a leaf with the same bytes', () => {
    const left = sha3_256Hasher.hashLeaf(new Uint8Array([1]));
    const right = sha3_256Hasher.hashLeaf(new Uint8Array([2]));
    const node = sha3_256Hasher.hashChildren(left, right);
    const fakeLeaf = sha3_256Hasher.hashLeaf(new Uint8Array([...left, ...right]));
    expect(constantTimeEqual(node, fakeLeaf)).toBe(false);
  });

  it('the empty tree root is the hash of the empty string', () => {
    expect(Buffer.from(sha3_256Hasher.emptyRoot()).toString('hex')).toBe(
      'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
    );
    expect(sha3_256Hasher.size).toBe(32);
    expect(sha256Hasher.size).toBe(32);
  });
});

describe('the bundled SHA3-256 hasher', () => {
  it('produces the same trees as an independent SHA3-256 (node:crypto)', () => {
    const reference = createHasher(nodeHash('sha3-256'), 32);
    fc.assert(
      fc.property(fc.array(fc.uint8Array({ maxLength: 40 }), { minLength: 0, maxLength: 40 }), (inputs) => {
        const ours = inputs.map((d) => sha3_256Hasher.hashLeaf(d));
        const theirs = inputs.map((d) => reference.hashLeaf(d));
        expect(rootHash(sha3_256Hasher, ours)).toEqual(rootHash(reference, theirs));
      }),
      { numRuns: 100 },
    );
  });

  it('is not interchangeable with the SHA-256 hasher', () => {
    const leaves = [1, 2, 3].map((n) => sha3_256Hasher.hashLeaf(new Uint8Array([n])));
    const root = rootHash(sha3_256Hasher, leaves);
    const proof = inclusionProof(sha3_256Hasher, leaves, 1);
    expect(verifyInclusion(sha3_256Hasher, { leafIndex: 1, treeSize: 3, leafHash: leaves[1], proof, root })).toBe(true);
    expect(verifyInclusion(sha256Hasher, { leafIndex: 1, treeSize: 3, leafHash: leaves[1], proof, root })).toBe(false);
  });
});

describe('createHasher', () => {
  it('rejects a hash function whose output length differs from the declared size', () => {
    const hasher = createHasher(nodeHash('sha256'), 48);
    expect(() => hasher.emptyRoot()).toThrow(RangeError);
  });

  it('rejects a size that is not a positive integer', () => {
    expect(() => createHasher(nodeHash('sha256'), 0)).toThrow(RangeError);
    expect(() => createHasher(nodeHash('sha256'), 1.5)).toThrow(RangeError);
  });

  it('returns copies: callers cannot mutate the cached empty root', () => {
    const root = sha3_256Hasher.emptyRoot();
    root[0] ^= 0xff;
    expect(sha3_256Hasher.emptyRoot()[0]).not.toBe(root[0]);
  });
});

describe('constantTimeEqual', () => {
  it('compares byte arrays', () => {
    expect(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
    expect(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
    expect(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2]))).toBe(false);
    expect(constantTimeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });

  it('agrees with a plain comparison on random inputs', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 40 }), fc.uint8Array({ maxLength: 40 }), (a, b) => {
        expect(constantTimeEqual(a, b)).toBe(Buffer.from(a).equals(Buffer.from(b)));
      }),
    );
  });
});
