import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  consistencyProof,
  inclusionProof,
  rootHash,
  sha256Hasher,
  verifyConsistency,
  verifyInclusion,
} from '../src/index.js';

/**
 * RFC 6962 reference vectors from transparency-dev/merkle (see
 * test/vectors/transparency-dev/README.md). They use SHA-256; the tree
 * construction is identical to RFC 9162 §2.1.
 */

const dir = new URL('./vectors/transparency-dev/', import.meta.url);
const load = <T>(name: string): T => JSON.parse(readFileSync(new URL(name, dir), 'utf8')) as T;

interface Trees {
  leafInputs: string[];
  rootHashes: string[];
  emptyRootHash: string;
}
interface InclusionProbe {
  file: string;
  leafIdx: number;
  treeSize: number;
  root: string | null;
  leafHash: string | null;
  proof: string[] | null;
  desc: string;
  wantErr: boolean;
}
interface ConsistencyProbe {
  file: string;
  size1: number;
  size2: number;
  root1: string | null;
  root2: string | null;
  proof: string[] | null;
  desc: string;
  wantErr: boolean;
}

const hex = (s: string | null): Uint8Array => Uint8Array.from(Buffer.from(s ?? '', 'hex'));
const toHex = (b: Uint8Array): string => Buffer.from(b).toString('hex');

const trees = load<Trees>('trees.json');
const inclusionProbes = load<InclusionProbe[]>('inclusion.json');
const consistencyProbes = load<ConsistencyProbe[]>('consistency.json');
const leafHashes = trees.leafInputs.map((input) => sha256Hasher.hashLeaf(hex(input)));

describe('RFC 6962 reference trees', () => {
  it('has the reference empty-tree root (SHA-256 of the empty string)', () => {
    expect(toHex(sha256Hasher.emptyRoot())).toBe(trees.emptyRootHash);
  });

  it.each(trees.rootHashes.map((root, size) => [size, root] as const))('root of the first %i leaves', (size, root) => {
    expect(toHex(rootHash(sha256Hasher, leafHashes.slice(0, size)))).toBe(root);
  });
});

describe('RFC 6962 reference inclusion probes', () => {
  it('covers positive and negative cases', () => {
    expect(inclusionProbes.filter((p) => !p.wantErr).length).toBeGreaterThan(0);
    expect(inclusionProbes.filter((p) => p.wantErr).length).toBeGreaterThan(80);
  });

  it.each(inclusionProbes.map((p) => [p.file, p] as const))('%s', (_file, p) => {
    const ok = verifyInclusion(sha256Hasher, {
      leafIndex: p.leafIdx,
      treeSize: p.treeSize,
      leafHash: hex(p.leafHash),
      proof: (p.proof ?? []).map(hex),
      root: hex(p.root),
    });
    expect(ok).toBe(!p.wantErr);
  });

  it('generates the reference proof for every positive probe over the reference leaves', () => {
    for (const p of inclusionProbes.filter((x) => !x.wantErr && x.file.match(/^\d\//))) {
      const generated = inclusionProof(sha256Hasher, leafHashes.slice(0, p.treeSize), p.leafIdx).map(toHex);
      expect(generated, p.file).toEqual(p.proof ?? []);
    }
  });
});

describe('RFC 6962 reference consistency probes', () => {
  it('covers positive and negative cases', () => {
    expect(consistencyProbes.filter((p) => !p.wantErr).length).toBeGreaterThan(0);
    expect(consistencyProbes.filter((p) => p.wantErr).length).toBeGreaterThan(80);
  });

  /**
   * The one deliberate deviation from the reference: with equal sizes the
   * reference accepts any two equal byte strings as roots (this probe uses
   * the 12-byte string "don't care 2"). This library rejects any root that
   * is not exactly one hash long, so the probe fails here.
   */
  const STRICTER_THAN_REFERENCE = new Set(['additional/sizes-are-equal-one-and-proof-is-empty.json']);

  it.each(consistencyProbes.map((p) => [p.file, p] as const))('%s', (file, p) => {
    const ok = verifyConsistency(sha256Hasher, {
      oldSize: p.size1,
      newSize: p.size2,
      oldRoot: hex(p.root1),
      newRoot: hex(p.root2),
      proof: (p.proof ?? []).map(hex),
    });
    expect(ok).toBe(STRICTER_THAN_REFERENCE.has(file) ? false : !p.wantErr);
  });

  it('the stricter probe passes once its roots are real hashes', () => {
    const root = sha256Hasher.hashLeaf(new TextEncoder().encode("don't care 2"));
    expect(verifyConsistency(sha256Hasher, { oldSize: 1, newSize: 1, oldRoot: root, newRoot: root, proof: [] })).toBe(true);
  });

  it('generates the reference proof for every positive probe over the reference leaves', () => {
    for (const p of consistencyProbes.filter((x) => !x.wantErr && x.file.match(/^\d\//))) {
      const generated = consistencyProof(sha256Hasher, leafHashes.slice(0, p.size2), p.size1).map(toHex);
      expect(generated, p.file).toEqual(p.proof ?? []);
    }
  });
});
