import { describe, it, expect } from 'vitest';
import { stableStringify } from '../crypto.js';

describe('stableStringify', () => {
  // ---------------------------------------------------------------
  // Existing behavior (regression)
  // ---------------------------------------------------------------
  it('sorts object keys at all nesting levels', () => {
    expect(stableStringify({ z: 1, a: { c: 3, b: 2 } }))
      .toBe('{"a":{"b":2,"c":3},"z":1}');
  });

  it('serializes null and undefined as "null"', () => {
    expect(stableStringify(null)).toBe('null');
    expect(stableStringify(undefined)).toBe('null');
  });

  it('serializes primitives', () => {
    expect(stableStringify(42)).toBe('42');
    expect(stableStringify('hello')).toBe('"hello"');
    expect(stableStringify(true)).toBe('true');
    expect(stableStringify(false)).toBe('false');
  });

  it('serializes arrays with stable element ordering', () => {
    expect(stableStringify([3, 1, 2])).toBe('[3,1,2]');
  });

  it('produces byte-identical output for reordered keys', () => {
    const a = stableStringify({ x: 1, y: 2 });
    const b = stableStringify({ y: 2, x: 1 });
    expect(a).toBe(b);
  });

  // ---------------------------------------------------------------
  // Audit-3 M-1: edge cases
  // ---------------------------------------------------------------
  it('serializes Date objects as ISO 8601 strings', () => {
    const d = new Date('2026-04-16T12:00:00.000Z');
    expect(stableStringify(d)).toBe('"2026-04-16T12:00:00.000Z"');
  });

  it('throws on invalid Date', () => {
    expect(() => stableStringify(new Date('invalid'))).toThrow('invalid Date');
  });

  it('serializes BigInt as a quoted string', () => {
    expect(stableStringify(BigInt(123456789))).toBe('"123456789"');
    expect(stableStringify(BigInt(-42))).toBe('"-42"');
  });

  it('throws on NaN', () => {
    expect(() => stableStringify(NaN)).toThrow('non-finite number');
  });

  it('throws on Infinity', () => {
    expect(() => stableStringify(Infinity)).toThrow('non-finite number');
    expect(() => stableStringify(-Infinity)).toThrow('non-finite number');
  });

  it('treats undefined in arrays as null', () => {
    // eslint-disable-next-line no-sparse-arrays
    expect(stableStringify([1, undefined, 3])).toBe('[1,null,3]');
  });

  it('skips undefined values in objects', () => {
    expect(stableStringify({ a: 1, b: undefined, c: 3 })).toBe('{"a":1,"c":3}');
  });

  // ---------------------------------------------------------------
  // Determinism property tests
  // ---------------------------------------------------------------
  it('is deterministic across 100 random key orderings', () => {
    const keys = ['alpha', 'beta', 'gamma', 'delta', 'epsilon'];
    const canonical = stableStringify(
      Object.fromEntries(keys.map((k, i) => [k, i])),
    );

    for (let i = 0; i < 100; i++) {
      const shuffled = [...keys].sort(() => Math.random() - 0.5);
      const obj = Object.fromEntries(shuffled.map((k) => [k, keys.indexOf(k)]));
      expect(stableStringify(obj)).toBe(canonical);
    }
  });

  it('nested objects with mixed types produce stable output', () => {
    const input = {
      z: [1, 'two', null, { b: true, a: false }],
      a: new Date('2026-01-01T00:00:00.000Z'),
      m: BigInt(999),
    };
    const result = stableStringify(input);
    expect(stableStringify(input)).toBe(result);
    expect(result).toContain('"a":"2026-01-01T00:00:00.000Z"');
    expect(result).toContain('"m":"999"');
    expect(result).toContain('"z":[1,"two",null,{"a":false,"b":true}]');
  });
});
