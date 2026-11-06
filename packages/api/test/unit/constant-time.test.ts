/**
 * Unit tests for the constant-time equality helper
 * (AUDIT-FINDING-002 introduces it; AUDIT-FINDING-012 sweeps the repo
 * to route every cryptographic string compare through it).
 */
import { describe, it, expect } from 'vitest';
import { constantTimeEqualString } from '../../src/lib/constant-time.js';

describe('constantTimeEqualString', () => {
  it('returns true for equal ASCII strings', () => {
    expect(constantTimeEqualString('abc123', 'abc123')).toBe(true);
  });

  it('returns false for one-bit-different strings of equal length', () => {
    expect(constantTimeEqualString('abc123', 'abc124')).toBe(false);
  });

  it('returns false for strings of different length', () => {
    expect(constantTimeEqualString('abc', 'abcd')).toBe(false);
    expect(constantTimeEqualString('abcd', 'abc')).toBe(false);
  });

  it('handles empty strings', () => {
    expect(constantTimeEqualString('', '')).toBe(true);
    expect(constantTimeEqualString('', 'a')).toBe(false);
  });

  it('handles multi-byte UTF-8 characters', () => {
    expect(constantTimeEqualString('café', 'café')).toBe(true);
    // 'café' and 'cafe\u0301' are canonically different even though they
    // render identically — a signature comparison is a byte compare, not a
    // normalization compare, so we surface the difference.
    expect(constantTimeEqualString('café', 'cafe\u0301')).toBe(false);
  });

  it('returns false when either argument is not a string', () => {
    expect(constantTimeEqualString(undefined as unknown as string, 'a')).toBe(false);
    expect(constantTimeEqualString('a', null as unknown as string)).toBe(false);
    expect(constantTimeEqualString(42 as unknown as string, 42 as unknown as string)).toBe(false);
  });

  it('returns false for base64 signatures that differ only in the last byte', () => {
    const a =
      'MEUCIQD' + 'x'.repeat(60) + 'A';
    const b =
      'MEUCIQD' + 'x'.repeat(60) + 'B';
    expect(a.length).toBe(b.length);
    expect(constantTimeEqualString(a, b)).toBe(false);
  });
});
