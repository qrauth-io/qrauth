import { describe, it, expect } from 'vitest';
import { computePairwiseSub, OidcPairwiseSecretMissingError } from '../oidc-pairwise.js';

const secret = Buffer.from('a'.repeat(32), 'utf8');

describe('computePairwiseSub (ADR-0003 Slice 3b)', () => {
  it('is deterministic — same inputs produce the same sub', () => {
    const a = computePairwiseSub({ userId: 'user-1', sectorIdentifier: 'rp.example.com', pairwiseSecret: secret });
    const b = computePairwiseSub({ userId: 'user-1', sectorIdentifier: 'rp.example.com', pairwiseSecret: secret });
    expect(a).toBe(b);
  });

  it('produces a base64url value with no padding', () => {
    const sub = computePairwiseSub({ userId: 'user-1', sectorIdentifier: 'rp.example.com', pairwiseSecret: secret });
    expect(sub).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(sub).not.toContain('=');
    // HMAC-SHA256 → 32 bytes → 43 base64url chars (unpadded).
    expect(sub).toHaveLength(43);
  });

  it('gives different subs for the same user across different sectors (the privacy property)', () => {
    const s1 = computePairwiseSub({ userId: 'user-1', sectorIdentifier: 'a.example.com', pairwiseSecret: secret });
    const s2 = computePairwiseSub({ userId: 'user-1', sectorIdentifier: 'b.example.com', pairwiseSecret: secret });
    expect(s1).not.toBe(s2);
  });

  it('gives different subs for different users in the same sector', () => {
    const s1 = computePairwiseSub({ userId: 'user-1', sectorIdentifier: 'rp.example.com', pairwiseSecret: secret });
    const s2 = computePairwiseSub({ userId: 'user-2', sectorIdentifier: 'rp.example.com', pairwiseSecret: secret });
    expect(s1).not.toBe(s2);
  });

  it('delimiter safety: (sector="ab", user="cd") differs from (sector="a", user="bcd")', () => {
    const s1 = computePairwiseSub({ userId: 'cd', sectorIdentifier: 'ab', pairwiseSecret: secret });
    const s2 = computePairwiseSub({ userId: 'bcd', sectorIdentifier: 'a', pairwiseSecret: secret });
    expect(s1).not.toBe(s2);
  });

  it('depends on the secret — a different key yields a different sub', () => {
    const other = Buffer.from('b'.repeat(32), 'utf8');
    const s1 = computePairwiseSub({ userId: 'user-1', sectorIdentifier: 'rp.example.com', pairwiseSecret: secret });
    const s2 = computePairwiseSub({ userId: 'user-1', sectorIdentifier: 'rp.example.com', pairwiseSecret: other });
    expect(s1).not.toBe(s2);
  });

  it('throws OidcPairwiseSecretMissingError when the secret is undefined (lazy validation)', () => {
    expect(() =>
      computePairwiseSub({ userId: 'user-1', sectorIdentifier: 'rp.example.com', pairwiseSecret: undefined }),
    ).toThrow(OidcPairwiseSecretMissingError);
  });

  it('throws OidcPairwiseSecretMissingError when the secret is too short (< 32 bytes)', () => {
    expect(() =>
      computePairwiseSub({ userId: 'user-1', sectorIdentifier: 'rp.example.com', pairwiseSecret: Buffer.alloc(16) }),
    ).toThrow(OidcPairwiseSecretMissingError);
  });

  it('the missing-secret error names the env var and the generation command', () => {
    try {
      computePairwiseSub({ userId: 'u', sectorIdentifier: 's', pairwiseSecret: null });
      throw new Error('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(OidcPairwiseSecretMissingError);
      expect((err as Error).message).toContain('OIDC_PAIRWISE_SECRET');
      expect((err as Error).message).toContain('openssl rand -base64 32');
    }
  });
});
