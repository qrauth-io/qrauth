import { describe, expect, it } from 'vitest';

process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);

const { orgFieldChanges } = await import('../organizations.js');

/** organization.update metadata (ADR-0008): addresses are never recorded, only that they changed. */
describe('orgFieldChanges', () => {
  it('records before/after for names and domains, and changed + a short hash for addresses', () => {
    const changes = orgFieldChanges(
      { name: 'Acme', email: 'ops@acme.test', billingEmail: null, domain: 'acme.test' },
      { name: 'Acme Ltd', email: 'security@acme.test', billingEmail: 'billing@acme.test', domain: 'acme.test' },
    );
    expect(changes).toEqual({
      name: { before: 'Acme', after: 'Acme Ltd' },
      email: { changed: true, afterHash: expect.stringMatching(/^[0-9a-f]{12}$/) },
      billingEmail: { changed: true, afterHash: expect.stringMatching(/^[0-9a-f]{12}$/) },
    });
    expect(JSON.stringify(changes)).not.toMatch(/@acme\.test/);
  });

  it('a cleared address has no hash; equal addresses hash the same', () => {
    expect(orgFieldChanges({ billingEmail: 'b@acme.test' }, { billingEmail: null })).toEqual({ billingEmail: { changed: true, afterHash: null } });
    const a = orgFieldChanges({ email: 'x@acme.test' }, { email: 'ops@acme.test' }) as Record<string, { afterHash: string }>;
    const b = orgFieldChanges({ email: 'y@acme.test' }, { email: 'ops@acme.test' }) as Record<string, { afterHash: string }>;
    expect(a.email.afterHash).toBe(b.email.afterHash);
  });
});
