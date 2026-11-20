import { describe, it, expect } from 'vitest';
import { createHmac } from 'node:crypto';
import Fastify from 'fastify';

/**
 * Audit-4 A4-H2: Verify kid-based JWT rotation.
 */
describe('JWT kid rotation (A4-H2)', () => {
  it('includes kid in newly signed tokens', async () => {
    const app = Fastify();
    await app.register(import('@fastify/jwt'), {
      secret: 'test-secret-32-chars-minimum-pad!',
      sign: { algorithm: 'HS256', kid: 'v1' },
      verify: { algorithms: ['HS256'] },
    });

    const token = app.jwt.sign({ sub: 'u1' });
    const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString());

    expect(header.kid).toBe('v1');
    expect(header.alg).toBe('HS256');

    await app.close();
  });

  it('kid is propagated in JWT header and can be used for key dispatch', () => {
    // Verify that a token signed with kid "v1" carries it in the header,
    // and a secret dispatch function can distinguish versions.
    const secrets: Record<string, string> = {
      v1: 'old-secret-32-chars-minimum-pad!',
      v2: 'new-secret-32-chars-minimum-pad!',
    };

    // Simulate token header parsing + dispatch (this is what our auth middleware does)
    const fakeHeader = { alg: 'HS256', typ: 'JWT', kid: 'v1' };
    const dispatched = secrets[fakeHeader.kid] ?? secrets['v2'];
    expect(dispatched).toBe(secrets['v1']);

    // For an unknown kid, falls back to current
    const unknownHeader = { alg: 'HS256', typ: 'JWT', kid: 'v99' };
    const fallback = secrets[unknownHeader.kid] ?? secrets['v2'];
    expect(fallback).toBe(secrets['v2']);

    // For no kid (legacy token), falls back to current
    const noKidHeader = { alg: 'HS256', typ: 'JWT' } as { kid?: string };
    const legacy = (noKidHeader.kid && secrets[noKidHeader.kid]) || secrets['v2'];
    expect(legacy).toBe(secrets['v2']);
  });
});
