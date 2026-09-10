import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

/**
 * Audit-4 A4-H1: Verify that Apple ID token handling rejects unverified JWTs.
 */
describe('Apple OAuth ID token verification', () => {
  const ORIGINAL_ENV = process.env;

  beforeEach(() => {
    process.env = {
      ...ORIGINAL_ENV,
      APPLE_CLIENT_ID: 'com.qrauth.test',
      APPLE_CLIENT_SECRET: 'test-secret',
    };
  });

  afterEach(() => {
    process.env = ORIGINAL_ENV;
    vi.restoreAllMocks();
  });

  it('rejects an Apple id_token with invalid signature', async () => {
    // A structurally valid but unsigned JWT (alg: none)
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      iss: 'https://appleid.apple.com',
      sub: 'fake-user-id',
      email: 'attacker@example.com',
      aud: 'com.qrauth.test',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
    })).toString('base64url');
    const fakeJwt = `${header}.${payload}.`;

    // Mock fetch to simulate Apple token endpoint returning a forged id_token
    const mockFetch = vi.fn().mockResolvedValueOnce({
      json: async () => ({
        access_token: 'fake-access-token',
        id_token: fakeJwt,
      }),
    });
    vi.stubGlobal('fetch', mockFetch);

    const { exchangeCodeForUser } = await import('../oauth.js');

    await expect(
      exchangeCodeForUser('apple', 'fake-code', 'https://qrauth.io/auth/callback/apple'),
    ).rejects.toThrow(/Apple ID token verification failed/);
  });
});
