import { describe, it, expect, vi, beforeAll, afterEach } from 'vitest';
import { createHash } from 'node:crypto';

beforeAll(() => {
  process.env.GOOGLE_CLIENT_ID ??= 'google-client';
  process.env.GOOGLE_CLIENT_SECRET ??= 'google-secret';
  process.env.GITHUB_CLIENT_ID ??= 'github-client';
  process.env.GITHUB_CLIENT_SECRET ??= 'github-secret';
  process.env.MICROSOFT_CLIENT_ID ??= 'microsoft-client';
  process.env.MICROSOFT_CLIENT_SECRET ??= 'microsoft-secret';
  process.env.APPLE_CLIENT_ID ??= 'apple-client';
  process.env.APPLE_CLIENT_SECRET ??= 'apple-secret';
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/** Runs the token exchange against a token endpoint that refuses, and returns the body that was sent. */
async function tokenRequestBody(provider: string, codeVerifier?: string): Promise<URLSearchParams> {
  const { exchangeCodeForUser } = await import('../oauth.js');
  const fetchMock = vi.fn().mockResolvedValue({ json: async () => ({ error: 'invalid_grant' }) });
  vi.stubGlobal('fetch', fetchMock);

  await expect(exchangeCodeForUser(provider, 'code', 'https://qrauth.test/cb', codeVerifier)).rejects.toThrow();

  return new URLSearchParams(String(fetchMock.mock.calls[0][1].body));
}

describe('PKCE (S256) on the authorization code flow', () => {
  it('generates a 43-char verifier and its S256 challenge', async () => {
    const { generatePkcePair } = await import('../oauth-state-binding.js');

    const { codeVerifier, codeChallenge } = generatePkcePair();

    expect(codeVerifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(codeChallenge).toBe(createHash('sha256').update(codeVerifier).digest('base64url'));
  });

  it.each(['google', 'github', 'microsoft'])('%s: the authorize URL carries the S256 challenge', async (provider) => {
    const { buildAuthUrl } = await import('../oauth.js');

    const params = new URL(buildAuthUrl(provider, 'https://qrauth.test/cb', 'state-1', 'challenge-1')).searchParams;

    expect(params.get('code_challenge')).toBe('challenge-1');
    expect(params.get('code_challenge_method')).toBe('S256');
  });

  it('without a challenge the authorize URL has no PKCE parameters', async () => {
    const { buildAuthUrl } = await import('../oauth.js');

    const params = new URL(buildAuthUrl('apple', 'https://qrauth.test/cb', 'state-1')).searchParams;

    expect(params.has('code_challenge')).toBe(false);
    expect(params.has('code_challenge_method')).toBe(false);
  });

  it.each(['google', 'github', 'microsoft'])('%s: the token exchange sends code_verifier', async (provider) => {
    const body = await tokenRequestBody(provider, 'verifier-1');

    expect(body.get('code_verifier')).toBe('verifier-1');
  });

  it('Apple: the token exchange sends no code_verifier', async () => {
    const body = await tokenRequestBody('apple');

    expect(body.has('code_verifier')).toBe(false);
  });

  it('only Google, GitHub and Microsoft use PKCE', async () => {
    const { usesPkce } = await import('../oauth-state-binding.js');

    expect(['google', 'github', 'microsoft', 'apple'].filter(usesPkce)).toEqual(['google', 'github', 'microsoft']);
  });
});
