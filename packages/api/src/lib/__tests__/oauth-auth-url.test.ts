import { describe, it, expect, beforeAll } from 'vitest';

beforeAll(() => {
  process.env.GOOGLE_CLIENT_ID ??= 'google-client';
  process.env.GOOGLE_CLIENT_SECRET ??= 'google-secret';
  process.env.MICROSOFT_CLIENT_ID ??= 'microsoft-client';
  process.env.MICROSOFT_CLIENT_SECRET ??= 'microsoft-secret';
  process.env.APPLE_CLIENT_ID ??= 'apple-client';
  process.env.APPLE_CLIENT_SECRET ??= 'apple-secret';
});

async function authUrl(provider: string, state = 'state-1'): Promise<string> {
  const { buildAuthUrl } = await import('../oauth.js');
  return buildAuthUrl(provider, 'https://qrauth.test/cb', state);
}

async function authParams(provider: string): Promise<URLSearchParams> {
  return new URL(await authUrl(provider)).searchParams;
}

describe('buildAuthUrl', () => {
  it('always shows the Microsoft account picker so a remembered personal account can be switched', async () => {
    const params = await authParams('microsoft');

    expect(params.get('prompt')).toBe('select_account');
    expect(params.get('scope')).toBe('openid email profile');
  });

  it('keeps Google on its account picker as before', async () => {
    expect((await authParams('google')).get('prompt')).toBe('select_account');
  });

  it('sends Apple the scope with %20, not +, so Apple shows the share-or-hide email choice', async () => {
    const url = await authUrl('apple');

    expect(url).toContain('scope=name%20email');
    expect(url).not.toContain('scope=name+email');
    expect((await authParams('apple')).get('scope')).toBe('name email');
    expect((await authParams('apple')).get('response_mode')).toBe('form_post');
  });

  it('encodes every space as %20 and keeps a literal + encoded', async () => {
    const url = await authUrl('microsoft', 'a+b c');

    expect(url).toContain('scope=openid%20email%20profile');
    expect(url).toContain('state=a%2Bb%20c');
    expect(new URL(url).searchParams.get('state')).toBe('a+b c');
  });
});
