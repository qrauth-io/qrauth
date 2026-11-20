import { describe, it, expect } from 'vitest';
import { parseFormBody } from '../form-body.js';
import { checkAuthorizeClientParams, checkAuthorizeParams, checkTokenParams } from '../oidc-request-params.js';

/**
 * Audit 2026-10 FINDING-021: /authorize and /token accept only single,
 * bounded strings for the parameters they read, so a repeated or oversized
 * parameter is answered with invalid_request instead of a 500.
 */

const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
const valid = {
  response_type: 'code',
  client_id: 'qrauth_oidc_abc',
  redirect_uri: 'https://rp.example/callback',
  scope: 'openid email',
  state: 'state-1',
};

describe('parseFormBody', () => {
  it('parses single values as strings', () => {
    expect(parseFormBody('a=1&b=two+words&c=%2F')).toEqual({ a: '1', b: 'two words', c: '/' });
  });

  it('keeps a repeated key as an array, like the query string parser', () => {
    expect(parseFormBody('scope=openid&scope=email&x=1')).toEqual({ scope: ['openid', 'email'], x: '1' });
  });

  it('cannot be used to set a prototype key', () => {
    const parsed = parseFormBody('__proto__=x&constructor=y');

    expect(Object.getPrototypeOf(parsed)).toBeNull();
    expect(({} as Record<string, unknown>).x).toBeUndefined();
  });

  it('returns an empty object for an empty body', () => {
    expect(parseFormBody('')).toEqual({});
  });
});

describe('checkAuthorizeClientParams (before the redirect URI is trusted)', () => {
  it('accepts single strings', () => {
    expect(checkAuthorizeClientParams(valid)).toBeNull();
  });

  it.each(['client_id', 'redirect_uri'])('rejects a repeated %s', (name) => {
    expect(checkAuthorizeClientParams({ ...valid, [name]: ['a', 'b'] })).toBe(`${name} must not be repeated`);
  });

  it('rejects an oversized client_id', () => {
    expect(checkAuthorizeClientParams({ ...valid, client_id: 'x'.repeat(300) })).toMatch(/client_id/);
  });
});

describe('checkAuthorizeParams', () => {
  it('accepts a normal request, with and without PKCE', () => {
    expect(checkAuthorizeParams(valid)).toBeNull();
    expect(checkAuthorizeParams({ ...valid, code_challenge: CHALLENGE, code_challenge_method: 'S256', nonce: 'n', prompt: 'login', max_age: '60' })).toBeNull();
  });

  it.each(['scope', 'state', 'nonce', 'prompt', 'max_age', 'response_type', 'code_challenge', 'code_challenge_method'])(
    'rejects a repeated %s',
    (name) => {
      expect(checkAuthorizeParams({ ...valid, [name]: ['a', 'b'] })).toBe(`${name} must not be repeated`);
    },
  );

  it.each([
    ['too short', CHALLENGE.slice(1)],
    ['too long', `${CHALLENGE}A`],
    ['not base64url', `${CHALLENGE.slice(0, 42)}+`],
  ])('rejects a code_challenge that is %s', (_label, challenge) => {
    expect(checkAuthorizeParams({ ...valid, code_challenge: challenge })).toMatch(/code_challenge/);
  });

  it.each([
    ['state', 4097],
    ['nonce', 1025],
    ['scope', 1025],
  ])('rejects an oversized %s', (name, length) => {
    expect(checkAuthorizeParams({ ...valid, [name]: 'x'.repeat(length) })).toMatch(new RegExp(name));
  });

  it('treats an empty value as absent, as the endpoint does', () => {
    expect(checkAuthorizeParams({ ...valid, code_challenge: '', nonce: '' })).toBeNull();
  });

  it('ignores parameters the endpoint does not read, repeated or not', () => {
    expect(checkAuthorizeParams({ ...valid, ui_locales: ['en', 'el'], login_hint: 'x'.repeat(5000) })).toBeNull();
  });
});

describe('checkTokenParams', () => {
  it('accepts both grants', () => {
    expect(checkTokenParams({ grant_type: 'authorization_code', code: 'c', redirect_uri: 'https://rp.example/cb', code_verifier: 'v'.repeat(43) })).toBeNull();
    expect(checkTokenParams({ grant_type: 'refresh_token', refresh_token: 'r', scope: 'openid' })).toBeNull();
  });

  it.each(['grant_type', 'code', 'redirect_uri', 'code_verifier', 'refresh_token', 'scope', 'client_id', 'client_secret'])(
    'rejects a repeated %s',
    (name) => {
      expect(checkTokenParams({ grant_type: 'authorization_code', [name]: ['a', 'b'] })).toBe(`${name} must not be repeated`);
    },
  );

  it('rejects a value that is not a string', () => {
    expect(checkTokenParams({ grant_type: 'authorization_code', code: { $ne: null } })).toMatch(/code/);
    expect(checkTokenParams({ grant_type: 'authorization_code', code: 42 })).toMatch(/code/);
  });

  it.each([
    ['too short', 'v'.repeat(42)],
    ['too long', 'v'.repeat(129)],
    ['outside the allowed characters', `${'v'.repeat(43)} `],
  ])('rejects a code_verifier that is %s', (_label, verifier) => {
    expect(checkTokenParams({ grant_type: 'authorization_code', code: 'c', code_verifier: verifier })).toMatch(/code_verifier/);
  });

  it('rejects an oversized code', () => {
    expect(checkTokenParams({ grant_type: 'authorization_code', code: 'c'.repeat(513) })).toMatch(/code/);
  });
});
