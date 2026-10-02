import { describe, it, expect, vi, beforeAll, beforeEach, afterEach } from 'vitest';
import { SignJWT, generateKeyPair, exportJWK, createLocalJWKSet, type JWK } from 'jose';
import {
  getProviders,
  MICROSOFT_CONSUMER_TENANT_ID,
  pickGithubEmail,
  verifyMicrosoftIdToken,
  verifyAppleIdToken,
  exchangeCodeForUser,
} from '../oauth.js';

/**
 * nOAuth fix: every provider mapping must report whether the PROVIDER
 * verified the email, and Microsoft identity must come only from a verified
 * id_token (never Graph `mail`).
 */

const CLIENT_ID = '11111111-2222-3333-4444-555555555555';
const TENANT = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
const CONSUMER_TENANT = '9188040d-6c67-4c5b-b112-36a304b66dad';
const OID = '00000000-0000-0000-0000-00000000abcd';

const ORIGINAL_ENV = process.env;

beforeEach(() => {
  process.env = {
    ...ORIGINAL_ENV,
    GOOGLE_CLIENT_ID: 'g', GOOGLE_CLIENT_SECRET: 'g',
    GITHUB_CLIENT_ID: 'gh', GITHUB_CLIENT_SECRET: 'gh',
    MICROSOFT_CLIENT_ID: CLIENT_ID, MICROSOFT_CLIENT_SECRET: 'ms',
    APPLE_CLIENT_ID: 'com.qrauth.test', APPLE_CLIENT_SECRET: 'a',
  };
});

afterEach(() => {
  process.env = ORIGINAL_ENV;
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Microsoft id_token verification
// ---------------------------------------------------------------------------

let signingKey: CryptoKey;
let otherKey: CryptoKey;
let jwks: ReturnType<typeof createLocalJWKSet>;

beforeAll(async () => {
  const pair = await generateKeyPair('RS256', { extractable: true });
  signingKey = pair.privateKey;
  otherKey = (await generateKeyPair('RS256')).privateKey;
  const publicJwk: JWK = { ...(await exportJWK(pair.publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
  jwks = createLocalJWKSet({ keys: [publicJwk] });
});

interface TokenOpts {
  claims?: Record<string, unknown>;
  key?: CryptoKey;
  aud?: string;
  iss?: string;
  expSeconds?: number;
}

async function msToken(opts: TokenOpts = {}): Promise<string> {
  const tid = (opts.claims?.tid as string | undefined) ?? TENANT;
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ tid, oid: OID, email: 'jane@contoso.example', name: 'Jane', ...opts.claims })
    .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
    .setIssuer(opts.iss ?? `https://login.microsoftonline.com/${tid}/v2.0`)
    .setAudience(opts.aud ?? CLIENT_ID)
    .setIssuedAt(now)
    .setExpirationTime(now + (opts.expSeconds ?? 3600))
    .sign(opts.key ?? signingKey);
}

describe('verifyMicrosoftIdToken', () => {
  it('accepts a correctly signed token for our client and the token tenant issuer', async () => {
    const payload = await verifyMicrosoftIdToken(await msToken(), CLIENT_ID, jwks);
    expect(payload.oid).toBe(OID);
    expect(payload.tid).toBe(TENANT);
  });

  it('rejects a token signed by a key not in the JWKS', async () => {
    await expect(verifyMicrosoftIdToken(await msToken({ key: otherKey }), CLIENT_ID, jwks))
      .rejects.toThrow(/Microsoft ID token verification failed/);
  });

  it('rejects an unsigned (alg: none) token', async () => {
    const enc = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const now = Math.floor(Date.now() / 1000);
    const forged = `${enc({ alg: 'none', typ: 'JWT' })}.${enc({
      iss: `https://login.microsoftonline.com/${TENANT}/v2.0`, aud: CLIENT_ID, tid: TENANT, oid: OID, exp: now + 3600,
    })}.`;
    await expect(verifyMicrosoftIdToken(forged, CLIENT_ID, jwks)).rejects.toThrow(/verification failed/);
  });

  it('rejects a token issued for another client (aud)', async () => {
    await expect(verifyMicrosoftIdToken(await msToken({ aud: 'some-other-app' }), CLIENT_ID, jwks))
      .rejects.toThrow(/verification failed/);
  });

  it('rejects an issuer that does not match the token tid', async () => {
    const otherTenant = 'ffffffff-ffff-ffff-ffff-ffffffffffff';
    await expect(
      verifyMicrosoftIdToken(await msToken({ iss: `https://login.microsoftonline.com/${otherTenant}/v2.0` }), CLIENT_ID, jwks),
    ).rejects.toThrow(/issuer does not match tenant/);
    await expect(
      verifyMicrosoftIdToken(await msToken({ iss: 'https://evil.example/v2.0' }), CLIENT_ID, jwks),
    ).rejects.toThrow(/issuer does not match tenant/);
  });

  it('rejects a non-GUID tid (issuer templating guard)', async () => {
    await expect(verifyMicrosoftIdToken(await msToken({ claims: { tid: 'common' } }), CLIENT_ID, jwks))
      .rejects.toThrow(/tid is not a tenant GUID/);
  });

  it('rejects an expired token', async () => {
    await expect(verifyMicrosoftIdToken(await msToken({ expSeconds: -60 }), CLIENT_ID, jwks))
      .rejects.toThrow(/verification failed/);
  });

  it('rejects a token without oid', async () => {
    await expect(verifyMicrosoftIdToken(await msToken({ claims: { oid: undefined } }), CLIENT_ID, jwks))
      .rejects.toThrow(/verification failed/);
  });
});

describe('Microsoft mapUser (verified id_token claims)', () => {
  const map = (claims: Record<string, unknown>) => getProviders().microsoft.mapUser(claims);

  it('uses oid as providerId and the id_token email', () => {
    expect(map({ oid: OID, tid: TENANT, email: 'jane@contoso.example', xms_edov: true, name: 'Jane' }))
      .toEqual({ providerId: OID, email: 'jane@contoso.example', emailVerified: true, name: 'Jane', avatarUrl: undefined, personalMicrosoftAccount: false });
  });

  it('is unverified when xms_edov is absent, false, or not the boolean true', () => {
    expect(map({ oid: OID, tid: TENANT, email: 'jane@contoso.example' }).emailVerified).toBe(false);
    expect(map({ oid: OID, tid: TENANT, email: 'jane@contoso.example', xms_edov: false }).emailVerified).toBe(false);
    expect(map({ oid: OID, tid: TENANT, email: 'jane@contoso.example', xms_edov: 'true' }).emailVerified).toBe(false);
    expect(map({ oid: OID, tid: TENANT, email: 'jane@contoso.example', xms_edov: 1 }).emailVerified).toBe(false);
  });

  it('treats personal (consumer tenant) accounts without xms_edov as unverified', () => {
    expect(map({ oid: OID, tid: CONSUMER_TENANT, email: 'jane@outlook.example' }).emailVerified).toBe(false);
  });

  it('flags personal accounts by the fixed consumer tenant, and only those', () => {
    expect(CONSUMER_TENANT).toBe(MICROSOFT_CONSUMER_TENANT_ID);
    expect(map({ oid: OID, tid: CONSUMER_TENANT, email: 'jane@outlook.example' }).personalMicrosoftAccount).toBe(true);
    expect(map({ oid: OID, tid: TENANT, email: 'jane@contoso.example', xms_edov: true }).personalMicrosoftAccount).toBe(false);
    expect(map({ oid: OID, email: 'jane@contoso.example' }).personalMicrosoftAccount).toBe(false);
  });

  it('never reads Graph mail / userPrincipalName', () => {
    const u = map({ oid: OID, tid: TENANT, mail: 'victim@corp.example', userPrincipalName: 'victim@corp.example' });
    expect(u.email).toBe('');
    expect(u.emailVerified).toBe(false);
  });

  it('no longer requests the Graph User.Read scope', () => {
    expect(getProviders().microsoft.scopes).toEqual(['openid', 'email', 'profile']);
  });
});

describe('exchangeCodeForUser — microsoft', () => {
  it('fails closed without an id_token and never calls Graph', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce({ json: async () => ({ access_token: 'at' }) });
    vi.stubGlobal('fetch', fetchMock);
    await expect(exchangeCodeForUser('microsoft', 'code', 'https://qrauth.io/cb'))
      .rejects.toThrow(/did not include an id_token/);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(String(fetchMock.mock.calls[0][0])).toContain('/oauth2/v2.0/token');
  });
});

// ---------------------------------------------------------------------------
// Google / Apple / GitHub
// ---------------------------------------------------------------------------

describe('Google mapUser', () => {
  const map = (d: Record<string, unknown>) => getProviders().google.mapUser(d);
  it('is verified only when verified_email === true', () => {
    expect(map({ id: '1', email: 'a@example.com', verified_email: true }).emailVerified).toBe(true);
    expect(map({ id: '1', email: 'a@example.com', verified_email: false }).emailVerified).toBe(false);
    expect(map({ id: '1', email: 'a@example.com' }).emailVerified).toBe(false);
    expect(map({ id: '1', email: 'a@example.com', verified_email: 'true' }).emailVerified).toBe(false);
  });
  it('keeps the v2 `id` as providerId (existing Google users stay matched)', () => {
    expect(map({ id: '1234', email: 'a@example.com', verified_email: true }).providerId).toBe('1234');
  });
});

describe('Apple mapUser', () => {
  const map = (d: Record<string, unknown>) => getProviders().apple.mapUser(d);
  it('accepts email_verified true or "true" only', () => {
    expect(map({ sub: 's', email: 'a@example.com', email_verified: true }).emailVerified).toBe(true);
    expect(map({ sub: 's', email: 'a@example.com', email_verified: 'true' }).emailVerified).toBe(true);
    expect(map({ sub: 's', email: 'a@example.com', email_verified: 'false' }).emailVerified).toBe(false);
    expect(map({ sub: 's', email: 'a@example.com' }).emailVerified).toBe(false);
  });
  it('verifyAppleIdToken rejects a token signed by an unknown key', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({ email: 'a@example.com', email_verified: true })
      .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
      .setIssuer('https://appleid.apple.com').setAudience('com.qrauth.test').setSubject('s')
      .setIssuedAt(now).setExpirationTime(now + 600)
      .sign(otherKey);
    await expect(verifyAppleIdToken(token, 'com.qrauth.test', jwks)).rejects.toThrow(/Apple ID token verification failed/);
  });
});

describe('GitHub email selection', () => {
  it('uses only the verified primary address from /user/emails', () => {
    expect(pickGithubEmail('public@example.com', [
      { email: 'other@example.com', primary: false, verified: true },
      { email: 'primary@example.com', primary: true, verified: true },
    ])).toEqual({ email: 'primary@example.com', emailVerified: true });
  });

  it('marks a public profile email unverified when no verified primary exists', () => {
    expect(pickGithubEmail('victim@example.com', [{ email: 'victim@example.com', primary: true, verified: false }]))
      .toEqual({ email: 'victim@example.com', emailVerified: false });
    expect(pickGithubEmail('victim@example.com', [])).toEqual({ email: 'victim@example.com', emailVerified: false });
    expect(pickGithubEmail(null, { message: 'Bad credentials' })).toEqual({ email: '', emailVerified: false });
  });

  it('exchangeCodeForUser always calls /user/emails, even with a public profile email', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({ json: async () => ({ access_token: 'at' }) })
      .mockResolvedValueOnce({ json: async () => ({ id: 42, login: 'eve', email: 'victim@example.com' }) })
      .mockResolvedValueOnce({ ok: true, json: async () => [{ email: 'victim@example.com', primary: true, verified: false }] });
    vi.stubGlobal('fetch', fetchMock);

    const user = await exchangeCodeForUser('github', 'code', 'https://qrauth.io/cb');

    expect(String(fetchMock.mock.calls[2][0])).toBe('https://api.github.com/user/emails');
    expect(user).toMatchObject({ providerId: '42', email: 'victim@example.com', emailVerified: false });
  });
});
