import { describe, it, expect, afterEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { redactParams, redactQuery, redactUrl, registerRequestLogHooks, requestLogSerializers } from '../request-logging.js';

/**
 * Request logs must never contain OAuth codes, tokens or client secrets that
 * arrive in a query string. The path and the non-secret parameters stay, so
 * the logs remain useful.
 */

const R = '[REDACTED]';

describe('redactUrl', () => {
  it('keeps the path and non-secret params of an OAuth callback and redacts code and state', () => {
    const url = '/api/v1/auth/oauth/microsoft/callback?code=1.AbC-secret_code&state=eyJjc3JmIjoi&session_state=0099-ab';

    expect(redactUrl(url)).toBe(
      `/api/v1/auth/oauth/microsoft/callback?code=${R}&state=${R}&session_state=0099-ab`,
    );
  });

  it.each(['code', 'state', 'id_token', 'access_token', 'refresh_token', 'token', 'client_secret', 'error_description'])(
    'redacts %s',
    (key) => {
      expect(redactUrl(`/x?a=1&${key}=s3cr3t-value&b=2`)).toBe(`/x?a=1&${key}=${R}&b=2`);
    },
  );

  it('matches keys case-insensitively and when percent-encoded', () => {
    expect(redactUrl('/x?CODE=abc&Access_Token=def')).toBe(`/x?CODE=${R}&Access_Token=${R}`);
    expect(redactUrl('/x?%63ode=abc')).toBe(`/x?%63ode=${R}`);
  });

  it('redacts every occurrence of a repeated key', () => {
    expect(redactUrl('/x?code=one&code=two')).toBe(`/x?code=${R}&code=${R}`);
  });

  it('does not touch keys that merely contain a secret key name', () => {
    expect(redactUrl('/x?returnTo=/dashboard&session_state=abc&barcode=123&tokens=5'))
      .toBe('/x?returnTo=/dashboard&session_state=abc&barcode=123&tokens=5');
  });

  it('leaves URLs without a query string, empty values and bare keys readable', () => {
    expect(redactUrl('/api/v1/auth/providers')).toBe('/api/v1/auth/providers');
    expect(redactUrl('/x?')).toBe('/x?');
    expect(redactUrl('/x?code=&a=1')).toBe('/x?code=&a=1');
    expect(redactUrl('/x?code&a=1')).toBe('/x?code&a=1');
  });

  it('keeps a value containing = fully redacted and survives malformed encoding', () => {
    expect(redactUrl('/x?token=abc=def==&a=1')).toBe(`/x?token=${R}&a=1`);
    expect(redactUrl('/x?%E0%A4%A=1&code=abc')).toBe(`/x?%E0%A4%A=1&code=${R}`);
  });

  it('redacts in a fragment-less absolute URL too', () => {
    expect(redactUrl('https://qrauth.io/cb?code=abc&x=1')).toBe(`https://qrauth.io/cb?code=${R}&x=1`);
  });
});

describe('redactUrl: more secret query keys (audit 2026-10 FINDING-013)', () => {
  it.each(['code_verifier', 'id_token_hint', 'client_assertion'])('redacts %s', (key) => {
    expect(redactUrl(`/x?a=1&${key}=s3cr3t-value&b=2`)).toBe(`/x?a=1&${key}=${R}&b=2`);
  });

  it('redacts the PKCE verifier on an auth-session poll and keeps the session id', () => {
    const url = '/api/v1/auth-sessions/cmv6abc123/sse?code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    expect(redactUrl(url)).toBe(`/api/v1/auth-sessions/cmv6abc123/sse?code_verifier=${R}`);
  });
});

describe('redactUrl: approval-page and OIDC query secrets', () => {
  const SESSION_TOKEN = 'as_SsLjqiiRjd-UzlD5PXrCARXUijD2ZJLq';

  it.each(['authSessionToken', 'nonce', 'login_hint'])('redacts %s', (key) => {
    expect(redactUrl(`/x?a=1&${key}=s3cr3t-value&b=2`)).toBe(`/x?a=1&${key}=${R}&b=2`);
  });

  it('redacts the approval-page OAuth start and keeps the same-device flag', () => {
    const url = `/api/v1/auth/oauth/microsoft?authSessionToken=${SESSION_TOKEN}&dr=1`;

    expect(redactUrl(url)).toBe(`/api/v1/auth/oauth/microsoft?authSessionToken=${R}&dr=1`);
  });

  it('matches authSessionToken in any case', () => {
    expect(redactUrl(`/x?authsessiontoken=${SESSION_TOKEN}&AUTHSESSIONTOKEN=${SESSION_TOKEN}`))
      .toBe(`/x?authsessiontoken=${R}&AUTHSESSIONTOKEN=${R}`);
  });

  it('redacts state, nonce and login_hint on an OIDC authorize request and keeps the rest', () => {
    const url = '/authorize?response_type=code&client_id=c1&redirect_uri=https%3A%2F%2Frp.example%2Fcb'
      + '&scope=openid&state=rp-state-1&nonce=n-0S6_WzA2Mj&login_hint=jane%40example.com&code_challenge=E9Mel&code_challenge_method=S256';

    expect(redactUrl(url)).toBe(
      '/authorize?response_type=code&client_id=c1&redirect_uri=https%3A%2F%2Frp.example%2Fcb'
      + `&scope=openid&state=${R}&nonce=${R}&login_hint=${R}&code_challenge=E9Mel&code_challenge_method=S256`,
    );
  });

  it('redactQuery covers the new keys too', () => {
    expect(redactQuery({ authSessionToken: SESSION_TOKEN, nonce: 'n', login_hint: 'jane', dr: '1' }))
      .toEqual({ authSessionToken: R, nonce: R, login_hint: R, dr: '1' });
  });
});

describe('redactUrl: non-secret parameters still log normally', () => {
  it('keeps dr, returnTo and utm_* exactly as received', () => {
    const url = '/api/v1/auth/oauth/google?returnTo=/dashboard&dr=1&utm_source=myapps&utm_medium=tile&utm_campaign=entra';

    expect(redactUrl(url)).toBe(url);
  });

  it('keeps dr on the approval page while redacting its path token', () => {
    expect(redactUrl('/a/as_SsLjqiiRjd-UzlD5PXrCARXUijD2ZJLq?dr=1')).toBe(`/a/${R}?dr=1`);
  });
});

describe('redactUrl: secrets inside a relative returnTo URL (one level)', () => {
  const AUTHORIZE = '/authorize?response_type=code&client_id=c1&redirect_uri=https%3A%2F%2Frp.example%2Fcb'
    + '&scope=openid+profile&state=rp-state-1&nonce=n-0S6_WzA2Mj&login_hint=jane%40example.com'
    + '&code_challenge=E9Mel&code_challenge_method=S256';

  function nestedReturnTo(logged: string): string {
    // searchParams decodes the value once: exactly the redirect target the browser would follow.
    return new URL(logged, 'https://op.test').searchParams.get('returnTo') ?? '';
  }

  it('redacts state, nonce and login_hint inside an encoded /authorize returnTo and keeps the rest visible', () => {
    const logged = redactUrl(`/login?returnTo=${encodeURIComponent(AUTHORIZE)}`);
    const inner = nestedReturnTo(logged);

    expect(logged.startsWith('/login?returnTo=')).toBe(true);
    expect(inner).toBe(
      '/authorize?response_type=code&client_id=c1&redirect_uri=https%3A%2F%2Frp.example%2Fcb'
      + `&scope=openid+profile&state=${R}&nonce=${R}&login_hint=${R}`
      + '&code_challenge=E9Mel&code_challenge_method=S256',
    );
    for (const secret of ['rp-state-1', 'n-0S6_WzA2Mj', 'jane%40example.com', 'jane@example.com']) {
      expect(logged).not.toContain(encodeURIComponent(secret));
      expect(inner).not.toContain(secret);
    }
  });

  it('matches the returnTo key case-insensitively', () => {
    const logged = redactUrl(`/login?RETURNTO=${encodeURIComponent('/authorize?state=s1&client_id=c1')}`);

    expect(logged).toBe(`/login?RETURNTO=${encodeURIComponent(`/authorize?state=${R}&client_id=c1`)}`);
  });

  it('leaves returnTo=/dashboard unchanged', () => {
    expect(redactUrl('/api/v1/auth/oauth/google?returnTo=/dashboard')).toBe('/api/v1/auth/oauth/google?returnTo=/dashboard');
    expect(redactUrl('/login?returnTo=%2Fdashboard')).toBe('/login?returnTo=%2Fdashboard');
  });

  it('keeps a returnTo with no secrets inside byte-for-byte', () => {
    const url = `/login?returnTo=${encodeURIComponent('/authorize?client_id=c1&scope=openid')}`;

    expect(redactUrl(url)).toBe(url);
  });

  it('logs a malformed returnTo unchanged and does not throw', () => {
    const url = '/login?returnTo=%E0%A4%A%2Fauthorize%3Fstate%3Ds1&dr=1';

    expect(() => redactUrl(url)).not.toThrow();
    expect(redactUrl(url)).toBe(url);
  });

  it('leaves absolute and protocol-relative returnTo values alone', () => {
    for (const target of ['https://evil.example/cb?state=s1', '//evil.example/cb?state=s1']) {
      const url = `/login?returnTo=${encodeURIComponent(target)}`;
      expect(redactUrl(url)).toBe(url);
    }
  });

  it('goes one level deep only', () => {
    const inner = `/login?returnTo=${encodeURIComponent('/authorize?state=s2')}&state=s1`;
    const logged = redactUrl(`/x?returnTo=${encodeURIComponent(inner)}`);

    expect(nestedReturnTo(logged)).toBe(`/login?returnTo=${encodeURIComponent('/authorize?state=s2')}&state=${R}`);
  });

  it('redactQuery applies the same rule to a parsed (already decoded) returnTo', () => {
    expect(redactQuery({ returnTo: '/authorize?state=s1&client_id=c1', dr: '1' }))
      .toEqual({ returnTo: `/authorize?state=${R}&client_id=c1`, dr: '1' });
    expect(redactQuery({ returnTo: '/dashboard' })).toEqual({ returnTo: '/dashboard' });
  });
});

describe('redactUrl: secrets carried in the path (audit 2026-10 FINDING-013)', () => {
  const TOKEN = 'k3Y5ecret-Tok_en0123456789abcdef';

  it.each([
    [`/api/v1/ephemeral/${TOKEN}/claim`, `/api/v1/ephemeral/${R}/claim`],
    [`/api/v1/auth/verify-email/${TOKEN}`, `/api/v1/auth/verify-email/${R}`],
    [`/api/v1/organizations/invitations/${TOKEN}/accept`, `/api/v1/organizations/invitations/${R}/accept`],
    [`/a/as_${TOKEN}`, `/a/${R}`],
    [`/api/v1/auth-sessions/as_${TOKEN}/approve`, `/api/v1/auth-sessions/${R}/approve`],
    [`/api/v1/auth-sessions/as_${TOKEN}/deny`, `/api/v1/auth-sessions/${R}/deny`],
  ])('%s', (url, expected) => {
    expect(redactUrl(url)).toBe(expected);
    expect(redactUrl(url)).not.toContain(TOKEN);
  });

  it('redacts the path and the query together', () => {
    expect(redactUrl(`/api/v1/ephemeral/${TOKEN}/claim?device=d1&token=abc`)).toBe(
      `/api/v1/ephemeral/${R}/claim?device=d1&token=${R}`,
    );
  });

  it('leaves identifiers that are not secrets alone', () => {
    for (const url of [
      '/v/qr_public_token_123',
      '/api/v1/qrcodes/qr_public_token_123',
      '/api/v1/auth-sessions/cmv6abc123',
      '/api/v1/ephemeral/cmv6abc123',
      '/api/v1/organizations/org_1/invitations',
      '/api/v1/auth/verify-email',
    ]) {
      expect(redactUrl(url)).toBe(url);
    }
  });

  it('copes with a trailing slash', () => {
    expect(redactUrl(`/a/as_${TOKEN}/`)).toBe(`/a/${R}/`);
  });

  it('matches from the start of the path only', () => {
    expect(redactUrl(`/x/a/as_${TOKEN}`)).toBe(`/x/a/as_${TOKEN}`);
  });
});

describe('redactParams', () => {
  it('redacts the token route parameter when the path carried a secret', () => {
    expect(redactParams({ token: 'as_secret' }, '/a/as_secret')).toEqual({ token: R });
    expect(redactParams({ token: 'abc' }, '/api/v1/ephemeral/abc/claim')).toEqual({ token: R });
  });

  it('leaves parameters of other routes alone', () => {
    expect(redactParams({ token: 'qr_public' }, '/v/qr_public')).toEqual({ token: 'qr_public' });
    expect(redactParams({ id: 'cmv6' }, '/api/v1/auth-sessions/cmv6')).toEqual({ id: 'cmv6' });
    expect(redactParams(undefined, '/x')).toBeUndefined();
  });
});

describe('redactQuery', () => {
  it('returns a new object with secret values replaced and the rest untouched', () => {
    const query = { code: 'abc', State: 'def', returnTo: '/dashboard', token: ['a', 'b'] };

    expect(redactQuery(query)).toEqual({ code: R, State: R, returnTo: '/dashboard', token: R });
    expect(query.code).toBe('abc');
  });

  it('passes through anything that is not a plain object', () => {
    expect(redactQuery(undefined)).toBeUndefined();
    expect(redactQuery(null)).toBeNull();
  });
});

describe('request logging wired into Fastify', () => {
  let app: FastifyInstance | null = null;
  const lines: string[] = [];

  async function build(): Promise<FastifyInstance> {
    lines.length = 0;
    const instance = Fastify({
      logger: { level: 'info', stream: { write: (line: string) => { lines.push(line); } }, serializers: requestLogSerializers },
    });
    registerRequestLogHooks(instance);
    instance.get('/api/v1/auth/oauth/:provider/callback', async (_request, reply) => reply.status(400).send({ ok: false }));
    instance.post('/token', async (_request, reply) => reply.status(401).send({ ok: false }));
    await instance.ready();
    return instance;
  }

  afterEach(async () => {
    await app?.close();
    app = null;
  });

  it('logs a callback URL with the path and non-secret params but [REDACTED] for code and state', async () => {
    app = await build();
    const CODE = '1.Aa8ALnT0-very-secret-code';
    const STATE = 'eyJjc3JmIjoic2VjcmV0LXN0YXRlIn0';

    await app.inject({
      method: 'GET',
      url: `/api/v1/auth/oauth/microsoft/callback?code=${CODE}&state=${STATE}&session_state=0099-ab`,
    });

    const output = lines.join('');
    expect(output).not.toContain(CODE);
    expect(output).not.toContain(STATE);
    const expected = `/api/v1/auth/oauth/microsoft/callback?code=${R}&state=${R}&session_state=0099-ab`;
    const parsed = lines.map((l) => JSON.parse(l));
    // Fastify's own "incoming request" line (req serializer), our onRequest line and our onResponse line.
    expect(parsed.find((l) => l.msg === 'incoming request')?.req.url).toBe(expected);
    expect(parsed.some((l) => l.msg === `GET ${expected}` && l.url === expected)).toBe(true);
    expect(parsed.some((l) => typeof l.msg === 'string' && l.msg.startsWith(`GET ${expected} → 400`) && l.url === expected)).toBe(true);
  });

  it('redacts on every route, and never logs the request body', async () => {
    app = await build();

    await app.inject({
      method: 'POST',
      url: '/token?client_secret=cs-secret&access_token=at-secret&refresh_token=rt-secret&id_token=it-secret&token=t-secret&grant=x',
      payload: { client_secret: 'body-secret', code: 'body-code' },
    });

    const output = lines.join('');
    for (const secret of ['cs-secret', 'at-secret', 'rt-secret', 'it-secret', 't-secret', 'body-secret', 'body-code']) {
      expect(output).not.toContain(secret);
    }
    expect(output).toContain('grant=x');
    expect(output).toContain('/token?client_secret=[REDACTED]');
  });

  it('an unknown route answers the usual 404 body but logs the URL redacted', async () => {
    app = await build();

    const res = await app.inject({ method: 'GET', url: '/nope?access_token=nf-secret&x=1' });

    expect(res.statusCode).toBe(404);
    expect(res.json()).toEqual({
      message: 'Route GET:/nope?access_token=nf-secret&x=1 not found',
      error: 'Not Found',
      statusCode: 404,
    });
    const output = lines.join('');
    expect(output).not.toContain('nf-secret');
    expect(output).toContain(`Route GET:/nope?access_token=${R}&x=1 not found`);
  });

  it('the req serializer also redacts a plain req object, as the error handler logs it', () => {
    const serialized = requestLogSerializers.req({ method: 'GET', url: '/cb?code=abc&x=1' } as never);

    expect(serialized.url).toBe(`/cb?code=${R}&x=1`);
    expect(serialized.method).toBe('GET');
  });
});
