import { describe, it, expect, afterEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { redactQuery, redactUrl, registerRequestLogHooks, requestLogSerializers } from '../request-logging.js';

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

  it.each(['code', 'state', 'id_token', 'access_token', 'refresh_token', 'token', 'client_secret'])(
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
