import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import type { FastifyCorsOptionsDelegateCallback } from '@fastify/cors';
import { corsDecision } from '../cors-policy.js';

/**
 * Audit 2026-10 FINDING-023, through the real @fastify/cors plugin wired the
 * way server.ts wires it: what a browser actually receives per origin.
 */

const BUILT_IN = ['https://qrauth.io'];
const APP_ORIGINS = new Set(['https://shop.example']);

let app: FastifyInstance;

beforeAll(async () => {
  app = Fastify({ logger: false });
  const delegate: FastifyCorsOptionsDelegateCallback = (request, callback) => {
    const origin = typeof request.headers.origin === 'string' ? request.headers.origin : undefined;
    const decision = corsDecision({ origin, builtInOrigins: BUILT_IN, appOrigins: APP_ORIGINS, permissive: false });
    callback(null, { origin: decision.origin, credentials: decision.credentials, methods: ['GET', 'POST', 'OPTIONS'] });
  };
  await app.register((await import('@fastify/cors')).default, () => delegate);
  app.get('/thing', async () => ({ ok: true }));
  await app.ready();
});

afterAll(async () => {
  await app?.close();
});

const get = (origin?: string) => app.inject({ method: 'GET', url: '/thing', headers: origin ? { origin } : {} });
const preflight = (origin: string) =>
  app.inject({
    method: 'OPTIONS',
    url: '/thing',
    headers: { origin, 'access-control-request-method': 'GET', 'access-control-request-headers': 'x-client-id,x-qrauth-code-verifier' },
  });

describe('CORS as a browser sees it', () => {
  it('the dashboard origin is reflected, with credentials', async () => {
    const res = await get('https://qrauth.io');

    expect(res.headers['access-control-allow-origin']).toBe('https://qrauth.io');
    expect(res.headers['access-control-allow-credentials']).toBe('true');
    expect(String(res.headers.vary)).toContain('Origin');
  });

  it('an app origin is reflected, without credentials, and its preflight allows the custom headers', async () => {
    const res = await get('https://shop.example');
    const pre = await preflight('https://shop.example');

    expect(res.headers['access-control-allow-origin']).toBe('https://shop.example');
    expect(res.headers['access-control-allow-credentials']).toBeUndefined();
    expect(pre.statusCode).toBe(204);
    expect(String(pre.headers['access-control-allow-headers'])).toContain('x-qrauth-code-verifier');
    expect(pre.headers['access-control-allow-credentials']).toBeUndefined();
  });

  it.each(['null', 'https://evil.example'])('%s receives no Access-Control-Allow-Origin', async (origin) => {
    const res = await get(origin);
    const pre = await preflight(origin);

    expect(res.headers['access-control-allow-origin']).toBeUndefined();
    expect(res.headers['access-control-allow-credentials']).toBeUndefined();
    expect(pre.headers['access-control-allow-origin']).toBeUndefined();
  });

  it('a request with no Origin is served without CORS headers', async () => {
    const res = await get();

    expect(res.statusCode).toBe(200);
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });
});
