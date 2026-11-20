import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import Fastify from 'fastify';
import cors from '@fastify/cors';

import { applySdkHeaders } from '../sdk-headers.js';

// The app's CORS plugin plus the onSend hook, composed as in server.ts: the
// plugin answers per origin (here: only the dashboard origin), the hook then
// makes /sdk/ readable from any origin.
async function buildApp() {
  const app = Fastify();
  await app.register(cors, {
    origin: (origin, cb) => cb(null, origin === 'https://qrauth.io' ? origin : false),
  });
  app.addHook('onSend', (request, reply, _payload, done) => {
    applySdkHeaders(request.url, reply);
    done();
  });
  app.get('/sdk/v1/components-0.4.3.js', async (_req, reply) => reply.type('application/javascript').send('/*x*/'));
  app.get('/sdk/verify-flash.js', async (_req, reply) => reply.type('application/javascript').send('/*x*/'));
  app.get('/api/v1/thing', async () => ({ ok: true }));
  await app.ready();
  return app;
}

// A header sent more than once comes back as an array.
function headerValues(value: string | string[] | number | undefined): string[] {
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [String(value)];
}

describe('/sdk/ cross-origin headers', () => {
  it.each(['/sdk/v1/components-0.4.3.js', '/sdk/verify-flash.js'])(
    '%s: exactly one Access-Control-Allow-Origin: *, with or without a third-party Origin',
    async (url) => {
      const app = await buildApp();
      for (const headers of [{}, { origin: 'https://customer.example' }, { origin: 'https://qrauth.io' }]) {
        const res = await app.inject({ method: 'GET', url, headers });
        expect(headerValues(res.headers['access-control-allow-origin'])).toEqual(['*']);
        expect(headerValues(res.headers['cross-origin-resource-policy'])).toEqual(['cross-origin']);
      }
      await app.close();
    },
  );

  it('does not widen CORS outside /sdk/', async () => {
    const app = await buildApp();
    const res = await app.inject({ method: 'GET', url: '/api/v1/thing', headers: { origin: 'https://customer.example' } });
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
    expect(res.headers['cross-origin-resource-policy']).toBeUndefined();
    await app.close();
  });
});

describe('nginx qrauth.io config', () => {
  it('adds no CORS header for /sdk/ (the API owns it)', () => {
    const conf = readFileSync(
      fileURLToPath(new URL('../../../../../deploy/nginx-qrauth-io.conf', import.meta.url)),
      'utf8',
    );
    const block = conf.slice(conf.indexOf('location /sdk/ {'));
    const sdkBlock = block.slice(0, block.indexOf('}'));
    expect(sdkBlock).toContain('proxy_pass');
    expect(sdkBlock.toLowerCase()).not.toMatch(/^\s*add_header\s+access-control-allow-origin/m);
  });
});
