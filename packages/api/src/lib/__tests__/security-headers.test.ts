import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import Fastify from 'fastify';
import helmet from '@fastify/helmet';

import { HELMET_OPTIONS } from '../security-headers.js';

const SECURITY_HEADERS = {
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'SAMEORIGIN',
  'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
  'referrer-policy': 'no-referrer',
  'x-xss-protection': '0',
} as const;

// A header sent more than once comes back as an array.
function headerValues(value: string | string[] | number | undefined): string[] {
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [String(value)];
}

describe('API security headers', () => {
  it.each(['/api/v1/thing', '/health', '/v/AbCd1234', '/sdk/verify-flash.js'])(
    '%s: each security header exactly once, with the expected value',
    async (url) => {
      const app = Fastify();
      await app.register(helmet, HELMET_OPTIONS);
      app.get('/api/v1/thing', async () => ({ ok: true }));
      app.get('/health', async () => ({ status: 'ok' }));
      app.get('/v/:token', async (_req, reply) => reply.type('text/html').send('<p>x</p>'));
      app.get('/sdk/verify-flash.js', async (_req, reply) => reply.type('application/javascript').send('/*x*/'));
      await app.ready();

      const res = await app.inject({ method: 'GET', url });
      expect(res.statusCode).toBe(200);
      for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
        expect(headerValues(res.headers[name]), name).toEqual([value]);
      }
      await app.close();
    },
  );
});

// --- nginx config: the API owns the headers on proxied locations ---------

const SECURITY_HEADER_NAMES = Object.keys(SECURITY_HEADERS);

function readDeployFile(name: string): string {
  return readFileSync(fileURLToPath(new URL(`../../../../../deploy/${name}`, import.meta.url)), 'utf8');
}

function stripComments(conf: string): string {
  return conf.replace(/#.*$/gm, '');
}

/** Text of the block opened by the first `{` at or after `start`, without the braces. */
function blockBody(conf: string, start: number): { body: string; end: number } {
  const open = conf.indexOf('{', start);
  let depth = 0;
  for (let i = open; i < conf.length; i++) {
    if (conf[i] === '{') depth++;
    if (conf[i] === '}') depth--;
    if (depth === 0) return { body: conf.slice(open + 1, i), end: i };
  }
  throw new Error('unbalanced braces in nginx config');
}

/** Directly nested `location` blocks, plus the block body with them removed. */
function splitLocations(body: string): { own: string; locations: { name: string; body: string }[] } {
  const locations: { name: string; body: string }[] = [];
  let own = '';
  let cursor = 0;
  const re = /location\s+([^{]+?)\s*\{/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(body)) !== null) {
    if (match.index < cursor) continue;
    own += body.slice(cursor, match.index);
    const { body: inner, end } = blockBody(body, match.index);
    locations.push({ name: match[1].trim(), body: inner });
    cursor = end + 1;
    re.lastIndex = cursor;
  }
  own += body.slice(cursor);
  return { own, locations };
}

function securityAddHeaders(text: string): string[] {
  return SECURITY_HEADER_NAMES.filter((name) =>
    new RegExp(`^\\s*add_header\\s+${name}\\b`, 'im').test(text),
  );
}

function httpsServerBody(): string {
  const conf = stripComments(readDeployFile('nginx-qrauth-io.conf'));
  const servers = [...conf.matchAll(/server\s*\{/g)].map((m) => blockBody(conf, m.index).body);
  const https = servers.find((s) => /listen\s+443/.test(s));
  if (!https) throw new Error('no listen 443 server block');
  return https;
}

describe('nginx qrauth.io config', () => {
  it('sets no security header at server level (it would be inherited by proxied locations)', () => {
    const { own } = splitLocations(httpsServerBody());
    expect(securityAddHeaders(own)).toEqual([]);
  });

  it('sets no security header in any location proxied to the API', () => {
    const { locations } = splitLocations(httpsServerBody());
    const proxied = locations.filter((l) => l.body.includes('proxy_pass'));
    expect(proxied.map((l) => l.name)).toEqual(
      expect.arrayContaining(['/api/', '/v/', '/a/', '/docs/', '/sdk/', '/health']),
    );
    for (const location of proxied) {
      expect(securityAddHeaders(location.body), location.name).toEqual([]);
    }
  });

  it('sets no security header in the included /internal/ location', () => {
    const conf = stripComments(readDeployFile('nginx-internal-route.conf'));
    expect(conf).toContain('proxy_pass');
    expect(securityAddHeaders(conf)).toEqual([]);
  });

  it('keeps every security header on the SPA (served by nginx itself)', () => {
    const { locations } = splitLocations(httpsServerBody());
    const spa = locations.find((l) => l.name === '/');
    expect(spa).toBeDefined();
    expect(securityAddHeaders(spa?.body ?? '')).toEqual(SECURITY_HEADER_NAMES);
  });

  it('static asset location: nosniff and the SPA HSTS, Cache-Control unchanged', () => {
    const { locations } = splitLocations(httpsServerBody());
    const staticAssets = locations.find((l) => l.name.startsWith('~*') && l.name.includes('js|css'));
    const spa = locations.find((l) => l.name === '/');
    expect(staticAssets).toBeDefined();
    const body = staticAssets?.body ?? '';

    expect(body).not.toContain('proxy_pass');
    expect(securityAddHeaders(body)).toEqual(['x-content-type-options', 'strict-transport-security']);
    expect(addHeaderValue(body, 'x-content-type-options')).toBe('nosniff');
    expect(addHeaderValue(body, 'strict-transport-security')).toBe(
      addHeaderValue(spa?.body ?? '', 'strict-transport-security'),
    );
    expect(addHeaderValue(body, 'cache-control')).toBe('public, immutable');
    expect(body).toMatch(/^\s*expires 30d;/m);
  });
});

describe('nginx qrauth.io /smoke (static smoke-code target)', () => {
  const smokeLocation = () => splitLocations(httpsServerBody()).locations.find((l) => l.name === '= /smoke');

  it('is an exact-match location served by nginx from the repo, not the SPA or the API', () => {
    const body = smokeLocation()?.body ?? '';
    expect(smokeLocation()).toBeDefined();
    expect(body).not.toContain('proxy_pass');
    expect(body).toMatch(/^\s*root\s+\/home\/progressnet\/vqr\/deploy\/smoke;/m);
    expect(body).toMatch(/^\s*try_files\s+\/index\.html\s+=404;/m);
    expect(body).not.toContain('/packages/web/dist');
  });

  it('sends the same security headers as location /, plus X-Robots-Tag noindex', () => {
    const body = smokeLocation()?.body ?? '';
    const spa = splitLocations(httpsServerBody()).locations.find((l) => l.name === '/')?.body ?? '';
    expect(securityAddHeaders(body)).toEqual(SECURITY_HEADER_NAMES);
    for (const name of SECURITY_HEADER_NAMES) {
      expect(addHeaderValue(body, name), name).toBe(addHeaderValue(spa, name));
    }
    expect(addHeaderValue(body, 'x-robots-tag')).toBe('noindex');
  });

  it('the page is plain, noindex, with no scripts and no external assets', () => {
    const html = readDeployFile('smoke/index.html');
    expect(html).toContain('QRAuth smoke target');
    expect(html).toMatch(/<meta name="robots" content="noindex,nofollow">/);
    expect(html).not.toMatch(/<script|<link|<img|<iframe|src=|href=/i);
  });
});

function addHeaderValue(text: string, name: string): string | undefined {
  return new RegExp(`^\\s*add_header\\s+${name}\\s+"([^"]*)"`, 'im').exec(text)?.[1];
}
