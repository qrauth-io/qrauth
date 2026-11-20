import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';

import { buildFlashScript, FLASH_SCRIPT, registerFlashScriptRoute } from '../flash-script.js';
import { buildFlashParts } from '../../renderers/flash.js';

const PUBLIC_ROOT = fileURLToPath(new URL('../../../public', import.meta.url));
const SCRIPT_SOURCE = readFileSync(`${PUBLIC_ROOT}/sdk/verify-flash.js`);

describe('hashed flash script name', () => {
  it('is derived from the file contents', () => {
    const hash = createHash('sha256').update(SCRIPT_SOURCE).digest('hex').slice(0, 16);
    expect(FLASH_SCRIPT.path).toBe(`/sdk/verify-flash.${hash}.js`);
    expect(FLASH_SCRIPT.body.equals(SCRIPT_SOURCE)).toBe(true);
  });

  it('changes when the script changes', () => {
    const edited = buildFlashScript(Buffer.concat([SCRIPT_SOURCE, Buffer.from('\n')]));
    expect(edited.path).not.toBe(FLASH_SCRIPT.path);
  });

  it('is the path the verify page references', () => {
    const parts = buildFlashParts('FLASH', 'https://pay.example.com/', '#16A34A');
    expect(parts.headScript).toBe(`<script src="${FLASH_SCRIPT.path}" defer></script>`);
  });
});

describe('serving', () => {
  async function buildApp() {
    const app = Fastify();
    await app.register(fastifyStatic, { root: PUBLIC_ROOT, prefix: '/', decorateReply: false });
    registerFlashScriptRoute(app);
    await app.ready();
    return app;
  }

  it('hashed path: the script, cached for a year', async () => {
    const app = await buildApp();
    const res = await app.inject({ method: 'GET', url: FLASH_SCRIPT.path });
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toMatch(/^application\/javascript/);
    expect(res.headers['cache-control']).toBe('public, max-age=31536000, immutable');
    expect(res.rawPayload.equals(SCRIPT_SOURCE)).toBe(true);
    await app.close();
  });

  it('unhashed path: still served, not cached', async () => {
    const app = await buildApp();
    const res = await app.inject({ method: 'GET', url: '/sdk/verify-flash.js' });
    expect(res.statusCode).toBe(200);
    expect(res.headers['cache-control']).toBe('public, max-age=0');
    expect(res.rawPayload.equals(SCRIPT_SOURCE)).toBe(true);
    await app.close();
  });
});

// The script replaces the page after FLASH_MS; every flash animation must
// have finished by then, with some margin for a slow frame.
const MIN_MARGIN_MS = 100;

function secondsToMs(value: string): number {
  return Math.round(parseFloat(value) * 1000);
}

/** Latest end (delay + duration) of any animation declared in the flash CSS. */
function latestAnimationEndMs(css: string): number {
  let latest = 0;
  for (const [, body] of css.matchAll(/\{([^{}]*)\}/g)) {
    const shorthand = /(?:^|;)\s*animation:\s*([^;]+)/.exec(body)?.[1] ?? '';
    const times = shorthand.match(/\d*\.?\d+s\b/g) ?? [];
    const duration = /animation-duration:\s*(\d*\.?\d+)s/.exec(body)?.[1] ?? times[0]?.slice(0, -1);
    const delay = /animation-delay:\s*(\d*\.?\d+)s/.exec(body)?.[1] ?? times[1]?.slice(0, -1) ?? '0';
    if (duration) latest = Math.max(latest, secondsToMs(duration) + secondsToMs(delay));
  }
  return latest;
}

describe('flash timing', () => {
  it('every flash animation ends before the redirect', () => {
    const flashMs = Number(/var FLASH_MS = (\d+);/.exec(SCRIPT_SOURCE.toString())?.[1]);
    expect(flashMs).toBe(600);

    const { css } = buildFlashParts('FLASH', 'https://pay.example.com/', '#16A34A');
    const end = latestAnimationEndMs(css);
    expect(end).toBe(450);
    expect(flashMs - end).toBeGreaterThanOrEqual(MIN_MARGIN_MS);
  });
});
