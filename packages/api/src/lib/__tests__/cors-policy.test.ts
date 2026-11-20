import { describe, it, expect, beforeEach, vi } from 'vitest';
import { corsDecision } from '../cors-policy.js';
import { getAllowedAppOrigins, invalidateAllowedAppOrigins } from '../cors-origins.js';

/**
 * Audit 2026-10 FINDING-023. Origins derived from registered apps are
 * allowed to call the API but never with credentials, and the `null` origin
 * (sandboxed frames, file:, custom-scheme redirect URLs) is never allowed.
 */

const BUILT_IN = ['https://qrauth.io'];
const APP = new Set(['https://shop.example']);
const decide = (origin: string | undefined, permissive = false) =>
  corsDecision({ origin, builtInOrigins: BUILT_IN, appOrigins: APP, permissive });

describe('corsDecision', () => {
  it('allows the dashboard origin with credentials', () => {
    expect(decide('https://qrauth.io')).toEqual({ origin: true, credentials: true });
  });

  it('allows an app-derived origin without credentials', () => {
    expect(decide('https://shop.example')).toEqual({ origin: true, credentials: false });
  });

  it.each(['null', 'https://evil.example', 'https://qrauth.io.evil.example', 'http://qrauth.io'])(
    'refuses %s',
    (origin) => {
      expect(decide(origin)).toEqual({ origin: false, credentials: false });
    },
  );

  it('refuses null even when a custom-scheme app put it in the app set', () => {
    expect(
      corsDecision({ origin: 'null', builtInOrigins: BUILT_IN, appOrigins: new Set(['null']), permissive: false }),
    ).toEqual({ origin: false, credentials: false });
  });

  it('lets a request with no Origin header through (server to server)', () => {
    expect(decide(undefined)).toEqual({ origin: true, credentials: false });
  });

  it('allows everything in dev and test, except that null still gets no credentials', () => {
    expect(decide('https://anything.example', true)).toEqual({ origin: true, credentials: true });
    expect(decide('null', true)).toEqual({ origin: false, credentials: false });
  });
});

describe('getAllowedAppOrigins', () => {
  beforeEach(() => invalidateAllowedAppOrigins());

  it('leaves out the null origin that custom-scheme and opaque redirect URLs produce', async () => {
    const prisma = {
      app: {
        findMany: vi.fn(async () => [
          { redirectUrls: ['https://shop.example/cb', 'myapp://callback', 'data:text/html,x', 'not a url'] },
        ]),
      },
    };

    const origins = await getAllowedAppOrigins(prisma as never);

    expect([...origins]).toEqual(['https://shop.example']);
  });
});
