import { describe, it, expect, beforeEach, vi } from 'vitest';

const store = vi.hoisted(() => new Map<string, { value: string; ttl: number }>());
vi.mock('../cache.js', () => ({
  redis: {
    get: vi.fn(async (k: string) => store.get(k)?.value ?? null),
    set: vi.fn(async (k: string, v: string, _ex: string, ttl: number) => {
      store.set(k, { value: v, ttl });
      return 'OK';
    }),
  },
}));

import { destinationCacheKey, lookupDestination, normalizeDestination } from '../web-risk.js';

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

const NOW = Date.parse('2026-10-27T12:00:00Z');

beforeEach(() => store.clear());

describe('normalizeDestination', () => {
  it.each([
    ['HTTPS://Example.COM:443/Path?q=1#frag', 'https://example.com/Path?q=1'],
    ['http://example.com:80', 'http://example.com/'],
    ['http://example.com:8080/a', 'http://example.com:8080/a'],
    ['javascript:alert(1)', null],
    ['not a url', null],
  ])('%s → %s', (input, expected) => {
    expect(normalizeDestination(input)).toBe(expected);
  });
});

describe('lookupDestination', () => {
  it('skips (no call) when no API key is configured', async () => {
    const fetchImpl = vi.fn();

    expect(await lookupDestination('https://a.example', { apiKey: null, fetchImpl })).toEqual({ verdict: 'skipped' });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('asks for the three threat types and reports a hit, cached until expireTime', async () => {
    const fetchImpl = vi.fn(async () =>
      json({ threat: { threatTypes: ['SOCIAL_ENGINEERING'], expireTime: '2026-10-27T12:10:00Z' } }));

    const verdict = await lookupDestination('https://Evil.example/login#x', { apiKey: 'k', fetchImpl, now: () => NOW });

    expect(verdict).toEqual({ verdict: 'flagged', threatTypes: ['SOCIAL_ENGINEERING'] });
    const called = new URL((fetchImpl.mock.calls[0] as unknown as [string])[0]);
    expect(called.origin + called.pathname).toBe('https://webrisk.googleapis.com/v1/uris:search');
    expect(called.searchParams.get('uri')).toBe('https://evil.example/login');
    expect(called.searchParams.getAll('threatTypes')).toEqual(['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE']);
    expect(store.get(destinationCacheKey('https://evil.example/login'))!.ttl).toBe(600);
  });

  it('reports clean for an empty response and caches it for 30 minutes', async () => {
    const fetchImpl = vi.fn(async () => json({}));

    expect(await lookupDestination('https://ok.example', { apiKey: 'k', fetchImpl })).toEqual({ verdict: 'clean' });
    expect(store.get(destinationCacheKey('https://ok.example/'))!.ttl).toBe(1800);
  });

  it('serves a cached verdict without calling the API (same URL, different fragment)', async () => {
    const fetchImpl = vi.fn(async () => json({ threat: { threatTypes: ['MALWARE'], expireTime: '2026-10-27T13:00:00Z' } }));
    await lookupDestination('https://m.example/x', { apiKey: 'k', fetchImpl, now: () => NOW });

    const again = await lookupDestination('https://M.example/x#other', { apiKey: 'k', fetchImpl });

    expect(again).toEqual({ verdict: 'flagged', threatTypes: ['MALWARE'] });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('reports unavailable on a timeout, an HTTP error or a bad body, and caches nothing', async () => {
    const timeout = vi.fn(async () => { throw Object.assign(new Error('aborted'), { name: 'TimeoutError' }); });
    const http = vi.fn(async () => json({}, 503));
    const bad = vi.fn(async () => new Response('<html>', { status: 200 }));

    expect(await lookupDestination('https://t.example', { apiKey: 'k', fetchImpl: timeout })).toEqual({ verdict: 'unavailable', detail: 'TimeoutError' });
    expect((await lookupDestination('https://t.example', { apiKey: 'k', fetchImpl: http })).verdict).toBe('unavailable');
    expect((await lookupDestination('https://t.example', { apiKey: 'k', fetchImpl: bad })).verdict).toBe('unavailable');
    expect(store.size).toBe(0);
  });

  it('passes a 2 s timeout signal', async () => {
    const fetchImpl = vi.fn(async (_url: string, init?: RequestInit) => {
      expect(init?.signal).toBeInstanceOf(AbortSignal);
      return json({});
    });

    await lookupDestination('https://s.example', { apiKey: 'k', fetchImpl: fetchImpl as unknown as typeof fetch });
  });
});
