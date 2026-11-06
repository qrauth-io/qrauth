import { describe, it, expect, vi, afterEach } from 'vitest';
import type { FastifyRequest } from 'fastify';

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

// Whether Cloudflare's visitor-location transform is declared on.
const cloudflare = { visitorLocationHeaders: true };
vi.mock('../config.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../config.js')>();
  return { ...actual, config: { ...actual.config, cloudflare } };
});

const { collectRequestMetadata, geoFromRequest } = await import('../metadata.js');

/**
 * Audit 2026-10 FINDING-015: no client IP leaves the platform for a geo
 * lookup. Location comes from the headers Cloudflare adds, and only when the
 * request reached the API through the local reverse proxy.
 */

function request(headers: Record<string, string>, remoteAddress: string | null = '127.0.0.1'): FastifyRequest {
  return {
    ip: '203.0.113.7',
    headers,
    raw: { socket: { remoteAddress: remoteAddress ?? undefined } },
  } as unknown as FastifyRequest;
}

afterEach(() => {
  vi.restoreAllMocks();
  cloudflare.visitorLocationHeaders = true;
});

describe('geoFromRequest', () => {
  it('reads country and city from the Cloudflare headers', () => {
    expect(geoFromRequest(request({ 'cf-ipcountry': 'GR', 'cf-ipcity': 'Athens' }))).toEqual({
      country: 'Greece',
      city: 'Athens',
    });
  });

  it('gives the country alone when the city header is not sent', () => {
    expect(geoFromRequest(request({ 'cf-ipcountry': 'US' }))).toEqual({ country: 'United States' });
  });

  it.each(['XX', 'T1', '', 'Greece', 'gr', '<b>'])('treats country %j as unknown', (value) => {
    expect(geoFromRequest(request({ 'cf-ipcountry': value }))).toEqual({});
  });

  it('drops a city that is not a plain place name', () => {
    expect(geoFromRequest(request({ 'cf-ipcountry': 'GR', 'cf-ipcity': '<script>x</script>' }))).toEqual({ country: 'Greece' });
  });

  it.each(['203.0.113.50', '10.0.0.5', null])(
    'ignores the headers on a request that did not come through the local proxy (%s)',
    (remoteAddress) => {
      const direct = request({ 'cf-ipcountry': 'GR', 'cf-ipcity': 'Athens' }, remoteAddress);

      expect(geoFromRequest(direct)).toEqual({});
    },
  );

  it('ignores the city header until the Cloudflare transform is declared on', () => {
    // With the transform off, Cloudflare passes a visitor's own CF-IPCity through.
    cloudflare.visitorLocationHeaders = false;

    expect(geoFromRequest(request({ 'cf-ipcountry': 'GR', 'cf-ipcity': 'Spoofville' }))).toEqual({ country: 'Greece' });
  });

  it.each(['127.0.0.1', '::1', '::ffff:127.0.0.1'])('accepts loopback written as %s', (remoteAddress) => {
    expect(geoFromRequest(request({ 'cf-ipcountry': 'GR' }, remoteAddress))).toEqual({ country: 'Greece' });
  });
});

describe('collectRequestMetadata', () => {
  it('makes no outbound request', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');

    const meta = await collectRequestMetadata(
      request({ 'cf-ipcountry': 'GR', 'cf-ipcity': 'Athens', 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/130.0 Safari/537.36' }),
    );

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(meta).toMatchObject({ ipAddress: '203.0.113.7', ipCountry: 'Greece', ipCity: 'Athens', browser: 'Chrome 130' });
  });

  it('leaves location empty when Cloudflare sent none', async () => {
    const meta = await collectRequestMetadata(request({}));

    expect(meta.ipCountry).toBeUndefined();
    expect(meta.ipCity).toBeUndefined();
  });
});
