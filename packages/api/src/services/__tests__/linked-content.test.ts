import { describe, expect, it, vi } from 'vitest';

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

const lookups = vi.hoisted(() => ({ verdict: (_url: string) => ({ verdict: 'clean' }) as { verdict: string; threatTypes?: string[]; detail?: string } }));
vi.mock('../destination-screening.js', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  screenDestination: vi.fn(async (url: string) => lookups.verdict(url)),
}));
vi.mock('../../lib/cache.js', () => ({ cacheGet: vi.fn(), cacheSet: vi.fn(), cacheDel: vi.fn(async () => undefined) }));
const sendLinkFlaggedEmail = vi.hoisted(() => vi.fn(async () => undefined));
vi.mock('../../lib/email.js', () => ({ sendLinkFlaggedEmail }));

import { detectPlatform } from '../platform.js';
import { resolveAppLinkScanMode } from '../scan-mode.js';
import { checkContent, flagContentLink, linkUrlHash, pruneLinkFlags, screenLinks } from '../link-screening.js';
import { appLinkTarget } from '../link-verification.js';

const UA = {
  iphone: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
  ipad: 'Mozilla/5.0 (iPad; CPU OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
  ipadDesktop: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
  iosChrome: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.6478.54 Mobile/15E148 Safari/604.1',
  android: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36',
  androidTablet: 'Mozilla/5.0 (Linux; Android 13; SM-X700) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
  samsung: 'Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36',
  windowsPhone: 'Mozilla/5.0 (Mobile; Windows Phone 8.1; Android 4.0; ARM; Trident/7.0; Touch; rv:11.0; IEMobile/11.0) like iPhone OS 7_0_3 Mac OS X AppleWebKit/537 (KHTML, like Gecko) Mobile Safari/537',
  windows: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
  linux: 'Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0',
};

describe('detectPlatform', () => {
  it.each([
    ['iphone', 'ios'],
    ['ipad', 'ios'],
    ['iosChrome', 'ios'],
    ['android', 'android'],
    ['androidTablet', 'android'],
    ['samsung', 'android'],
    ['ipadDesktop', 'other'],
    ['windowsPhone', 'other'],
    ['windows', 'other'],
    ['linux', 'other'],
  ] as const)('%s -> %s', (ua, platform) => {
    expect(detectPlatform(UA[ua])).toBe(platform);
  });

  it('no User-Agent is other', () => {
    expect(detectPlatform(undefined)).toBe('other');
    expect(detectPlatform('')).toBe('other');
  });
});

describe('resolveAppLinkScanMode', () => {
  const base = { configured: 'FLASH', trustState: 'VERIFIED' as const, locationBound: false, platformUrl: 'https://apps.apple.com/x' };

  it('FLASH only when every condition holds', () => {
    expect(resolveAppLinkScanMode(base)).toBe('FLASH');
    expect(resolveAppLinkScanMode({ ...base, configured: 'PAGE' })).toBe('PAGE');
    expect(resolveAppLinkScanMode({ ...base, trustState: 'SIGNED_UNVERIFIED_ISSUER' })).toBe('PAGE');
    expect(resolveAppLinkScanMode({ ...base, trustState: 'UNTRUSTED' })).toBe('PAGE');
    expect(resolveAppLinkScanMode({ ...base, locationBound: true })).toBe('PAGE');
    expect(resolveAppLinkScanMode({ ...base, platformUrl: null })).toBe('PAGE');
    expect(resolveAppLinkScanMode({ ...base, platformUrl: 'http://apps.apple.com/x' })).toBe('PAGE');
    expect(resolveAppLinkScanMode({ ...base, platformUrl: 'https://user:pass@apps.apple.com/x' })).toBe('PAGE');
  });
});

const content_ok = () => ({ iosUrl: 'https://i.example/', androidUrl: 'https://a.example/', fallbackUrl: 'https://w.example/' });

describe('appLinkTarget', () => {
  const content = { iosUrl: 'https://i.example/', androidUrl: 'https://a.example/', fallbackUrl: 'https://w.example/' };
  const input = { content, states: {}, configured: 'FLASH', trustState: 'VERIFIED' as const, locationBound: false };

  it('continues to the platform URL', () => {
    expect(appLinkTarget({ ...input, userAgent: UA.android })).toEqual({ platform: 'android', scanMode: 'FLASH', continueUrl: 'https://a.example/' });
    expect(appLinkTarget({ ...input, userAgent: UA.windows })).toEqual({ platform: 'other', scanMode: 'FLASH', continueUrl: 'https://w.example/' });
  });

  it('never continues for stored content that fails the schema', () => {
    for (const content of [
      { ...content_ok(), iosUrl: 'https://user:pass@evil.example/' },
      { ...content_ok(), iosUrl: 'https://10.0.0.1/' },
      { iosUrl: 'https://i.example/' },
      null,
      'https://i.example/',
    ]) {
      expect(appLinkTarget({ ...input, content, userAgent: UA.iphone })).toEqual({ platform: 'ios', scanMode: 'PAGE' });
    }
  });

  it('does not continue to a flagged platform URL', () => {
    expect(appLinkTarget({ ...input, userAgent: UA.iphone, states: { 'https://i.example/': { flagged: true } } }))
      .toEqual({ platform: 'ios', scanMode: 'PAGE' });
  });
});

describe('screenLinks', () => {
  it('runs at most 4 lookups at once', async () => {
    let inFlight = 0;
    let peak = 0;
    const lookup = vi.fn(async () => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 2));
      inFlight -= 1;
      return { verdict: 'clean' as const };
    });

    const result = await screenLinks(Array.from({ length: 20 }, (_, i) => `https://x.example/${i}`), lookup);

    expect(lookup).toHaveBeenCalledTimes(20);
    expect(peak).toBe(4);
    expect(result.cleanHashes.size).toBe(20);
  });

  it.each([
    ['flagged', { verdict: 'flagged' as const, threatTypes: ['MALWARE'] }],
    ['unavailable', { verdict: 'unavailable' as const, detail: 'timeout' }],
  ])('stops starting lookups after the first %s verdict', async (_label, bad) => {
    const lookup = vi.fn(async (url: string) => {
      await new Promise((r) => setTimeout(r, 2));
      return url.endsWith('/1') ? bad : { verdict: 'clean' as const };
    });

    const result = await screenLinks(Array.from({ length: 20 }, (_, i) => `https://x.example/${i}`), lookup);

    // Links 0-3 start together; link 1 refuses, so at most the three other
    // in-flight slots each take one more before stopping.
    expect(lookup.mock.calls.length).toBeLessThanOrEqual(7);
    expect(result.flagged.length > 0 || result.unavailable).toBe(true);
  });

  it('looks each distinct URL up once and sorts the verdicts', async () => {
    const lookup = vi.fn(async (url: string) =>
      url.includes('bad') ? { verdict: 'flagged' as const, threatTypes: ['MALWARE'] }
        : url.includes('down') ? { verdict: 'unavailable' as const, detail: 'timeout' }
          : { verdict: 'clean' as const });

    const result = await screenLinks(['https://ok.example/', 'https://OK.example/#a', 'https://bad.example/', 'https://down.example/'], lookup);

    expect(lookup).toHaveBeenCalledTimes(3);
    expect(result.flagged).toEqual([{ url: 'https://bad.example/', threatTypes: ['MALWARE'] }]);
    expect(result.unavailable).toBe(true);
    expect(result.cleanHashes).toEqual(new Set([linkUrlHash('https://ok.example/')]));
  });
});

describe('checkContent', () => {
  const LIST = { title: 'T', links: [{ label: 'a', url: 'https://ok.example/' }, { label: 'b', url: 'https://bad.example/' }] };

  it('400 for content that fails its schema, naming the field', async () => {
    const result = await checkContent('link-list', { ...LIST, links: [{ label: 'a', url: 'javascript:alert(1)' }] });
    expect(result).toMatchObject({ ok: false, status: 400 });
    expect(JSON.stringify(result)).toContain('links.0.url');
  });

  it('400 when a linked type has no content', async () => {
    expect(await checkContent('app-link', undefined)).toMatchObject({ ok: false, status: 400 });
  });

  it('422 naming the first listed link', async () => {
    lookups.verdict = (url) => (url.includes('bad') ? { verdict: 'flagged', threatTypes: ['SOCIAL_ENGINEERING'] } : { verdict: 'clean' });
    const result = await checkContent('link-list', LIST);
    expect(result).toEqual({
      ok: false,
      status: 422,
      body: expect.objectContaining({ error: 'DestinationFlagged', url: 'https://bad.example/', threatType: 'SOCIAL_ENGINEERING' }),
    });
  });

  it('503 when a link cannot be screened', async () => {
    lookups.verdict = (url) => (url.includes('bad') ? { verdict: 'unavailable', detail: 'timeout' } : { verdict: 'clean' });
    expect(await checkContent('link-list', LIST)).toMatchObject({ ok: false, status: 503 });
  });

  it('without Web Risk (verdict skipped): 503 unless unscreened links are allowed', async () => {
    lookups.verdict = () => ({ verdict: 'skipped' });
    const refused = await checkContent('link-list', LIST, false);
    expect(refused).toMatchObject({ ok: false, status: 503 });
    expect((refused as { retryable?: boolean }).retryable).toBeUndefined();
    expect(await checkContent('link-list', LIST, true)).toMatchObject({ ok: true });
  });

  it('400 for an unknown content type', async () => {
    expect(await checkContent('hologram', {})).toMatchObject({ ok: false, status: 400 });
  });

  it('passes clean content with its links and verdicts', async () => {
    lookups.verdict = () => ({ verdict: 'clean' });
    const result = await checkContent('link-list', LIST);
    expect(result).toMatchObject({ ok: true, urls: ['https://ok.example/', 'https://bad.example/'] });
  });

  it('other types: schema only, no lookup', async () => {
    expect(await checkContent('vcard', { firstName: 'A', lastName: 'B' })).toMatchObject({ ok: true, screening: null });
    expect(await checkContent('url', undefined)).toMatchObject({ ok: true });
    expect(await checkContent('coupon', undefined)).toMatchObject({ ok: true });
  });
});

describe('pruneLinkFlags', () => {
  it('keeps only the flags of links still present and not screened clean', async () => {
    const deleteMany = vi.fn(async () => ({ count: 1 }));
    const urls = ['https://kept-unscreened.example/', 'https://clean-now.example/'];
    const screening = { flagged: [], unavailable: true, unscreened: false, cleanHashes: new Set([linkUrlHash('https://clean-now.example/')]) };

    await pruneLinkFlags({ qRCodeLinkFlag: { deleteMany } } as never, 'qr1', urls, screening);

    expect(deleteMany).toHaveBeenCalledWith({ where: { qrCodeId: 'qr1', urlHash: { notIn: [linkUrlHash('https://kept-unscreened.example/')] } } });
  });
});

describe('flagContentLink', () => {
  const code = { id: 'qr1', token: 'tok', organizationId: 'org1' };
  const log = { warn: vi.fn() } as never;
  const db = (count: number) => ({
    qRCodeLinkFlag: { createMany: vi.fn(async () => ({ count })) },
    qRCode: { findUnique: vi.fn(async () => ({ organization: { name: 'Acme' } })) },
    membership: { findMany: vi.fn(async () => [{ user: { email: 'owner@acme.example' } }]) },
  });

  it('records the flag once and emails the owners on the first flag only', async () => {
    sendLinkFlaggedEmail.mockClear();
    const first = db(1);
    expect(await flagContentLink(first as never, log, code, 'https://bad.example/', ['MALWARE'])).toBe(true);
    expect(first.qRCodeLinkFlag.createMany).toHaveBeenCalledWith({
      data: [{ qrCodeId: 'qr1', urlHash: linkUrlHash('https://bad.example/'), url: 'https://bad.example/', threatTypes: 'MALWARE' }],
      skipDuplicates: true,
    });
    expect(sendLinkFlaggedEmail).toHaveBeenCalledWith('owner@acme.example', expect.objectContaining({ token: 'tok', url: 'https://bad.example/' }));

    sendLinkFlaggedEmail.mockClear();
    expect(await flagContentLink(db(0) as never, log, code, 'https://bad.example/', ['MALWARE'])).toBe(false);
    expect(sendLinkFlaggedEmail).not.toHaveBeenCalled();
  });
});
