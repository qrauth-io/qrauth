import { describe, it, expect, afterEach, vi } from 'vitest';

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

// Whether Cloudflare's visitor-location transform is declared on.
const cloudflare = { visitorLocationHeaders: true };
vi.mock('../config.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../config.js')>();
  return { ...actual, config: { ...actual.config, cloudflare } };
});

const { describeRequester, formatRequester, readRequester } = await import('../oidc-requester.js');

afterEach(() => {
  cloudflare.visitorLocationHeaders = true;
});

const CHROME_MAC =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36';

describe('describeRequester', () => {
  it('takes device, browser and OS from the User-Agent and place from the edge headers', () => {
    expect(describeRequester({ 'user-agent': CHROME_MAC, 'cf-ipcountry': 'GR', 'cf-ipcity': 'Athens' })).toEqual({
      deviceType: 'desktop', browser: 'Chrome 130', os: 'macOS', country: 'GR', city: 'Athens',
    });
  });

  it('leaves the city out until Cloudflare is declared to set it', () => {
    // With the transform off the header is whatever the visitor sent, and
    // it would be shown to the person approving the sign-in.
    cloudflare.visitorLocationHeaders = false;

    expect(describeRequester({ 'user-agent': CHROME_MAC, 'cf-ipcountry': 'GR', 'cf-ipcity': 'Spoofville' })).toEqual({
      deviceType: 'desktop', browser: 'Chrome 130', os: 'macOS', country: 'GR',
    });
  });

  it('leaves the place out when the headers are absent', () => {
    const info = describeRequester({ 'user-agent': CHROME_MAC });
    expect(info.country).toBeUndefined();
    expect(info.city).toBeUndefined();
  });

  it('accepts real place names with accents, spaces and punctuation', () => {
    for (const city of ['São Paulo', "L'Aquila", 'Θεσσαλονίκη', 'Frankfurt (Oder)', 'Stratford-upon-Avon']) {
      expect(describeRequester({ 'cf-ipcity': city }).city).toBe(city);
    }
  });

  it('rejects markup, over-long values and the edge placeholders', () => {
    expect(describeRequester({ 'cf-ipcity': '<img src=x>' }).city).toBeUndefined();
    expect(describeRequester({ 'cf-ipcity': 'a'.repeat(65) }).city).toBeUndefined();
    expect(describeRequester({ 'cf-ipcountry': 'XX' }).country).toBeUndefined();
    expect(describeRequester({ 'cf-ipcountry': 'T1' }).country).toBeUndefined();
    expect(describeRequester({ 'cf-ipcountry': 'gr' }).country).toBeUndefined();
  });
});

describe('readRequester', () => {
  it('returns null for metadata without a well-formed requester', () => {
    expect(readRequester(null)).toBeNull();
    expect(readRequester({})).toBeNull();
    expect(readRequester({ requester: { deviceType: 1 } })).toBeNull();
  });

  it('re-validates stored place values', () => {
    const stored = { requester: { deviceType: 'mobile', browser: 'Safari 18', os: 'iOS', city: '<b>x</b>', country: 'GR' } };
    expect(readRequester(stored)).toEqual({ deviceType: 'mobile', browser: 'Safari 18', os: 'iOS', country: 'GR' });
  });
});

describe('formatRequester', () => {
  it('builds one readable line', () => {
    expect(formatRequester({ deviceType: 'desktop', browser: 'Chrome 130', os: 'macOS', city: 'Athens', country: 'GR' }))
      .toBe('Computer · Chrome 130 on macOS · Athens, GR');
  });

  it('skips unknown parts', () => {
    expect(formatRequester({ deviceType: 'unknown', browser: 'unknown', os: 'unknown' })).toBe('Unknown device');
    expect(formatRequester({ deviceType: 'mobile', browser: 'unknown', os: 'Android', country: 'DE' }))
      .toBe('Phone · Android · DE');
  });
});
