import { describe, expect, it } from 'vitest';

import { NO_DEVICE, parseScanDevice } from '../scan-device.js';

/** ADR-0006 D1: device type, OS and browser names from the user agent (bowser). */

describe('parseScanDevice', () => {
  it.each([
    ['iPhone Safari', 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1', 'mobile', 'iOS', 'Safari'],
    ['Android Chrome', 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36', 'mobile', 'Android', 'Chrome'],
    ['iPad', 'Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1', 'tablet', 'iOS', 'Safari'],
    ['Windows Edge', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0', 'desktop', 'Windows', 'Microsoft Edge'],
    ['macOS Safari', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15', 'desktop', 'macOS', 'Safari'],
    ['Googlebot', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', 'bot', null, 'Googlebot'],
  ])('%s', (_name, ua, deviceType, os, browser) => {
    expect(parseScanDevice(ua)).toEqual({ deviceType, os, browser });
  });

  it('gives nulls for missing or unrecognisable user agents', () => {
    expect(parseScanDevice(null)).toBe(NO_DEVICE);
    expect(parseScanDevice('')).toBe(NO_DEVICE);
    expect(parseScanDevice('curl/8.4.0')).toEqual({ deviceType: null, os: null, browser: null });
  });

  it('bounds the input and the stored names', () => {
    const huge = `Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) ${'x'.repeat(100_000)}`;
    const device = parseScanDevice(huge);
    expect(device.os).toBe('iOS');
    for (const value of Object.values(device)) expect((value ?? '').length).toBeLessThanOrEqual(64);
  });
});
