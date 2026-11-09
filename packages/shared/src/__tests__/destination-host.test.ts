import { describe, expect, it } from 'vitest';

import { createQRCodeSchema, bulkCreateQRCodeSchema, destinationHostRefusal, destinationHttpUrl, httpsUrl } from '../index.js';

const REFUSED = [
  'https://127.0.0.1/',
  'https://10.0.0.1/',
  'https://192.168.1.10:8443/x',
  'https://169.254.169.254/latest/',
  'https://2130706433/', // decimal
  'https://0x7f000001/', // hex
  'https://0x7f.1/', // mixed
  'https://0177.0.0.1/', // octal
  'https://[::1]/',
  'https://[::ffff:127.0.0.1]/', // IPv4-mapped
  'https://[fe80::1]/',
  'https://localhost/',
  'https://LOCALHOST./',
  'https://app.localhost/',
  'https://intranet/',
  'https://printer.local/',
  'https://svc.internal/',
  'https://router.home.arpa/',
  'http://192.168.0.1/',
];
const ALLOWED = [
  'https://example.com/',
  'https://sub.example.co.uk/a?b=1',
  'https://xn--pypal-4ve.com/',
  'https://localhost-tools.example.com/',
  'https://local.example.com/',
  'https://example.internal.example.com/',
  'https://1.2.3.4.nip.example/',
];

describe('destinationHostRefusal', () => {
  it.each(REFUSED)('refuses %s', (url) => {
    expect(destinationHostRefusal(new URL(url).hostname)).not.toBeNull();
  });

  it.each(ALLOWED)('allows %s', (url) => {
    expect(destinationHostRefusal(new URL(url).hostname)).toBeNull();
  });
});

describe('validators', () => {
  it.each(REFUSED.filter((u) => u.startsWith('https')))('httpsUrl (links) and destinationHttpUrl refuse %s', (url) => {
    expect(httpsUrl().safeParse(url).success).toBe(false);
    expect(destinationHttpUrl().safeParse(url).success).toBe(false);
  });

  it('create and bulk refuse a private destination, with the host message', () => {
    const create = createQRCodeSchema.safeParse({ destinationUrl: 'https://10.0.0.1/' });
    expect(create.success).toBe(false);
    expect(JSON.stringify(create.error?.issues)).toContain('public host name');
    expect(bulkCreateQRCodeSchema.safeParse({ items: [{ destinationUrl: 'https://localhost/' }] }).success).toBe(false);
    expect(createQRCodeSchema.safeParse({ destinationUrl: 'https://example.com/' }).success).toBe(true);
  });
});

describe('normalized, without spaces or control characters', () => {
  it.each([' https://example.com/', 'https://example.com/ ', 'ht\ttps://example.com/', 'https://exa\tmple.com/', 'https://example.com/a\nb', 'https://example.com/\u0000', 'https://example.com/a b'])(
    'refuses %j as a link and as a destination',
    (url) => {
      expect(httpsUrl().safeParse(url).success).toBe(false);
      expect(destinationHttpUrl().safeParse(url).success).toBe(false);
    },
  );

  it.each([
    ['HTTPS://Example.COM/a', 'https://example.com/a'],
    ['https://example.com', 'https://example.com/'],
    ['https://example.com:443/x', 'https://example.com/x'],
    ['https:example.com', 'https://example.com/'],
    ['https://раураl.com/', 'https://xn--l-7sba6dbr.com/'],
    ['https://example.com/?q="<x>', 'https://example.com/?q=%22%3Cx%3E'],
  ])('stores %j as %j', (input, normalized) => {
    expect(httpsUrl().parse(input)).toBe(normalized);
    expect(destinationHttpUrl().parse(input)).toBe(normalized);
  });
});
