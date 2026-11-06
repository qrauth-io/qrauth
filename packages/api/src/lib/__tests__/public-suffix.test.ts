import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { parsePublicSuffixList, PSL_FILE, PSL_SHA256, registrableDomain } from '../public-suffix.js';

describe('bundled Public Suffix List', () => {
  it('is unmodified: its SHA-256 matches the pinned value and the README', () => {
    const hash = createHash('sha256').update(readFileSync(PSL_FILE)).digest('hex');
    expect(hash).toBe(PSL_SHA256);
    const readme = readFileSync(new URL('../../../data/third-party/psl/README.md', import.meta.url), 'utf8');
    expect(readme).toContain(PSL_SHA256);
  });
});

describe('registrableDomain', () => {
  it.each([
    ['paypal.com', 'com', 'paypal.com'],
    ['www.google.com.hk', 'com.hk', 'google.com.hk'],
    ['login.example.co.uk', 'co.uk', 'example.co.uk'],
    ['efka.gov.gr', 'gov.gr', 'efka.gov.gr'],
    ['xn--kxae4bafwg.xn--pxaix.gr', 'gr', 'xn--pxaix.gr'], // ουτοπία.δπθ.gr
    ['example.xn--qxam', 'xn--qxam', 'example.xn--qxam'], // .ελ
    ['paypa1.github.io', 'github.io', 'paypa1.github.io'], // PRIVATE section
    ['shop.blogspot.com', 'blogspot.com', 'shop.blogspot.com'],
    ['a.b.c.kawasaki.jp', 'c.kawasaki.jp', 'b.c.kawasaki.jp'], // wildcard *.kawasaki.jp
    ['www.city.kawasaki.jp', 'kawasaki.jp', 'city.kawasaki.jp'], // exception !city.kawasaki.jp
    ['host.unknowntld', 'unknowntld', 'host.unknowntld'], // default rule *
    ['PayPal.COM.', 'com', 'paypal.com'],
  ])('%s → suffix %s, domain %s', (host, suffix, domain) => {
    expect(registrableDomain(host)).toMatchObject({ suffix, domain });
  });

  it('a public suffix has no registrable domain', () => {
    expect(registrableDomain('gov.gr')).toEqual({ suffix: 'gov.gr', domain: null, label: null });
    expect(registrableDomain('github.io')).toMatchObject({ domain: null });
  });

  it('parses rules, wildcards, exceptions and IDN rules (stored as punycode)', () => {
    const rules = parsePublicSuffixList('// comment\ncom\n*.ck\n!www.ck\nελ\n\n');
    expect(registrableDomain('a.b.ck', rules)).toMatchObject({ suffix: 'b.ck', domain: 'a.b.ck' });
    expect(registrableDomain('www.ck', rules)).toMatchObject({ suffix: 'ck', domain: 'www.ck' });
    expect(registrableDomain('x.xn--qxam', rules)).toMatchObject({ suffix: 'xn--qxam', domain: 'x.xn--qxam' });
  });
});
