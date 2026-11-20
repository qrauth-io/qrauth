import { describe, expect, it } from 'vitest';

import {
  hostAllowed,
  normaliseAllowlist,
  normaliseAllowlistEntry,
  policyDestinations,
  urlsOutside,
} from '../allowlist-domains.js';

const entry = (domain: string, includeSubdomains = true) => ({ domain, includeSubdomains });

describe('normaliseAllowlistEntry', () => {
  it('keeps a registrable domain as is, lower-cased', () => {
    expect(normaliseAllowlistEntry(entry('Example.COM'))).toEqual({
      input: 'Example.COM',
      ok: true,
      entry: { domain: 'example.com', includeSubdomains: true, unicode: 'example.com' },
      note: null,
    });
  });

  it('reduces a host to its registrable domain with the Public Suffix List, and says so', () => {
    const www = normaliseAllowlistEntry(entry('www.shop.example.co.uk'));
    expect(www).toMatchObject({ ok: true, entry: { domain: 'example.co.uk' } });
    expect(www.ok && www.note).toBe('Reduced to the registrable domain example.co.uk.');
  });

  it('keeps only the domain of a URL', () => {
    const url = normaliseAllowlistEntry(entry('https://www.example.com/path?q=1'));
    expect(url).toMatchObject({ ok: true, entry: { domain: 'example.com' } });
    expect(url.ok && url.note).toBe('Only the domain is kept. Reduced to the registrable domain example.com.');
  });

  it('treats a private-section suffix as a suffix: alice.github.io is its own domain, github.io is refused', () => {
    expect(normaliseAllowlistEntry(entry('alice.github.io'))).toMatchObject({ ok: true, entry: { domain: 'alice.github.io' }, note: null });
    expect(normaliseAllowlistEntry(entry('github.io'))).toMatchObject({ ok: false, message: expect.stringContaining('public suffix') });
    expect(normaliseAllowlistEntry(entry('co.uk'))).toMatchObject({ ok: false, message: expect.stringContaining('example.co.uk') });
  });

  it('stores an internationalised domain in punycode, with its Unicode form for display', () => {
    const idn = normaliseAllowlistEntry(entry('münchen.de'));
    expect(idn).toMatchObject({ ok: true, entry: { domain: 'xn--mnchen-3ya.de', unicode: 'münchen.de' }, note: null });
    expect(normaliseAllowlistEntry(entry('xn--mnchen-3ya.de'))).toMatchObject({ ok: true, entry: { domain: 'xn--mnchen-3ya.de', unicode: 'münchen.de' } });
  });

  it('accepts a leading wildcard but explains that subdomains come from the setting', () => {
    const wild = normaliseAllowlistEntry(entry('*.example.com'));
    expect(wild).toMatchObject({ ok: true, entry: { domain: 'example.com' } });
    expect(wild.ok && wild.note).toContain('not a wildcard');
  });

  it('refuses IP addresses, localhost, single labels, private names and text that is not a domain', () => {
    for (const bad of ['192.168.1.1', '[::1]', 'localhost', 'intranet', 'printer.local', 'not a domain', 'ftp://example.com']) {
      expect(normaliseAllowlistEntry(entry(bad)).ok, bad).toBe(false);
    }
  });
});

describe('normaliseAllowlist', () => {
  it('merges entries for the same domain (subdomains if either has them) and sorts by domain', () => {
    const { results, allowlist } = normaliseAllowlist([
      entry('zeta.example', false),
      entry('www.example.com', false),
      entry('example.com', true),
    ]);
    expect(allowlist).toEqual([
      { domain: 'example.com', includeSubdomains: true, unicode: 'example.com' },
      { domain: 'zeta.example', includeSubdomains: false, unicode: 'zeta.example' },
    ]);
    expect(results[2]).toMatchObject({ ok: true, note: 'Listed more than once; merged into one entry.' });
  });

  it('reports invalid entries and leaves them out of the list', () => {
    const { results, allowlist } = normaliseAllowlist([entry('example.com'), entry('co.uk')]);
    expect(results.map((r) => r.ok)).toEqual([true, false]);
    expect(allowlist.map((e) => e.domain)).toEqual(['example.com']);
  });
});

describe('hostAllowed', () => {
  const list = [entry('example.com', true), entry('exact.org', false)];

  it('matches the domain itself and, with includeSubdomains, its subdomains', () => {
    expect(hostAllowed('example.com', list)).toBe(true);
    expect(hostAllowed('a.b.example.com', list)).toBe(true);
    expect(hostAllowed('EXAMPLE.com.', list)).toBe(true);
    expect(hostAllowed('exact.org', list)).toBe(true);
    expect(hostAllowed('www.exact.org', list)).toBe(false);
  });

  it('does not match names that only end with or start with an allowed domain', () => {
    expect(hostAllowed('notexample.com', list)).toBe(false);
    expect(hostAllowed('example.com.evil.net', list)).toBe(false);
    expect(hostAllowed('example.co', list)).toBe(false);
  });
});

describe('urlsOutside', () => {
  const list = [entry('xn--mnchen-3ya.de'), entry('example.com')];

  it('compares the URL host in punycode, so a Unicode URL matches its punycode entry', () => {
    expect(urlsOutside(['https://münchen.de/', 'https://www.xn--mnchen-3ya.de/x'], list)).toEqual([]);
  });

  it('refuses a confusable of an allowed domain (Cyrillic а in exаmple.com)', () => {
    expect(urlsOutside(['https://exаmple.com/'], list)).toEqual(['https://exаmple.com/']);
  });

  it('refuses a URL that does not parse', () => {
    expect(urlsOutside(['not a url', 'https://example.com/'], list)).toEqual(['not a url']);
  });
});

describe('policyDestinations', () => {
  it('is the URL of a URL code, the links of smart link and link list codes, nothing for other types', () => {
    expect(policyDestinations({ contentType: 'url', destinationUrl: 'https://a.example/', content: null })).toEqual(['https://a.example/']);
    expect(policyDestinations({ contentType: null, destinationUrl: 'https://a.example/', content: null })).toEqual(['https://a.example/']);
    const app = { iosUrl: 'https://apps.apple.com/app/id1', androidUrl: 'https://play.google.com/x', fallbackUrl: 'https://a.example/app' };
    expect(policyDestinations({ contentType: 'app-link', destinationUrl: 'https://qrauth.io/v/t', content: app })).toEqual([
      app.iosUrl,
      app.androidUrl,
      app.fallbackUrl,
    ]);
    const list = { title: 'Links', links: [{ label: 'Menu', url: 'https://a.example/menu' }] };
    expect(policyDestinations({ contentType: 'link-list', destinationUrl: 'https://qrauth.io/v/t', content: list })).toEqual(['https://a.example/menu']);
    expect(policyDestinations({ contentType: 'vcard', destinationUrl: 'https://qrauth.io/v/t', content: { firstName: 'A' } })).toEqual([]);
  });
});
