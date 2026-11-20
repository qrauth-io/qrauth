import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { DomainService, LOOKALIKE_REFERENCE_TTL_MS, LOOKALIKE_RELOAD_RETRY_MS } from '../domain.js';
import { curatedBrands, lookalikeMessage, normalizeHost, parentDomains, parseCuratedList, registrableLabel } from '../lookalike.js';

/**
 * Lookalike detection (ADR-0007): UTS #39 confusable skeletons, mixed-script
 * labels and the curated protected list, on top of the edit-distance rules.
 */

const ISSUER = 'org_issuer';

function service(extraOrgs: Array<{ id: string; name: string; domain: string; domainReviewStatus?: string; domainReview?: unknown }> = [], destinations: Array<{ destinationUrl: string; organizationId: string; name: string }> = []) {
  const prisma = {
    organization: {
      findMany: vi.fn(async () => [{ id: ISSUER, name: 'Issuer Ltd', domain: 'issuer-shop.example' }, { id: 'org_acme', name: 'Acme Bank', domain: 'acme-bank.gr' }, ...extraOrgs]),
    },
    qRCode: {
      findMany: vi.fn(async () => destinations.map((d) => ({ destinationUrl: d.destinationUrl, organizationId: d.organizationId, organization: { name: d.name } }))),
    },
  };
  return { svc: new DomainService(prisma as never), prisma };
}

const check = (svc: DomainService, url: string) => svc.checkUrlAgainstVerifiedDomains(url, ISSUER);

describe('flagged: homoglyphs of protected domains', () => {
  it.each([
    ['https://раураl.com/login', 'paypal.com'], // Cyrillic
    ['https://xn--80aa0cbo65f.com/', 'paypal.com'], // the same, as punycode
    ['https://аррӏе.com/id', 'apple.com'], // all-Cyrillic whole-script confusable
    ['https://gοοgle.com/', 'google.com'], // Greek omicron
    ['https://gօօgle.com/', 'google.com'], // Armenian oh
    ['https://paypa1.com/', 'paypal.com'], // ASCII digit one
    ['https://rnicrosoft.com/', 'microsoft.com'], // rn for m
    ['https://g0v.gr/', 'gov.gr'],
    ['https://eur0bank.gr/', 'eurobank.gr'],
    ['https://login.eurоbank.gr/', 'eurobank.gr'], // Cyrillic о in the registrable part, with a subdomain
    ['https://νινα.com/', 'viva.com'], // all-Greek label confusable with a Latin brand
    ['https://acrne-bank.gr/', 'acme-bank.gr'], // verified organization (rn for m)
    ['https://ᏴᎪᎡᏟᏞᎪᎽᏚ.co.uk/', 'barclays.co.uk'], // whole-script Cherokee, capital letters
    ['https://ᏼꭺꭱꮯꮮꭺꮍꮪ.co.uk/', 'barclays.co.uk'], // the same in Cherokee small letters (IDNA maps them to capitals)
    ['https://xn--68drb0f5gvag9n.co.uk/', 'barclays.co.uk'], // as punycode
  ])('%s looks like %s', async (url, domain) => {
    const { svc } = service();
    const result = await check(svc, url);
    expect(result.isSuspicious).toBe(true);
    expect(result.warnings.some((w) => w.domain === domain && w.reason === 'confusable')).toBe(true);
  });

  it.each([
    ['https://xn--80aa0cbo65f.fr/', 'PayPal'], // whole-script Cyrillic brand name on another TLD
    ['https://paypa1.co.uk/', 'PayPal'],
    ['https://g00gle.com.hk/', 'Google'],
    ['https://paypa1.github.io/', 'PayPal'], // a tenant of a shared platform (PSL private section)
    ['https://rnicrosoft.blogspot.com/', 'Microsoft sign-in'],
  ])('a confusable spelling of a brand name on any TLD: %s', async (url, brand) => {
    const { svc } = service();
    const result = await check(svc, url);
    expect(result.isSuspicious).toBe(true);
    expect(result.warnings[0]).toMatchObject({ verifiedOrgName: brand, reason: 'confusable' });
  });

  it('a near miss on a long protected name is still caught by edit distance on skeletons', async () => {
    const { svc } = service();
    const result = await check(svc, 'https://eurobamk.gr/');
    expect(result.isSuspicious).toBe(true);
    expect(result.warnings[0]).toMatchObject({ domain: 'eurobank.gr', reason: 'one_char_difference' });
  });
});

describe('flagged: mixed scripts in one label', () => {
  it.each([
    ['https://pаypal-help.com/', ['Latin', 'Cyrillic']],
    ['https://ηellenic-shop.gr/', ['Greek', 'Latin']],
    ['https://xn--ellenic-shop-yzi.gr/', ['Greek', 'Latin']],
  ])('%s', async (url, scripts) => {
    const { svc } = service();
    const result = await check(svc, url);
    expect(result.isSuspicious).toBe(true);
    const mixed = result.warnings.find((w) => w.reason === 'mixed_script');
    expect(mixed).toMatchObject({ scripts, verifiedOrgName: '' });
    expect(lookalikeMessage(mixed!)).toContain(`mixes ${scripts.join(' and ')} letters`);
  });
});

describe('not flagged', () => {
  it.each([
    'https://ουτοπία.δπθ.gr/', // a real Greek IDN (Democritus University)
    'https://xn--kxae4bafwg.xn--pxaix.gr/', // the same, as punycode
    'https://παράδειγμα.δοκιμή/', // IANA's Greek test domain
    'https://εθνικήτράπεζα.gr/', // Greek spelling of a bank name, not confusable with nbg.gr
    'https://ελληνικά.ελ/',
    'https://δήμοςαθηναίων.gr/',
    'https://example.com/',
    'https://my-small-cafe.gr/menu',
  ])('legitimate: %s', async (url) => {
    const { svc } = service();
    expect((await check(svc, url)).isSuspicious).toBe(false);
  });

  it.each([
    'https://paypal.com/', 'https://www.paypal.com/x', 'https://checkout.paypal.com/', // the protected domain and its subdomains
    'https://paypal.de/', 'https://paypal.me/someone', // the brand's other official domains
    'https://accounts.google.com/', 'https://login.microsoftonline.com/', 'https://appleid.apple.com/',
    'https://efka.gov.gr/', 'https://www.gov.gr/ipiresies', 'https://acme-bank.gr/', 'https://ebank.acme-bank.gr/',
  ])('protected or official: %s', async (url) => {
    const { svc } = service();
    expect((await check(svc, url)).isSuspicious).toBe(false);
  });

  it.each(['https://www.google.com.hk/', 'https://google.it/', 'https://www.amazon.co.jp/', 'https://paypal.fr/'])(
    "a brand's own name on another TLD is not a lookalike of it: %s",
    async (url) => {
      const { svc } = service();
      expect((await check(svc, url)).isSuspicious).toBe(false);
    },
  );

  it.each(['https://wolt.com/', 'https://viva.com/', 'https://diva.gr/', 'https://nova.gr/', 'https://visa.gr/'])(
    'short protected names match on skeleton only, and protected brands never flag each other: %s',
    async (url) => {
      const { svc } = service();
      expect((await check(svc, url)).isSuspicious).toBe(false);
    },
  );

  it("the issuer's own domain is not a lookalike when it resembles nothing; there is no blanket exemption", async () => {
    const { svc } = service();
    expect((await svc.checkUrlAgainstVerifiedDomains('https://issuer-shop.example/', ISSUER)).isSuspicious).toBe(false);
    expect((await svc.checkUrlAgainstVerifiedDomains('https://pay.issuer-shop.example/', ISSUER)).isSuspicious).toBe(false);
    // A verified domain is never flagged by another organization's verified
    // reference (it was reviewed when verified, D9) ...
    const own = service([{ id: 'org_x', name: 'X', domain: 'acme-banks.gr' }]).svc;
    expect((await own.checkUrlAgainstVerifiedDomains('https://acme-banks.gr/', 'org_x')).isSuspicious).toBe(false);
    // ... but curated brands still apply to the issuer's own verified domain.
    const brand = service([{ id: 'org_y', name: 'Y', domain: 'paypa1.com' }]).svc;
    expect((await brand.checkUrlAgainstVerifiedDomains('https://paypa1.com/', 'org_y')).warnings[0]).toMatchObject({ domain: 'paypal.com', source: 'curated' });
  });
});

describe('strict brands: the exact name on an unlisted TLD', () => {
  it.each([
    ['https://aade.com/', 'AADE'],
    ['https://paypal.xyz/login', 'PayPal'],
    ['https://www.gsis.com/', 'GSIS / TaxisNet'],
    ['https://eurobank.co/', 'Eurobank'],
    ['https://aade.okta.com/', 'AADE'], // as a tenant of a multi-tenant domain
    ['https://microsoftonline.net/', 'Microsoft sign-in'],
  ])('%s is a lookalike of %s', async (url, brand) => {
    const { svc } = service();
    const result = await check(svc, url);
    expect(result.isSuspicious).toBe(true);
    expect(result.warnings.find((w) => w.verifiedOrgName === brand)).toMatchObject({ reason: 'brand_name' });
  });

  it.each([
    'https://google.it/', 'https://amazon.de/', 'https://www.amazon.co.jp/', // non-strict brands
    'https://paypal.fr/', 'https://visa.de/', 'https://ing.nl/', // a strict brand's listed country domains
    'https://wise.gr/', 'https://alpha.com/', 'https://viva.de/', 'https://chase.gr/', // ordinary words stay non-strict
  ])('passes: %s', async (url) => {
    const { svc } = service();
    expect((await check(svc, url)).isSuspicious).toBe(false);
  });
});

describe('ASCII homoglyphs on short curated names', () => {
  it.each([
    ['https://vvise.com/', 'Wise', 'homoglyph_match'],
    ['https://vvolt.com/', 'Wolt', 'homoglyph_match'],
    ['https://w-ise.com/', 'Wise', 'homoglyph_match'],
    ['https://rne.com/', 'Apple', 'confusable'], // rn for m (me.com); already in the Unicode data
  ])('%s looks like %s (%s)', async (url, brand, reason) => {
    const { svc } = service();
    const result = await check(svc, url);
    expect(result.isSuspicious).toBe(true);
    expect(result.warnings.find((w) => w.verifiedOrgName === brand)).toMatchObject({ reason });
  });

  it('a different short name passes', async () => {
    const { svc } = service();
    expect((await check(svc, 'https://nbq.gr/')).isSuspicious).toBe(false);
  });
});

describe('diacritics on curated brand names', () => {
  it.each([
    ['https://äpple.com/', 'Apple'],
    ['https://åpple.com/', 'Apple'],
    ['https://a\u0308pple.com/', 'Apple'], // combining diaeresis
    ['https://päypal.com/', 'PayPal'],
    ['https://vísa.com/', 'Visa'],
    ['https://ñbg.gr/', 'National Bank of Greece'],
  ])('%s is a lookalike of %s', async (url, brand) => {
    const { svc } = service();
    const result = await check(svc, url);
    expect(result.isSuspicious).toBe(true);
    expect(result.warnings.find((w) => w.verifiedOrgName === brand)).toMatchObject({ reason: 'confusable' });
  });

  it('Greek words with accents are not brand names once accents are removed', async () => {
    const { svc } = service();
    for (const url of ['https://αθήνα.gr/', 'https://κυβέρνηση.gr/', 'https://ποδήλατο.gr/']) {
      expect((await check(svc, url)).isSuspicious).toBe(false);
    }
  });
});

describe('multi-tenant protected domains', () => {
  it.each([
    ['https://paypa1.sharepoint.com/', 'PayPal'],
    ['https://раураl.sharepoint.com/', 'PayPal'],
    ['https://eur0bank.atlassian.net/', 'Eurobank'],
    ['https://g00gle.blogspot.com/', 'Google'],
    ['https://rnicrosoft.github.io/', 'Microsoft sign-in'],
    ['https://paypa1.my.salesforce.com/', 'PayPal'], // tenant under a listed broader domain
    // Each hyphen-separated part of a tenant label: confusable or a strict brand's exact name.
    ['https://paypa1-login.sharepoint.com/', 'PayPal'],
    ['https://paypal-secure.googleusercontent.com/', 'PayPal'],
    ['https://secure-eurobank.sharepoint.com/', 'Eurobank'],
    ['https://aade-tax.sharepoint.com/', 'AADE'],
    ['https://раураl-login.sharepoint.com/', 'PayPal'],
  ])('a tenant label is checked like a registered name: %s', async (url, brand) => {
    const { svc } = service();
    const result = await check(svc, url);
    expect(result.isSuspicious).toBe(true);
    expect(result.warnings.some((w) => w.verifiedOrgName === brand)).toBe(true);
  });

  it.each([
    'https://sharepoint.com/', 'https://contoso.sharepoint.com/sites/hr', 'https://my-team.atlassian.net/',
    'https://lh3.googleusercontent.com/a.png', 'https://octocat.github.io/', 'https://us02web.zoom.us/j/1',
    'https://login.salesforce.com/', 'https://acme.my.salesforce.com/',
    // Ordinary hyphenated tenant names, a non-strict brand's name, and `gov`
    // (gov.gr is itself a public suffix, so its name is a common word).
    'https://contoso-hr.sharepoint.com/', 'https://my-team.atlassian.net/', 'https://sales-ops.sharepoint.com/',
    'https://google-fans.sharepoint.com/', 'https://gov-team.sharepoint.com/', 'https://eu-west.googleusercontent.com/',
  ])('the apex and ordinary tenants pass: %s', async (url) => {
    const { svc } = service();
    expect((await check(svc, url)).isSuspicious).toBe(false);
  });
});

describe('verified organizations as references', () => {
  it('a verified domain that is itself a lookalike of a curated brand is not a reference', async () => {
    const { svc } = service([{ id: 'org_evil', name: 'Evil Inc', domain: 'g00gle.com' }]);
    expect((await check(svc, 'https://google.com/')).isSuspicious).toBe(false);
    expect((await check(svc, 'https://g00gle.com/')).warnings[0]).toMatchObject({ domain: 'google.com', source: 'curated' });
  });

  it('a verified reference never flags a curated domain or a non-multi-tenant subdomain of one', async () => {
    const { svc } = service([{ id: 'org_y', name: 'Y', domain: 'paypal-community.example' }]);
    for (const url of ['https://paypal.com/', 'https://www.paypal.com/x', 'https://login.microsoftonline.com/']) {
      expect((await check(svc, url)).isSuspicious).toBe(false);
    }
  });

  it('the message names only curated brands, never a verified organization', async () => {
    const { svc } = service();
    const result = await check(svc, 'https://acrne-bank.gr/');
    expect(result.warnings[0]).toMatchObject({ domain: 'acme-bank.gr', verifiedOrgName: 'Acme Bank', source: 'verified' });
    expect(lookalikeMessage(result.warnings[0])).toBe('This address looks like acme-bank.gr, but it is a different site. Proceed with caution.');
  });
});

describe('warnings and messages', () => {
  it('one warning per protected brand, strongest first, with a "looks like" message', async () => {
    const { svc } = service();
    const result = await check(svc, 'https://paypa1.com/');
    expect(result.warnings.filter((w) => w.verifiedOrgName === 'PayPal')).toHaveLength(1);
    expect(lookalikeMessage(result.warnings[0])).toBe('This address looks like paypal.com (PayPal), but it is a different site. Proceed with caution.');
  });
});

describe('caching (scan path)', () => {
  afterEach(() => vi.restoreAllMocks());

  it('loads the protected set once and answers repeated hosts from cache (keyed by host, not URL)', async () => {
    const { svc, prisma } = service();
    const first = await check(svc, 'https://раураl.com/a?x=1');
    expect(await check(svc, 'https://раураl.com/b?y=2')).toBe(first);
    await check(svc, 'https://example.org/');
    expect(prisma.organization.findMany).toHaveBeenCalledTimes(1);
    expect(prisma.qRCode.findMany).toHaveBeenCalledTimes(1);
  });

  it('a change in the protected set applies after the 5-minute reload (new generation)', async () => {
    const now = vi.spyOn(Date, 'now').mockReturnValue(1_000_000);
    const { svc, prisma } = service();
    expect((await check(svc, 'https://newbank-online.gr/')).isSuspicious).toBe(false);
    prisma.organization.findMany.mockResolvedValue([{ id: 'org_new', name: 'New Bank', domain: 'newbank-0nline.gr' }]);
    now.mockReturnValue(1_000_000 + LOOKALIKE_REFERENCE_TTL_MS - 1);
    expect((await check(svc, 'https://newbank-online.gr/')).isSuspicious).toBe(false); // still the old set
    now.mockReturnValue(1_000_000 + LOOKALIKE_REFERENCE_TTL_MS + 1);
    expect((await check(svc, 'https://newbank-online.gr/')).warnings[0]).toMatchObject({ domain: 'newbank-0nline.gr' });
  });

  it('before any successful load, a failed load serves the curated list, logs, and retries after the back-off', async () => {
    const now = vi.spyOn(Date, 'now').mockReturnValue(2_000_000);
    const log = { error: vi.fn() };
    const { prisma } = service();
    const svc = new DomainService(prisma as never, log);
    prisma.organization.findMany.mockRejectedValueOnce(new Error('db down'));

    const result = await check(svc, 'https://раураl.com/');
    expect(result.warnings.some((w) => w.domain === 'paypal.com')).toBe(true); // curated still applies
    expect(log.error).toHaveBeenCalledWith(expect.objectContaining({ event: 'lookalike.reference_reload_failed', servingPrevious: false }), expect.any(String));
    await check(svc, 'https://acrne-bank.gr/');
    expect(prisma.organization.findMany).toHaveBeenCalledTimes(1); // no retry before the back-off

    now.mockReturnValue(2_000_000 + LOOKALIKE_RELOAD_RETRY_MS + 1);
    expect((await check(svc, 'https://acrne-bank.gr/')).warnings[0]).toMatchObject({ domain: 'acme-bank.gr' });
    expect(prisma.organization.findMany).toHaveBeenCalledTimes(2);
  });

  it('a failed reload keeps serving the previous set, never throws', async () => {
    const now = vi.spyOn(Date, 'now').mockReturnValue(3_000_000);
    const log = { error: vi.fn() };
    const { prisma } = service();
    const svc = new DomainService(prisma as never, log);
    await check(svc, 'https://example.org/');
    prisma.qRCode.findMany.mockRejectedValueOnce(new Error('db down'));
    now.mockReturnValue(3_000_000 + LOOKALIKE_REFERENCE_TTL_MS + 1);

    await expect(check(svc, 'https://acrne-bank.gr/')).resolves.toMatchObject({ isSuspicious: true }); // Acme from the previous set
    expect(log.error).toHaveBeenCalledWith(expect.objectContaining({ servingPrevious: true }), expect.any(String));
  });
});

describe('normalisation helpers', () => {
  it('punycode to Unicode, NFKC and lowercase', () => {
    expect(normalizeHost('XN--80AA0CBO65F.COM.')).toEqual({ ascii: 'xn--80aa0cbo65f.com', unicode: normalizeHost('xn--80aa0cbo65f.com').unicode });
    // IDNA keeps Cherokee capitals; they are not lowercased before the skeleton.
    expect(normalizeHost(new URL('https://ꭺꭱ.example/').hostname).unicode).toBe('ᎪᎡ.example');
    expect(normalizeHost('ｐａｙｐａｌ.com'.normalize('NFKC')).unicode).toBe('paypal.com');
  });

  it('registered name from the Public Suffix List', () => {
    expect(registrableLabel('www.google.com.hk')).toBe('google');
    expect(registrableLabel('login.example.co.uk')).toBe('example');
    expect(registrableLabel('efka.gov.gr')).toBe('efka');
    expect(registrableLabel('xn--kxae4bafwg.xn--pxaix.gr')).toBe('δπθ');
    expect(registrableLabel('paypa1.github.io')).toBe('paypa1');
    expect(registrableLabel('gov.gr')).toBe('gov');
    expect(registrableLabel('paypal.com')).toBe('paypal');
  });

  it('parent domains with at least two labels', () => {
    expect(parentDomains('a.b.example.gr')).toEqual(['a.b.example.gr', 'b.example.gr', 'example.gr']);
    expect(parentDomains('localhost')).toEqual([]);
  });
});

describe('curated protected list', () => {
  it('parses: about 200 domains, each listed once, all lowercase ASCII', () => {
    const brands = curatedBrands();
    const domains = brands.flatMap((b) => b.domains);
    expect(domains.length).toBeGreaterThanOrEqual(190);
    expect(new Set(domains).size).toBe(domains.length);
    expect(brands.find((b) => b.name === 'PayPal')?.domains).toContain('paypal.com');
    for (const d of ['gov.gr', 'gsis.gr', 'aade.gr', 'nbg.gr', 'piraeusbank.gr', 'eurobank.gr', 'alpha.gr', 'microsoftonline.com', 'icloud.com', 'google.com']) {
      expect(domains).toContain(d);
    }
  });

  it('refuses malformed lines', () => {
    expect(() => parseCuratedList('PayPal paypal.com')).toThrow(/line 1/);
    expect(() => parseCuratedList('PayPal: PayPal.com')).toThrow(/bad domain/);
    expect(() => parseCuratedList('PayPal: https://paypal.com')).toThrow(/bad domain/);
    expect(parseCuratedList('# comment\n\nCrypto.com: crypto.com')).toEqual([{ name: 'Crypto.com', strict: false, wordlike: false, domains: ['crypto.com'], multiTenant: [] }]);
    expect(parseCuratedList('Slack: @slack.com')).toEqual([{ name: 'Slack', strict: false, wordlike: false, domains: ['slack.com'], multiTenant: ['slack.com'] }]);
    expect(parseCuratedList('AADE [strict]: aade.gr')).toEqual([{ name: 'AADE', strict: true, wordlike: false, domains: ['aade.gr'], multiTenant: [] }]);
    expect(parseCuratedList('Visa [strict wordlike]: visa.com')).toEqual([{ name: 'Visa', strict: true, wordlike: true, domains: ['visa.com'], multiTenant: [] }]);
    expect(() => parseCuratedList('AADE [loose]: aade.gr')).toThrow(/unknown flag/);
    expect(() => parseCuratedList('Visa [wordlike]: visa.com')).toThrow(/strict brands only/);
  });

  it('the file documents how to update it', () => {
    const text = readFileSync(new URL('../../../data/protected-domains.txt', import.meta.url), 'utf8');
    expect(text).toMatch(/Format: one brand per line/);
    expect(text).toMatch(/Policy:/);
  });
});

describe('reviewDomain (ADR-0007 D9, D10)', () => {
  it('does not apply an approved exemption: the approved lookalike still shows its matches', async () => {
    const approved = { id: 'org_m', name: 'M', domain: 'paypa1.com', domainReviewStatus: 'APPROVED', domainReview: { domain: 'paypa1.com', decision: 'approved' } };
    const { svc } = service([approved]);
    // The exemption applies to the organization's own codes ...
    expect((await svc.checkUrlAgainstVerifiedDomains('https://paypa1.com/', 'org_m')).isSuspicious).toBe(false);
    // ... but the review of the domain itself still reports the match.
    const review = await svc.reviewDomain('paypa1.com', 'org_m');
    expect(review.isSuspicious).toBe(true);
    expect(review.warnings[0]).toMatchObject({ domain: 'paypal.com', source: 'curated' });
  });
});

describe('verified destinations that resemble a verified domain (memo across reloads)', () => {
  it('re-evaluates destinations when the verified domains change', async () => {
    const { svc, prisma } = service([], [{ destinationUrl: 'https://bigc0rp.com/login', organizationId: 'org_acme', name: 'Acme Bank' }]);
    const domainsFlagging = async () => (await check(svc, 'https://blgc0rp.com/')).warnings.map((w) => w.domain);

    // No verified bigcorp.com yet: the destination is a reference.
    expect(await domainsFlagging()).toContain('bigc0rp.com');

    // bigcorp.com becomes verified: on the next load the destination is no longer one.
    prisma.organization.findMany.mockResolvedValue([
      { id: ISSUER, name: 'Issuer Ltd', domain: 'issuer-shop.example' },
      { id: 'org_acme', name: 'Acme Bank', domain: 'acme-bank.gr' },
      { id: 'org_big', name: 'Big Corp', domain: 'bigcorp.com' },
    ]);
    DomainService.clearCaches(prisma);
    const after = await domainsFlagging();
    expect(after).toContain('bigcorp.com');
    expect(after).not.toContain('bigc0rp.com');

    // And back: the verification ends, the destination is a reference again.
    prisma.organization.findMany.mockResolvedValue([
      { id: ISSUER, name: 'Issuer Ltd', domain: 'issuer-shop.example' },
      { id: 'org_acme', name: 'Acme Bank', domain: 'acme-bank.gr' },
    ]);
    DomainService.clearCaches(prisma);
    expect(await domainsFlagging()).toContain('bigc0rp.com');
  });
});
