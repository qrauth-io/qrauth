import { readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';

import { DomainService } from '../domain.js';
import { curatedBrands } from '../lookalike.js';
import { recordLookalikeIncident } from '../lookalike-incidents.js';
import {
  KEYWORDS_FILE,
  brandWithKeyword,
  containsRun,
  embeddedName,
  hasCredentialKeyword,
  hasKeyword,
  hostTokens,
  keywordForm,
  parseKeywords,
  phishingKeywords,
  protectedNameLabels,
  protectedNameTokens,
  tokenSkeleton,
} from '../lookalike-words.js';

/**
 * Brand-in-host rules (ADR-0007 D11): a protected domain's name in front of
 * another registrable domain, a strict brand's name as a hyphen token, and a
 * strict brand's name run together with a phishing keyword.
 */

const ISSUER = 'org_issuer';

function service(orgs: Array<{ id: string; name: string; domain: string; domainReviewStatus?: string; domainReview?: unknown }> = []) {
  const prisma = {
    organization: { findMany: vi.fn(async () => [{ id: 'org_big', name: 'Big Corp', domain: 'bigcorp.com' }, ...orgs]) },
    qRCode: { findMany: vi.fn(async () => []) },
  };
  return new DomainService(prisma as never);
}

const check = (host: string, org = ISSUER, svc = service()) => svc.checkUrlAgainstVerifiedDomains(`https://${host}/`, org);

describe('brand as a subdomain prefix or hyphen-joined name (embedded_domain)', () => {
  it.each([
    ['eurobank.gr.secure-login.com', 'Eurobank'],
    ['www.paypal.com.account-check.net', 'PayPal'],
    ['paypal-com-login.net', 'PayPal'],
    ['eurobank-gr.example', 'Eurobank'],
    ['aade.gr.myaccount.app', 'AADE'],
    ['optimabank-gr.com', 'Optima bank'],
    ['paypa1.com.account-check.net', 'PayPal'], // confusable spelling of the name
    ['paypal-com.evil.net', 'PayPal'], // strict, distinctive: the hyphen form alone
    ['eurobank-gr-login.com', 'Eurobank'],
    ['eurobank.gr.secure-login.com', 'Eurobank'],
    ['db.com.evil.org', 'Deutsche Bank'], // dotted: every protected domain
    ['visa.com.evil.net', 'Visa'],
    ['gov-gr-login.info', 'Hellenic Government (gov.gr)'], // short name: hyphen form with a keyword
    ['visa-gr-login.com', 'Visa'], // wordlike: hyphen form with a keyword
    ['alpha-gr-login.com', 'Alpha Bank'], // not strict: hyphen form with a keyword
    ['login.bigcorp.com.evil.io', 'Big Corp'], // a verified organization's domain, dotted
    ['bigcorp-com-login.support', 'Big Corp'], // verified, hyphen form with a keyword
  ])('%s', async (host, brand) => {
    const result = await check(host);
    expect(result.isSuspicious).toBe(true);
    expect(result.warnings[0]).toMatchObject({ verifiedOrgName: brand, reason: 'embedded_domain' });
  });

  it.each([
    'alpha-gr.com', 'nova-gr.com', 'public-gr.com', 'alpha-gr-consulting.com', 'vodafone-gr-shop.com', // not strict
    'visa-gr.com', // wordlike
    'ing-be.com', 'db-com.org', 'gov-gr.info', // shorter than 4 characters
    'bigcorp-com.support', // a verified organization's domain, hyphen form alone
  ])('hyphen form without a keyword, unless strict and distinctive: %s', async (host) => {
    expect((await check(host)).isSuspicious).toBe(false);
  });

  it.each([
    ['paypalcom-login.net', 'PayPal'],
    ['paypalcom.net', 'PayPal'], // strict, distinctive: alone
    ['paypalcouk-verify.com', 'PayPal'],
    ['eurobankgr.com', 'Eurobank'],
    ['alphagr-login.com', 'Alpha Bank'], // not strict: with a keyword
    ['govgr-login.info', 'Hellenic Government (gov.gr)'], // short: with a keyword
    ['visacom-secure.net', 'Visa'], // wordlike: with a keyword
    ['deutschebankde-login.com', 'Deutsche Bank'],
  ])('name run together with its TLD in one token: %s', async (host, brand) => {
    const result = await check(host);
    expect(result.isSuspicious).toBe(true);
    expect(result.warnings[0]).toMatchObject({ verifiedOrgName: brand, reason: 'embedded_domain' });
  });

  it.each(['alphagr.com', 'novagr-shop.com', 'govgr.info', 'visacom.net', 'ingbe.com', 'dbcom-tools.org'])(
    'name run together with its TLD, without a keyword, unless strict and distinctive: %s',
    async (host) => {
      expect((await check(host)).isSuspicious).toBe(false);
    },
  );

  it('a verified organization\'s domain run together with its TLD needs a keyword', async () => {
    const svc = service([{ id: 'org_taxi', name: 'Athens Taxi', domain: 'taxi.gr' }]);
    expect((await check('athens-taxigr.com', ISSUER, svc)).isSuspicious).toBe(false);
    expect((await check('taxigr-login.com', ISSUER, svc)).warnings[0]).toMatchObject({ verifiedOrgName: 'Athens Taxi', reason: 'embedded_domain' });
  });

  it('a verified organization\'s domain in hyphen form needs a keyword (athens-taxi-gr.com)', async () => {
    const svc = service([{ id: 'org_taxi', name: 'Athens Taxi', domain: 'taxi.gr' }]);
    expect((await check('athens-taxi-gr.com', ISSUER, svc)).isSuspicious).toBe(false);
    expect((await check('taxi.gr.evil.io', ISSUER, svc)).warnings[0]).toMatchObject({ verifiedOrgName: 'Athens Taxi', reason: 'embedded_domain' });
  });

  it.each(['www.google.com.hk', 'paypal.com.au', 'sites.google.com', 'eurobank.cy', 'minfin.gov.gr', 'login.bigcorp.com', 'contoso.sharepoint.com'])(
    'not for the brand\'s own or country domains: %s',
    async (host) => {
      expect((await check(host)).isSuspicious).toBe(false);
    },
  );

  it("never flags another organization's verified domain (reference guard); the issuer's own references are skipped", async () => {
    const svc = service([{ id: 'org_x', name: 'X', domain: 'bigcorp-com.support' }]);
    expect((await check('bigcorp-com.support', 'org_other', svc)).isSuspicious).toBe(false);
    expect((await check('bigcorp.com.evil.io', 'org_big')).isSuspicious).toBe(false);
  });

  it('an approved domain is exempt for its own organization only (D10)', async () => {
    const approved = { id: 'org_m', name: 'M', domain: 'paypal-com.biz', domainReviewStatus: 'APPROVED', domainReview: { domain: 'paypal-com.biz' } };
    const svc = service([approved]);
    expect((await check('paypal-com.biz', 'org_m', svc)).isSuspicious).toBe(false);
    expect((await check('paypal-com.biz', ISSUER, svc)).isSuspicious).toBe(true);
  });
});

describe('strict brand as a hyphen token (brand_token)', () => {
  it.each([
    ['paypal-secure.com', 'PayPal', 'brand_token'],
    ['secure-paypal.xyz', 'PayPal', 'brand_token'],
    ['revolut-app.io', 'Revolut', 'brand_token'],
    ['piraeusbank-update.com', 'Piraeus Bank', 'brand_token'],
    ['elta-tracking.com', 'ELTA Hellenic Post', 'brand_token'],
    ['päypal-login.com', 'PayPal', 'confusable'],
    ['paypa1-help.com', 'PayPal', 'confusable'],
    ['nbg-login.gr', 'National Bank of Greece', 'brand_token'], // short name next to a keyword
    ['n26-verify.com', 'N26', 'brand_token'],
  ])('%s', async (host, brand, reason) => {
    const result = await check(host);
    expect(result.isSuspicious).toBe(true);
    expect(result.warnings[0]).toMatchObject({ verifiedOrgName: brand, reason });
  });

  it.each([
    ['vısa-hr.sharepoint.com', 'Visa'], // dotless ı; wordlike, tenant label
    ['nbɡ-hr.sharepoint.com', 'National Bank of Greece'], // script ɡ; short name, tenant label
    ['ıng-team.sharepoint.com', 'ING'],
    ['vısa-pay.com', 'Visa'],
    ['strıpe-checkout.com', 'Stripe'],
    ['vіsa-team.com', 'Visa'], // Cyrillic і
    ['kråken-games.com', 'Kraken'], // diacritic
  ])('a confusable or accented spelling needs no keyword: %s', async (host, brand) => {
    const result = await check(host);
    expect(result.isSuspicious).toBe(true);
    expect(result.warnings[0]).toMatchObject({ verifiedOrgName: brand, reason: 'confusable' });
  });

  it.each([
    'apple-pie.com', 'wise-owl.co.uk', 'google-login.com', 'amazon-seller-login.com', 'alpha-omega.gr', // non-strict brands
    'db-tools.io', 'ing-photos.com', 'nbg-online.com', 'gov-team.org', 'db-team.sharepoint.com', // short names without a keyword
  ])('not flagged: %s', async (host) => {
    expect((await check(host)).isSuspicious).toBe(false);
  });
});

describe('strict brand run together with a phishing keyword (brand_keyword)', () => {
  it.each([
    ['paypalsecure.com', 'PayPal'],
    ['mypaypallogin.com', 'PayPal'],
    ['eurobankeisodos.gr', 'Eurobank'],
    ['alphabanksyndesi.com', 'Alpha Bank'],
    ['revolutverify.app', 'Revolut'],
    ['stripel0gin.com', 'Stripe'], // confusable keyword
    ['vivawalletlogin.gr', 'Viva Wallet'],
    ['mastercardsecure.com', 'Mastercard'],
    ['paypalsecure.sharepoint.com', 'PayPal'], // tenant label
    ['securepaypal.com', 'PayPal'], // a whole keyword before the brand
    ['paypalsupport.com', 'PayPal'],
    ['stripelogin.com', 'Stripe'], // wordlike: a credential word
    ['fireservicelogin.gr', 'Hellenic Fire Service'],
  ])('%s', async (host, brand) => {
    const result = await check(host);
    expect(result.isSuspicious).toBe(true);
    expect(result.warnings[0]).toMatchObject({ verifiedOrgName: brand, reason: 'brand_keyword' });
  });

  it.each([
    'applebees.com', 'visaplace.com', 'paypalfans.com', 'paypallovers.org', 'revolutionary.com', 'eurobankers.gr',
    'pinstripe-account.com', // the brand inside another word, the keyword in another token
    'pinstripeaccounting.com', 'stripedaccountants.com', 'pinstripesupport.com', 'santanderaccountants.com', // inside a longer word
    'fireservicesupport.co.uk', // wordlike: a general word is not enough
    'ελληνικά.gr', 'εθνικήτράπεζα.gr', 'τράπεζα-αθηνών.gr', 'kraken.io.example', 'stripedshirts.gr',
  ])('not flagged without a keyword next to the brand: %s', async (host) => {
    expect((await check(host)).isSuspicious).toBe(false);
  });
});

describe('warning order (create response and verify page)', () => {
  it('a mixed-script warning comes before a match below the threshold, and the incident records it (eurobаnkers.gr)', async () => {
    const url = 'https://eurobаnkers.gr/'; // Cyrillic а
    const result = await check('eurobаnkers.gr');
    expect(result.isSuspicious).toBe(true);
    expect(result.warnings.map((w) => [w.reason, w.similarity])).toEqual([['mixed_script', 100], ['substring_match', 70]]);

    const create = vi.fn(async () => ({}));
    const db = { fraudIncident: { findFirst: vi.fn(async () => null), create } };
    await recordLookalikeIncident(db as never, 'qr_1', url, result.warnings[0], 'create');
    expect(create).toHaveBeenCalledWith({ data: expect.objectContaining({ details: expect.objectContaining({ lookalikeReason: 'mixed_script' }) }) });
  });

  it('a brand match comes before mixed scripts', async () => {
    const result = await check('xn--l-7sba6dbr.com'); // раураl.com
    expect(result.warnings.map((w) => w.reason)).toEqual(['confusable', 'mixed_script']);
    expect(result.warnings[0]).toMatchObject({ domain: 'paypal.com', verifiedOrgName: 'PayPal' });
  });
});

describe('phishing keyword list', () => {
  it('parses both tiers, and holds the required words', () => {
    const words = parseKeywords(readFileSync(KEYWORDS_FILE, 'utf8'));
    for (const word of ['login', 'signin', 'logon', 'password', 'passcode', 'verify', 'verification', 'kyc', '2fa', 'wallet', 'seedphrase', 'eisodos', 'σύνδεση']) {
      expect(words.credential).toContain(word);
    }
    for (const word of ['account', 'support', 'update', 'alert', 'auth', 'otp', 'secure', 'billing', 'payment', 'confirm', 'unlock', 'service']) {
      expect(words.general).toContain(word);
    }
    expect(phishingKeywords().credential.length + phishingKeywords().general.length).toBeGreaterThan(30);
  });

  it('holds no common name parts', () => {
    const words = parseKeywords(readFileSync(KEYWORDS_FILE, 'utf8'));
    for (const word of ['pay', 'bank', 'app', 'online', 'gr', 'web', 'shop']) {
      expect([...words.credential, ...words.general]).not.toContain(word);
    }
  });

  it('credential words match inside a longer word, general words only as a whole token', () => {
    expect(hasCredentialKeyword(tokenSkeleton('mylogin'))).toBe(true);
    expect(hasKeyword(tokenSkeleton('mylogin'))).toBe(true);
    expect(hasKeyword(tokenSkeleton('secure'))).toBe(true);
    expect(hasCredentialKeyword(tokenSkeleton('secure'))).toBe(false);
    for (const word of ['accountants', 'alerts', 'authentic', 'updates', 'supporters']) expect(hasKeyword(tokenSkeleton(word))).toBe(false);
  });

  it.each([
    ['[general]\nLogin', 'lowercase'],
    ['[general]\nab', '3+'],
    ['[general]\nsign-in', 'one lowercase word'],
    ['[credential]\nlogin\n[general]\nlogin', 'duplicate'],
    ['login', 'before the [credential] or [general] header'],
  ])('rejects %j', (text, message) => {
    expect(() => parseKeywords(text)).toThrow(message);
  });
});

describe('keywords in their plain-letter form (1 → l/i, 0 → o, 3 → e, 5 → s)', () => {
  it.each([
    ['paypals1gnin.com', 'brand_keyword'],
    ['paypalsupp0rt.com', 'brand_keyword'],
    ['visa-v3rify.com', 'brand_token'],
    ['visa-l0g1n.com', 'brand_token'],
    ['kraken-pa55word.net', 'brand_token'],
  ])('flagged: %s', async (host, reason) => {
    const result = await check(host);
    expect(result.isSuspicious).toBe(true);
    expect(result.warnings[0].reason).toBe(reason);
  });

  it('keyword form', () => {
    expect(keywordForm(tokenSkeleton('s1gnin'))).toBe(keywordForm('signin'));
    expect(keywordForm(tokenSkeleton('l0g1n'))).toBe(keywordForm('login'));
    expect(keywordForm(tokenSkeleton('pa55w0rd'))).toBe(keywordForm('password'));
    expect(keywordForm(tokenSkeleton('v3rify'))).toBe(keywordForm('verify'));
  });
});

describe('short keywords match whole tokens only', () => {
  it.each(['visa-hotpot.com', 'paypalhotpot.com', 'nova-gr-hotpot.com', 'visa-kycle.com'])('not flagged: %s', async (host) => {
    expect((await check(host)).isSuspicious).toBe(false);
  });

  it.each([
    ['paypal-otp.com', 'brand_token'],
    ['paypalotp.com', 'brand_keyword'], // the rest is exactly a keyword
    ['visa-kyc.com', 'brand_token'], // a short credential word as a whole token
    ['nova-gr-otp.com', 'embedded_domain'],
  ])('flagged: %s', async (host, reason) => {
    const result = await check(host);
    expect(result.isSuspicious).toBe(true);
    expect(result.warnings[0].reason).toBe(reason);
  });

  it('credential words under 4 characters do not match inside a word', () => {
    expect(hasCredentialKeyword(tokenSkeleton('kyc'))).toBe(true);
    expect(hasCredentialKeyword(tokenSkeleton('kycheck'))).toBe(false);
    expect(hasCredentialKeyword(tokenSkeleton('my2fa'))).toBe(false);
    expect(hasKeyword(tokenSkeleton('hotpot'))).toBe(false);
  });
});

describe('keyword tiers in the brand rules', () => {
  it.each([
    'visa-support.gr', 'visa-accountants.co.uk', 'schengen-visa-update.com', 'visa-alerts.travel', 'authentic-greek-visa.com',
    'ktimatologio-update.gr', 'nbg-support.gr',
  ])('a general word does not count next to a short or wordlike brand: %s', async (host) => {
    expect((await check(host)).isSuspicious).toBe(false);
  });

  it.each([
    ['visa-signin.com', 'brand_token'],
    ['ktimatologio-login.gr', 'brand_token'],
    ['nbg-passcode.gr', 'brand_token'],
    ['eurobank-gr-support.com', 'embedded_domain'], // any tier in the hyphen form
    ['paypalsecure.com', 'brand_keyword'], // a general word as the rest of the token
  ])('flagged: %s', async (host, reason) => {
    const result = await check(host);
    expect(result.isSuspicious).toBe(true);
    expect(result.warnings[0].reason).toBe(reason);
  });
});

describe('wordlike brands inside a longer token', () => {
  it.each(['pinstripewallet.com', 'stripedwallets.com', 'mystripelogin.com', 'fireservicesupport.co.uk', 'krakenwalletguide.com'])(
    'not flagged: %s',
    async (host) => {
      expect((await check(host)).isSuspicious).toBe(false);
    },
  );

  it.each([
    ['stripewallet.com', 'brand_keyword'],
    ['loginstripe.com', 'brand_keyword'],
    ['stripel0gin.com', 'brand_keyword'],
    ['stripe-login.com', 'brand_token'],
  ])('flagged: %s', async (host, reason) => {
    const result = await check(host);
    expect(result.isSuspicious).toBe(true);
    expect(result.warnings[0].reason).toBe(reason);
  });
});

describe('brand run together with a keyword (helper)', () => {
  it.each([
    ['paypalsecure', 'paypal', false, true],
    ['securepaypal', 'paypal', false, true],
    ['mypaypallogin', 'paypal', false, true],
    ['mypaypalsecure', 'paypal', false, false], // not at the start or end, general word
    ['paypalsecurity1', 'paypal', false, false], // the rest is not exactly a keyword
    ['stripesupport', 'stripe', true, false], // wordlike: general word
    ['stripelogin', 'stripe', true, true],
    ['mystripelogin', 'stripe', true, false], // wordlike: never inside a longer word
    ['pinstripeaccounting', 'stripe', false, false],
  ])('%s with %s (wordlike %s): %s', (token, brand, wordlike, expected) => {
    expect(brandWithKeyword([tokenSkeleton(token)], tokenSkeleton(brand), wordlike)).toBe(expected);
  });
});

describe("a brand's official domains", () => {
  it.each(['paypal-community.com', 'www.paypal-community.com', 'paypal-prepagata.com', 'www.paypal-prepagata.com'])(
    'PayPal: %s',
    async (host) => {
      expect((await check(host)).warnings).toEqual([]);
    },
  );
});

describe('helpers', () => {
  it('name tokens of a protected domain', () => {
    expect(protectedNameTokens('eurobank.gr')).toEqual(['eurobank', 'gr']);
    expect(protectedNameTokens('www.deutsche-bank.de')).toEqual(['deutsche', 'bank', 'de']);
    expect(protectedNameTokens('gov.gr')).toEqual(['gov', 'gr']);
    expect(protectedNameLabels('www.deutsche-bank.de')).toEqual(['deutsche-bank', 'de']);
  });

  it('embedded name: dotted or hyphen form, keyword outside the run', () => {
    const labels = protectedNameLabels('eurobank.gr');
    const tokens = protectedNameTokens('eurobank.gr');
    expect(embeddedName(hostTokens('eurobank.gr.secure-login.com'), labels, tokens)).toEqual({ form: 'dotted' });
    expect(embeddedName(hostTokens('eurobank-gr-login.com'), labels, tokens)).toEqual({ form: 'hyphen', keyword: true });
    expect(embeddedName(hostTokens('eurobank-gr.example'), labels, tokens)).toEqual({ form: 'hyphen', keyword: false });
    expect(embeddedName(hostTokens('eurobankgr-login.com'), labels, tokens)).toEqual({ form: 'hyphen', keyword: true });
    expect(embeddedName(hostTokens('eurobankgr.example'), labels, tokens)).toEqual({ form: 'hyphen', keyword: false });
    expect(embeddedName(hostTokens('myeurobankgr.com'), labels, tokens)).toBeNull();
    expect(embeddedName(hostTokens('eurobank.com'), labels, tokens)).toBeNull();
  });

  it('contiguous runs only', () => {
    expect(containsRun(['a', 'paypal', 'com', 'x'], ['paypal', 'com'])).toBe(true);
    expect(containsRun(['paypal', 'x', 'com'], ['paypal', 'com'])).toBe(false);
    expect(tokenSkeleton('PäYPAL')).toBe(tokenSkeleton('paypal'));
  });
});

describe('wordlike strict brands (D11)', () => {
  it('the audited brands are marked', () => {
    const wordlike = curatedBrands().filter((b) => b.wordlike).map((b) => b.name).sort();
    expect(wordlike).toEqual(['Hellenic Cadastre', 'Hellenic Fire Service', 'Hellenic Police', 'Kraken', 'Santander', 'Stripe', 'Trezor', 'Visa']);
    expect(curatedBrands().filter((b) => b.wordlike).every((b) => b.strict)).toBe(true);
  });

  it.each([
    ['visa.xyz', 'brand_name'], // still strict on other TLDs
    ['visa-login.com', 'brand_token'],
    ['kraken-wallet-login.net', 'brand_token'],
    ['stripe-account-verify.com', 'brand_token'],
    ['astynomia-eisodos.gr', 'brand_token'],
    ['vіsa-login.com', 'confusable'], // Cyrillic і
    ['stripel0gin.com', 'brand_keyword'],
    ['www.visa.com.verify-card.net', 'embedded_domain'],
  ])('flagged: %s', async (host, reason) => {
    const result = await check(host);
    expect(result.isSuspicious).toBe(true);
    expect(result.warnings[0].reason).toBe(reason);
  });

  it('visa-greece.com is not a Visa lookalike (it resembles visitgreece.gr, an edit-distance match)', async () => {
    const result = await check('visa-greece.com');
    expect(result.warnings.some((w) => w.verifiedOrgName === 'Visa')).toBe(false);
    expect(result.warnings.map((w) => w.domain)).toEqual(['visitgreece.gr']);
  });

  it.each(['visa-team.com', 'visa-services.gr', 'kraken-games.com', 'stripe-design.com', 'santander-hotels.es', 'astynomia-news.gr', 'trezor-shop.cz', 'secure-kraken.net'])(
    'not flagged without a credential keyword: %s',
    async (host) => {
      expect((await check(host)).isSuspicious).toBe(false);
    },
  );
});
