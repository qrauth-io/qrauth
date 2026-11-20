import { describe, expect, it } from 'vitest';

import type { LinkState, RenderContext } from '../index.js';
import type { TrustState } from '../../services/trust-state.js';
import type { Platform } from '../../services/platform.js';
import renderAppLink from '../app-link.js';
import renderLinkList from '../link-list.js';
import { safeHttpsHref } from '../links.js';

const APP = {
  iosUrl: 'https://apps.apple.com/app/id123',
  androidUrl: 'https://play.google.com/store/apps/details?id=com.acme&hl=en',
  fallbackUrl: 'https://acme.example/app',
};
const LIST = {
  title: 'Acme links',
  description: 'Menu and booking',
  links: [
    { label: 'Menu', url: 'https://acme.example/menu' },
    { label: 'Book a table', url: 'https://book.example/acme' },
  ],
};

function ctx(
  contentType: 'app-link' | 'link-list',
  content: unknown,
  opts: { trustState?: TrustState; platform?: Platform; links?: Record<string, LinkState>; label?: string | null } = {},
): RenderContext {
  const trustState = opts.trustState ?? 'VERIFIED';
  return {
    nonce: 'TESTNONCE',
    qrCode: {
      token: 'tok_test',
      contentType,
      content,
      label: opts.label === undefined ? 'Get the Acme app' : opts.label,
      destinationUrl: 'https://qrauth.io/v/tok_test',
      latitude: null,
      longitude: null,
      createdAt: new Date('2026-10-27T00:00:00Z'),
    },
    organization: { id: 'org_1', name: 'Acme', slug: 'acme', trustLevel: 'BUSINESS', kycStatus: 'VERIFIED', domainVerified: true },
    trustState,
    verified: trustState === 'VERIFIED',
    security: { signatureValid: true, proxyDetected: false, trustScore: 90, transparencyLogVerified: true },
    locationMatch: { matched: false, distanceM: null, registeredAddress: null },
    scannedAt: '2026-10-27T00:00:00Z',
    assetBaseUrl: 'http://localhost:3000/assets',
    platform: opts.platform,
    links: opts.links,
  };
}

const XSS = [
  '<script>alert(1)</script>',
  '"><img src=x onerror=alert(1)>',
  "'><svg onload=alert(1)>",
  '</style><script>alert(1)</script>',
  '&lt;script&gt;',
];

/** No markup from user text: every literal '<' opens one of the renderer's own tags. */
function expectNoInjectedMarkup(html: string) {
  const tags = [...html.matchAll(/<\/?([a-z]+)\b[^>]*>/gi)].map((m) => m[1].toLowerCase());
  expect(new Set(tags)).toEqual(new Set(tags.filter((t) => ['style', 'div', 'ul', 'li', 'a', 'span', 'p'].includes(t))));
  expect(html).not.toMatch(/<[a-z][^>]*\son[a-z]+\s*=/i);
  expect(html.match(/<style\b[^>]*>/g)).toEqual(['<style nonce="TESTNONCE">']);
}

describe('safeHttpsHref', () => {
  it.each([
    ['https://example.com/a', 'https://example.com/a'],
    ['http://example.com', null],
    ['javascript:alert(1)', null],
    ['data:text/html,x', null],
    ['intent://x#Intent;end', null],
    ['https://a@evil.example/', null],
    [42, null],
  ])('%j -> %j', (input, expected) => {
    expect(safeHttpsHref(input)).toBe(expected);
  });
});

describe('app-link renderer', () => {
  it('matches the snapshot (iOS, VERIFIED)', () => {
    expect(renderAppLink(ctx('app-link', APP, { platform: 'ios' }))).toMatchSnapshot();
  });

  it('matches the snapshot (desktop, neutral issuer, Google Play flagged)', () => {
    const html = renderAppLink(ctx('app-link', APP, {
      platform: 'other',
      trustState: 'SIGNED_UNVERIFIED_ISSUER',
      links: { [APP.androidUrl]: { flagged: true } },
    }));
    expect(html).toMatchSnapshot();
  });

  it('highlights the device choice only when VERIFIED', () => {
    expect(renderAppLink(ctx('app-link', APP, { platform: 'android' }))).toContain('class="ql-link ql-primary" href="https://play.google.com');
    expect(renderAppLink(ctx('app-link', APP, { platform: 'android', trustState: 'SIGNED_UNVERIFIED_ISSUER' }))).not.toContain('class="ql-link ql-primary"');
    expect(renderAppLink(ctx('app-link', APP, { platform: 'other' }))).not.toContain('class="ql-link ql-primary"');
  });

  it('every link is https with rel="noopener noreferrer nofollow" and an escaped href', () => {
    const html = renderAppLink(ctx('app-link', APP, { platform: 'ios' }));
    const anchors = html.match(/<a\b[^>]*>/g) ?? [];
    expect(anchors).toHaveLength(3);
    for (const a of anchors) {
      expect(a).toMatch(/^<a class="ql-link( ql-primary)?" href="https:\/\/[^"]+" rel="noopener noreferrer nofollow">$/);
    }
    expect(html).toContain('id=com.acme&amp;hl=en');
  });

  it('two flagged links are both named in the notice', () => {
    const html = renderAppLink(ctx('app-link', APP, { platform: 'ios', links: { [APP.iosUrl]: { flagged: true }, [APP.fallbackUrl]: { flagged: true } } }));
    expect(html).toContain('The App Store and Website links were removed: Google Web Risk lists them as dangerous.');
    expect((html.match(/<a\b/g) ?? [])).toHaveLength(1);
  });

  it('marks a lookalike link', () => {
    const html = renderAppLink(ctx('app-link', APP, {
      platform: 'other',
      trustState: 'UNTRUSTED',
      links: { [APP.fallbackUrl]: { flagged: false, lookalike: { similarTo: 'acme.com', verifiedOrg: '<b>Acme</b>', source: 'curated' } } },
    }));
    expect(html).toContain('Do not proceed - this QR code is not verified');
    expect(html).toContain('Looks like acme.com (&lt;b&gt;Acme&lt;/b&gt;)');
  });

  it.each(XSS)('escapes %j in the label', (payload) => {
    expectNoInjectedMarkup(renderAppLink(ctx('app-link', APP, { platform: 'ios', label: payload })));
  });

  it('renders nothing for content that fails its schema (javascript:, data:, intent: or http)', () => {
    for (const bad of ['javascript:alert(1)', 'data:text/html,<b>', 'intent://x#Intent;end', 'http://acme.example/']) {
      const html = renderAppLink(ctx('app-link', { ...APP, iosUrl: bad }, { platform: 'ios' }));
      expect(html).toBe('<p>This code has no links.</p>');
    }
  });
});

describe('link-list renderer', () => {
  it('matches the snapshot', () => {
    expect(renderLinkList(ctx('link-list', LIST))).toMatchSnapshot();
  });

  it('matches the snapshot (UNTRUSTED, one flagged, one lookalike)', () => {
    const html = renderLinkList(ctx('link-list', LIST, {
      trustState: 'UNTRUSTED',
      links: {
        'https://book.example/acme': { flagged: true },
        'https://acme.example/menu': { flagged: false, lookalike: { similarTo: 'acme.com', verifiedOrg: 'Acme Corp', source: 'curated' } },
      },
    }));
    expect(html).toMatchSnapshot();
  });

  it('no link is primary: a link list never continues on its own', () => {
    expect(renderLinkList(ctx('link-list', LIST))).not.toContain('class="ql-link ql-primary"');
  });

  it('omits the description when there is none', () => {
    expect(renderLinkList(ctx('link-list', { title: 'T', links: LIST.links }))).not.toContain('class="ql-desc"');
  });

  it('counts several flagged links', () => {
    const html = renderLinkList(ctx('link-list', LIST, { links: Object.fromEntries(LIST.links.map((l) => [l.url, { flagged: true }])) }));
    expect(html).toContain('2 links were removed: Google Web Risk lists them as dangerous.');
    expect(html).not.toContain('<a ');
  });

  it.each(XSS)('escapes %j in the title, description and every link label', (payload) => {
    const content = {
      title: payload,
      description: payload,
      links: [{ label: payload, url: 'https://acme.example/menu' }, { label: payload, url: 'https://acme.example/b?x="><script>' }],
    };
    const html = renderLinkList(ctx('link-list', content));
    expectNoInjectedMarkup(html);
    // The schema stores links normalized, so quotes and brackets are percent-encoded.
    expect(html).toContain('href="https://acme.example/b?x=%22%3E%3Cscript%3E"');
  });

  it.each(['javascript:alert(1)', 'data:text/html,<b>x</b>', 'intent://x#Intent;end', 'JAVASCRIPT:alert(1)'])(
    'renders nothing for a stored %j link (content fails its schema)',
    (bad) => {
      const html = renderLinkList(ctx('link-list', { ...LIST, links: [{ label: 'x', url: bad }] }));
      expect(html).toBe('<p>This code has no links.</p>');
      expect(html).not.toContain('href');
    },
  );
});
