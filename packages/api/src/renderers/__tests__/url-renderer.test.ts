import { describe, it, expect } from 'vitest';

import type { RenderContext } from '../index.js';
import type { TrustState } from '../../services/trust-state.js';
import renderUrlContent from '../url.js';
import { safeHttpHref } from '../utils.js';

function makeCtx(destinationUrl: string, trustState: TrustState = 'VERIFIED'): RenderContext {
  return {
    nonce: 'TESTNONCE',
    qrCode: {
      token: 'tok_test',
      contentType: 'url',
      content: null,
      label: null,
      destinationUrl,
      latitude: null,
      longitude: null,
      createdAt: new Date('2026-10-27T00:00:00Z'),
    },
    organization: {
      id: 'org_1',
      name: 'Acme',
      slug: 'acme',
      trustLevel: 'INDIVIDUAL',
      kycStatus: 'VERIFIED',
      domainVerified: true,
    },
    trustState,
    verified: trustState === 'VERIFIED',
    security: { signatureValid: true, proxyDetected: false, trustScore: 90, transparencyLogVerified: true },
    locationMatch: { matched: false, distanceM: null, registeredAddress: null },
    scannedAt: '2026-10-27T00:00:00Z',
    assetBaseUrl: 'http://localhost:3000/assets',
  };
}

describe('safeHttpHref', () => {
  it.each([
    ['https://example.com/a', 'https://example.com/a'],
    ['http://example.com', 'http://example.com'],
    ['javascript:alert(1)', null],
    ['data:text/html,x', null],
    ['intent://x#Intent;end', null],
    ['not a url', null],
    ['', null],
  ])('%s -> %s', (input, expected) => {
    expect(safeHttpHref(input)).toBe(expected);
  });
});

describe('url renderer — destination scheme', () => {
  it('renders the Continue link for an http(s) destination', () => {
    const html = renderUrlContent(makeCtx('https://example.com/pay'));

    expect(html).toContain('href="https://example.com/pay"');
    expect(html).toContain('Continue to example.com');
  });

  it.each(['javascript:alert(1)', 'data:text/html,<b>x</b>', 'intent://x#Intent;end'])(
    'emits no link and the not-verified state for a legacy row with %s',
    (destinationUrl) => {
      const html = renderUrlContent(makeCtx(destinationUrl));

      expect(html).not.toContain('href=');
      expect(html).not.toContain('Continue to');
      expect(html).toContain('Do not proceed');
    },
  );
});

describe('url renderer — trust states', () => {
  it('VERIFIED: green Continue button', () => {
    const html = renderUrlContent(makeCtx('https://example.com/pay', 'VERIFIED'));

    expect(html).toContain('background:#047857');
    expect(html).toContain('Continue to example.com');
    expect(html).not.toContain('data-destination-host');
  });

  it('SIGNED_UNVERIFIED_ISSUER: destination host above a neutral Continue button', () => {
    const html = renderUrlContent(makeCtx('https://example.com/pay', 'SIGNED_UNVERIFIED_ISSUER'));

    const hostIdx = html.indexOf('data-destination-host');
    const continueIdx = html.indexOf('Continue to example.com');
    expect(hostIdx).toBeGreaterThan(-1);
    expect(continueIdx).toBeGreaterThan(hostIdx);
    expect(html).not.toContain('#047857');
  });

  it('UNTRUSTED: no Continue link', () => {
    const html = renderUrlContent(makeCtx('https://example.com/pay', 'UNTRUSTED'));

    expect(html).not.toContain('Continue to');
    expect(html).toContain('Do not proceed');
  });
});
