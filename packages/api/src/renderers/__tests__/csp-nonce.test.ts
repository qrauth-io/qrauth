import { describe, it, expect } from 'vitest';

import type { RenderContext } from '../index.js';
import { renderShell } from '../shell.js';
import renderCoupon from '../coupon.js';
import renderEvent from '../event.js';
import renderVcard from '../vcard.js';
import renderPdf from '../pdf.js';
import renderFeedback from '../feedback.js';

// ----------------------------------------------------------------------
// F-007 / issue #1 regression guard.
//
// The verify page sets a per-response CSP with `style-src 'self' 'nonce-…'`
// and `script-src 'self' 'nonce-…'` — NO 'unsafe-inline'. Every inline
// <style>/<script> the shell and content renderers emit must therefore carry
// that exact nonce, and NO inline on*= event-handler attributes may remain
// (script-src blocks them). These tests assert both invariants directly on
// renderer output, so a regression that drops a nonce or reintroduces an
// inline handler fails here instead of silently breaking styling in prod.
// ----------------------------------------------------------------------

const NONCE = 'TESTNONCE0123456789ab==';

function makeCtx(content: unknown): RenderContext {
  return {
    nonce: NONCE,
    qrCode: {
      token: 'tok_test',
      contentType: 'test',
      content,
      label: 'Test',
      destinationUrl: 'https://example.com',
      latitude: null,
      longitude: null,
      createdAt: new Date('2026-06-08T00:00:00Z'),
    },
    organization: {
      id: 'org_1',
      name: 'Acme',
      slug: 'acme',
      trustLevel: 'BUSINESS',
      kycStatus: 'VERIFIED',
      domainVerified: true,
    },
    verified: true,
    security: {
      signatureValid: true,
      proxyDetected: false,
      trustScore: 92,
      transparencyLogVerified: true,
    },
    locationMatch: { matched: false, distanceM: null, registeredAddress: null },
    scannedAt: '2026-06-08T00:00:00Z',
    assetBaseUrl: 'http://localhost:3000/assets',
  };
}

/** Every <style> and <script> element opening tag in the html. */
function elementTags(html: string): string[] {
  return html.match(/<(?:style|script)(?:\s[^>]*)?>/gi) ?? [];
}

/** Inline event-handler attributes (onclick=, onerror=, …) — must be absent. */
const INLINE_HANDLER = /\son(?:error|click|load|change|submit|input|mouseover|mouseout|mousedown|mouseup|keydown|keyup|keypress|focus|blur|abort|toggle)\s*=/i;

const contentRenderers: Array<{ name: string; render: (ctx: RenderContext) => string; content: unknown; expectScript: boolean }> = [
  { name: 'coupon', render: renderCoupon, content: { headline: 'Save 20%', imageUrl: 'https://img.example/x.jpg', redemptionUrl: 'https://shop.example/x' }, expectScript: false },
  { name: 'event', render: renderEvent, content: { title: 'Launch', startDate: '2026-07-01T18:00:00', imageUrl: 'https://img.example/x.jpg' }, expectScript: false },
  { name: 'vcard', render: renderVcard, content: { firstName: 'Jane', lastName: 'Doe', email: 'j@acme.com', photoUrl: 'https://img.example/p.jpg' }, expectScript: false },
  { name: 'pdf', render: renderPdf, content: { title: 'Doc', fileUrl: 'https://files.example/d.pdf' }, expectScript: false },
  { name: 'feedback', render: renderFeedback, content: { title: 'Rate us', collectName: true }, expectScript: true },
];

describe('content renderers — CSP nonce + no inline handlers', () => {
  for (const r of contentRenderers) {
    describe(r.name, () => {
      const html = r.render(makeCtx(r.content));
      const tags = elementTags(html);

      it('emits at least one <style> element', () => {
        expect(tags.some((t) => /^<style/i.test(t))).toBe(true);
      });

      it('every <style>/<script> element carries the response nonce', () => {
        expect(tags.length).toBeGreaterThan(0);
        for (const tag of tags) {
          expect(tag).toContain(`nonce="${NONCE}"`);
        }
      });

      if (r.expectScript) {
        it('emits a nonced <script> element', () => {
          expect(tags.some((t) => /^<script/i.test(t))).toBe(true);
        });
      }

      it('contains NO inline on*= event-handler attributes', () => {
        expect(INLINE_HANDLER.test(html)).toBe(false);
      });
    });
  }
});

describe('renderShell — CSP nonce + no inline handlers', () => {
  const { html } = renderShell(makeCtx({ headline: 'x' }), '<div class="content">body</div>', 'seedhmac');
  const tags = elementTags(html);

  it('emits nonced <style> and <script> elements', () => {
    expect(tags.some((t) => /^<style/i.test(t))).toBe(true);
    expect(tags.some((t) => /^<script/i.test(t))).toBe(true);
  });

  it('every shell <style>/<script> carries the SAME response nonce', () => {
    expect(tags.length).toBeGreaterThan(0);
    for (const tag of tags) {
      expect(tag).toContain(`nonce="${NONCE}"`);
    }
  });

  it('contains NO inline on*= event-handler attributes', () => {
    expect(INLINE_HANDLER.test(html)).toBe(false);
  });

  it('uses the nonce from RenderContext, not a self-generated one', () => {
    // Shell no longer calls randomBytes; the only nonce present is ctx.nonce.
    const nonces = [...html.matchAll(/nonce="([^"]+)"/g)].map((m) => m[1]);
    expect(nonces.length).toBeGreaterThan(0);
    expect(new Set(nonces)).toEqual(new Set([NONCE]));
  });
});
