import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it, vi } from 'vitest';

import {
  CUSTOMER_LOGO_FIXTURE,
  EXPORT_GOLDEN_CASES,
  EXPORT_ORIGIN,
  EXPORT_TOKEN,
} from '../../../../shared/src/qr-render/__tests__/export-golden-cases.js';

/**
 * The server's SVG export matches the shared export golden files, which the
 * dashboard preview is also checked against (packages/web,
 * qr-preview-golden.test.ts): preview and export are byte-identical for the
 * same code and style (ADR-0005 PR 3), including customer logos (PR 4),
 * which go through loadLogoBytes as the image route loads them. The verify
 * URL is pinned to the production origin, as in the golden files. Badge
 * cases render for a verified and an unverified issuer (the mark's wording,
 * D9 2026-10-30).
 */

process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

vi.mock('../../lib/qrcode-access.js', () => ({
  buildVerificationUrl: (token: string) => `${EXPORT_ORIGIN}/v/${token}`,
}));

const { loadLogoBytes, renderExport, styleForRender } = await import('../qr-render.js');

const CASES_DIR = join(dirname(fileURLToPath(import.meta.url)), '../../../../shared/src/qr-render/__tests__');
const GOLDEN_DIR = join(CASES_DIR, 'golden-export');
const CUSTOMER_LOGO = new Uint8Array(readFileSync(join(CASES_DIR, CUSTOMER_LOGO_FIXTURE)));

/** The organization's library as the image route reads it: the golden logo belongs to org_1. */
const logos = {
  bytes: async (organizationId: string, assetId: string) =>
    organizationId === 'org_1' && assetId === 'golden-logo' ? CUSTOMER_LOGO : null,
};

describe('server SVG export = shared export golden files', () => {
  it.each(EXPORT_GOLDEN_CASES.map((c) => [c.name, c] as const))('%s', async (name, c) => {
    const style = styleForRender(c.style);
    const logo = await loadLogoBytes(style, 'org_1', logos);
    const qr = { token: EXPORT_TOKEN, issuerVerified: c.issuerVerified === true };
    const { body, notDrawn } = await renderExport(qr, style, logo, { format: 'svg' });
    expect(body.toString('utf8')).toBe(readFileSync(join(GOLDEN_DIR, `${name}.svg`), 'utf8'));
    expect(notDrawn).not.toContain('logo');
  });

  it('a customer logo of another organization is not drawn: its area stays empty', async () => {
    const c = EXPORT_GOLDEN_CASES.find((x) => x.name === 'v2-customer-logo-scale-0.75')!;
    const style = styleForRender(c.style);
    const logo = await loadLogoBytes(style, 'org_2', logos);
    expect(logo).toBeNull();
    const { body, notDrawn } = await renderExport({ token: EXPORT_TOKEN, issuerVerified: false }, style, logo, { format: 'svg' });
    expect(notDrawn).toContain('logo');
    expect(body.toString('utf8')).not.toContain(Buffer.from(CUSTOMER_LOGO).toString('base64'));
  });
});
