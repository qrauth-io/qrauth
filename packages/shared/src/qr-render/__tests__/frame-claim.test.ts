// SPDX-License-Identifier: MIT
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { FRAME_FONT_ASSET, loadFrameFont } from '../font.js';
import { outlineText } from '../frames/text.js';
import {
  BADGE_MARK_SIGNED,
  DEFAULT_STYLE,
  FRAME_QRAUTH_CLAIM_MESSAGE,
  LEGACY_DEFAULT_CAPTION,
  displayFrameText,
  isFrameClaimRefused,
  referencesQrauth,
  renderQr,
  styleFrameLayout,
  type QrFrame,
  type QrStyleV2,
} from '../index.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const FONT = loadFrameFont(new Uint8Array(readFileSync(join(HERE, '..', '..', '..', FRAME_FONT_ASSET))));
const URL_28 = 'https://qrauth.io/v/aB3dE5gH';

/** The two prod-like rows: FREE, unverified issuer, v1 style with the old default caption. */
const PROD_LIKE_V1 = [
  { templateId: 'classic', fgColor: '#000000', bgColor: '#FFFFFF', showLogo: true, captionText: 'QRAuth Verified' },
  { templateId: 'dark', fgColor: '#FFFFFF', bgColor: '#1B2A4A', showLogo: true, captionText: 'QRAuth Verified' },
];

const withFrame = (template: QrFrame['template'], text: string): QrStyleV2 => ({
  ...DEFAULT_STYLE,
  frame: { template, text, color: '#FFFFFF', textColor: '#000000' },
});

/** The outlined path of `text` in the style's (single) text box. */
function textPath(style: unknown, text: string): string {
  const meta = renderQr({ data: URL_28, style }).meta;
  const parsed = renderQr({ data: URL_28, style }).style;
  const box = styleFrameLayout(parsed, meta.symbolSize)!.textBoxes.find((b) => b.role === 'text')!;
  return outlineText(text, box, FONT)!.d;
}

describe('old default caption on an unverified issuer (D9, 2026-10-30)', () => {
  it('displayFrameText swaps only the old default, trimmed and case-insensitive', () => {
    expect(LEGACY_DEFAULT_CAPTION).toBe('QRAuth Verified');
    for (const text of ['QRAuth Verified', 'qrauth verified', '  QRAUTH VERIFIED  ', 'QRauth verified']) {
      expect(displayFrameText(text, false)).toBe(BADGE_MARK_SIGNED);
      expect(displayFrameText(text, true)).toBe(text);
    }
    for (const text of ['QRAuth Verified!', 'Verified', 'Scan me', '', 'QRAuth  Verified']) {
      expect(displayFrameText(text, false)).toBe(text);
    }
  });

  it('the prod-like FREE unverified rows draw "Signed with QRAuth"', () => {
    for (const style of PROD_LIKE_V1) {
      const unverified = renderQr({ data: URL_28, style, font: FONT, issuerVerified: false });
      expect(unverified.meta.frameText).toBe(BADGE_MARK_SIGNED);
      expect(unverified.svg).toContain(textPath(style, BADGE_MARK_SIGNED));
      expect(unverified.svg).not.toContain(textPath(style, LEGACY_DEFAULT_CAPTION));
      // An omitted status is unverified.
      expect(renderQr({ data: URL_28, style, font: FONT }).svg).toBe(unverified.svg);
    }
  });

  it('a verified issuer draws the stored caption unchanged', () => {
    for (const style of PROD_LIKE_V1) {
      const verified = renderQr({ data: URL_28, style, font: FONT, issuerVerified: true });
      expect(verified.meta.frameText).toBe(LEGACY_DEFAULT_CAPTION);
      expect(verified.svg).toContain(textPath(style, LEGACY_DEFAULT_CAPTION));
    }
  });

  it('applies to every template that draws text, not only captions', () => {
    for (const template of ['caption', 'banner-bottom', 'banner-top', 'rounded-label', 'badge'] as const) {
      const style = withFrame(template, 'QRAuth Verified');
      expect(renderQr({ data: URL_28, style, font: FONT, issuerVerified: false }).meta.frameText).toBe(BADGE_MARK_SIGNED);
      expect(renderQr({ data: URL_28, style, font: FONT, issuerVerified: true }).meta.frameText).toBe('QRAuth Verified');
    }
    expect(renderQr({ data: URL_28, style: withFrame('none', 'QRAuth Verified') }).meta.frameText).toBeNull();
  });

  it('other texts draw the same for both issuer statuses', () => {
    const style = withFrame('caption', 'Scan to verify');
    expect(renderQr({ data: URL_28, style, font: FONT, issuerVerified: false }).svg).toBe(
      renderQr({ data: URL_28, style, font: FONT, issuerVerified: true }).svg,
    );
  });
});

describe('frame text that references QRAuth (D9, 2026-10-30)', () => {
  it.each([
    'QRAuth',
    'qrauth',
    'Verified by QRAuth',
    'QRAuth Verified',
    'qrauth.io',
    'Q R A u t h',
    'Q.R.A.U.T.H',
    'Q-R-Auth',
    'Q R Auth', // no-break and thin spaces
    'QR​Auth', // zero-width space
    'Q‌R‍A⁠uth﻿', // zero-width non-joiner, joiner, word joiner, BOM
    'QR­Auth', // soft hyphen
    'ＱＲＡｕｔｈ', // full-width
    'Q‐R‑A–u—t−h', // Unicode hyphens, dashes, minus
    'Q·R•A․uth', // middle dot, bullet, one-dot leader
    'Q．R－Auth', // full-width full stop and hyphen
    'ⓆⓇⒶⓤⓣⓗ', // circled letters (NFKC folds them)
    '𝐐𝐑𝐀𝐮𝐭𝐡', // mathematical bold
  ])('catches %j', (text) => {
    expect(referencesQrauth(text)).toBe(true);
  });

  it.each(['Scan to verify', 'QR menu', 'Q R code', 'Auth required', 'QR / Auth', ''])('leaves %j alone', (text) => {
    expect(referencesQrauth(text)).toBe(false);
  });

  it('refuses only unverified issuers, only for a frame that draws text', () => {
    const frame = { template: 'banner-bottom', text: 'Q R A u t h' };
    expect(isFrameClaimRefused(false, frame)).toBe(true);
    expect(isFrameClaimRefused(true, frame)).toBe(false);
    expect(isFrameClaimRefused(false, { ...frame, template: 'none' })).toBe(false);
    expect(isFrameClaimRefused(false, null)).toBe(false);
    expect(isFrameClaimRefused(false, undefined)).toBe(false);
    expect(isFrameClaimRefused(false, { ...frame, text: 'Scan me' })).toBe(false);
    expect(FRAME_QRAUTH_CLAIM_MESSAGE).toBe('Only verified organisations can reference QRAuth in frame text.');
  });
});
