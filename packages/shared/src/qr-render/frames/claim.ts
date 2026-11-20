// SPDX-License-Identifier: MIT
import { BADGE_MARK_SIGNED } from './layout.js';

/**
 * The dashboard's old default caption (v1 `captionText`). Stored on codes of
 * unverified issuers too, where it asserts a verification QRAuth has not
 * done (ADR-0005 D9, amendment of 2026-10-30).
 */
export const LEGACY_DEFAULT_CAPTION = 'QRAuth Verified';

/**
 * The frame text to draw. For an unverified issuer, a text equal to the old
 * default caption (trimmed, case-insensitive) draws as "Signed with QRAuth",
 * which is true for every code; any other text draws as stored.
 */
export function displayFrameText(text: string, issuerVerified: boolean): string {
  if (issuerVerified) return text;
  return text.trim().toLowerCase() === LEGACY_DEFAULT_CAPTION.toLowerCase() ? BADGE_MARK_SIGNED : text;
}

/** 403 message: an unverified issuer's frame text references QRAuth (ADR-0005 D9, 2026-10-30). */
export const FRAME_QRAUTH_CLAIM_MESSAGE = 'Only verified organisations can reference QRAuth in frame text.';

/**
 * Characters dropped before looking for "qrauth": whitespace, dots and
 * hyphens (ASCII and Unicode forms that NFKC keeps), the soft hyphen, and
 * zero-width and invisible characters. Bidi controls are refused by the
 * style schema already.
 */
const CLAIM_IGNORED = /[\s.·•․‧・\-‐-―−­᠎​-‍⁠-⁤﻿]/gu;

/**
 * True when `text` references QRAuth: after Unicode NFKC normalisation
 * (full-width and compatibility forms become ASCII), lower-casing and
 * dropping CLAIM_IGNORED, it contains "qrauth". Catches "QRAuth",
 * "Q R A u t h", "Q.R-Auth" and "ＱＲＡｕｔｈ".
 */
export function referencesQrauth(text: string): boolean {
  return text.normalize('NFKC').toLowerCase().normalize('NFKC').replace(CLAIM_IGNORED, '').includes('qrauth');
}

/** The frame fields the claim rule reads. */
export interface ClaimFrame {
  readonly template: string;
  readonly text: string;
}

/**
 * True when saving `frame` is refused because an unverified issuer's frame
 * text references QRAuth (ADR-0005 D9, 2026-10-30). A frame that draws no
 * text (absent or `none`) and every verified issuer are allowed. The route
 * applies it to changed styles only; an unchanged stored style is exempt.
 */
export function isFrameClaimRefused(issuerVerified: boolean, frame: ClaimFrame | null | undefined): boolean {
  if (issuerVerified || !frame || frame.template === 'none') return false;
  return referencesQrauth(frame.text);
}
