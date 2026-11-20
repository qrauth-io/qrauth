// SPDX-License-Identifier: MIT
import { contrastRatio, isLighter } from './colour.js';
import { isFrameTextSupported } from './frames/coverage.js';
import { MAX_LOGO_VERSION } from './logo.js';
import type { EcLevel } from './matrix.js';
import type { QrStyleV2 } from './style.js';

/** Below this contrast ratio a style without a logo is rejected (ADR-0005 D4.1, D9). */
export const CONTRAST_MIN = 3;
/**
 * Below this contrast ratio a style with a logo is rejected (D4.1, D9). With
 * the QRAuth logo, zxing missed square-module codes at 3.03:1 and 3.23:1 at
 * 8 px per module; every render from 3.45:1 up decoded.
 */
export const CONTRAST_MIN_WITH_LOGO = 3.5;
/**
 * Below this contrast ratio a light-on-dark style with a logo is rejected
 * (D4.1, D9). Light-on-dark without a logo keeps the 3:1 floor.
 */
export const CONTRAST_MIN_INVERTED_WITH_LOGO = 7;
/** Below this contrast ratio a style is allowed with a warning. */
export const CONTRAST_WARN = 4.5;
/**
 * Below this contrast ratio frame text is rejected: text against the frame
 * colour, or against the background for a caption (WCAG AA for text,
 * ADR-0005 PR 5). The code's own floors above are unchanged.
 */
export const FRAME_TEXT_CONTRAST_MIN = 4.5;
/** The message for frame text with a character the bundled font cannot draw. */
export const FRAME_GLYPH_UNSUPPORTED_MESSAGE = 'This character is not supported in frame text yet';
/** Print exports below this module pitch get a warning (D4.6, unverified). */
export const MIN_MODULE_MM = 0.4;

export type ScanIssueCode =
  | 'contrast-too-low'
  | 'contrast-too-low-with-logo'
  | 'contrast-too-low-inverted-with-logo'
  | 'contrast-low'
  | 'inverted-required'
  | 'inverted'
  | 'inverted-mismatch'
  | 'ec-below-floor'
  | 'frame-contrast-too-low'
  | 'frame-contrast-low'
  | 'frame-glyph-unsupported'
  | 'logo-version-too-high';

export interface ScanIssue {
  readonly code: ScanIssueCode;
  readonly message: string;
}

export interface ScanReport {
  /** Block a save (API 422, UI blocks save). */
  readonly errors: readonly ScanIssue[];
  /** Allowed, shown as a UI warning. */
  readonly warnings: readonly ScanIssue[];
}

const EC_RANK: Readonly<Record<EcLevel, number>> = { M: 0, Q: 1, H: 2 };

/** Lowest EC level the style allows: H with a logo, Q for stylised modules, else M. */
export function ecFloor(style: Pick<QrStyleV2, 'logo' | 'modules'>): EcLevel {
  if (style.logo) return 'H';
  if (style.modules !== 'square') return 'Q';
  return 'M';
}

/**
 * EC level used for rendering: `auto` resolves to the floor, and an explicit
 * level is never used below the floor (a save below it is rejected by
 * `checkStyle`; existing rows still render).
 */
export function resolveEcLevel(style: Pick<QrStyleV2, 'logo' | 'modules' | 'ecLevel'>): EcLevel {
  const floor = ecFloor(style);
  if (style.ecLevel === 'auto') return floor;
  return EC_RANK[style.ecLevel] >= EC_RANK[floor] ? style.ecLevel : floor;
}

/**
 * Lowest fg/bg contrast ratio a style may be saved with: 7 for a light-on-dark
 * style with a logo, 3.5 for any other style with a logo, else 3. Light-on-dark
 * is decided by the colours, not the `inverted` flag.
 */
export function contrastFloor(style: Pick<QrStyleV2, 'logo' | 'fg' | 'bg'>): number {
  if (!style.logo) return CONTRAST_MIN;
  return isLighter(style.fg, style.bg) ? CONTRAST_MIN_INVERTED_WITH_LOGO : CONTRAST_MIN_WITH_LOGO;
}

function contrastIssues(
  a: string,
  b: string,
  codes: { error: ScanIssueCode; warn: ScanIssueCode },
  what: string,
  floor: number = CONTRAST_MIN,
): { errors: ScanIssue[]; warnings: ScanIssue[] } {
  const ratio = contrastRatio(a, b);
  const shown = ratio.toFixed(2);
  if (ratio < floor) {
    return {
      errors: [{ code: codes.error, message: `${what} contrast ${shown}:1 is below ${floor}:1` }],
      warnings: [],
    };
  }
  if (ratio < CONTRAST_WARN) {
    return {
      errors: [],
      warnings: [{ code: codes.warn, message: `${what} contrast ${shown}:1 is below ${CONTRAST_WARN}:1` }],
    };
  }
  return { errors: [], warnings: [] };
}

/**
 * Write-time scannability rules for a v2 style (ADR-0005 D4). Rendering never
 * rejects a stored style on these grounds; saving a style must pass them.
 * `version` is the symbol version, when known, for the logo limit.
 */
export function checkStyle(style: QrStyleV2, version?: number): ScanReport {
  const errors: ScanIssue[] = [];
  const warnings: ScanIssue[] = [];
  const add = (r: { errors: ScanIssue[]; warnings: ScanIssue[] }): void => {
    errors.push(...r.errors);
    warnings.push(...r.warnings);
  };

  if (style.logo && isLighter(style.fg, style.bg)) {
    add(
      contrastIssues(
        style.fg,
        style.bg,
        { error: 'contrast-too-low-inverted-with-logo', warn: 'contrast-low' },
        'Light on dark with a logo, colour',
        CONTRAST_MIN_INVERTED_WITH_LOGO,
      ),
    );
  } else if (style.logo) {
    add(
      contrastIssues(
        style.fg,
        style.bg,
        { error: 'contrast-too-low-with-logo', warn: 'contrast-low' },
        'With a logo, colour',
        CONTRAST_MIN_WITH_LOGO,
      ),
    );
  } else {
    add(contrastIssues(style.fg, style.bg, { error: 'contrast-too-low', warn: 'contrast-low' }, 'Colour'));
  }

  if (isLighter(style.fg, style.bg)) {
    if (style.inverted) {
      warnings.push({ code: 'inverted', message: 'Some scanners do not read light-on-dark codes' });
    } else {
      errors.push({
        code: 'inverted-required',
        message: 'A foreground lighter than the background requires inverted: true',
      });
    }
  } else if (style.inverted) {
    // The flag does not change how the code is drawn, so a stale `true` is
    // only a mismatch, not a scanning risk.
    warnings.push({
      code: 'inverted-mismatch',
      message: 'inverted is true, but the foreground is not lighter than the background',
    });
  }

  if (style.ecLevel !== 'auto' && EC_RANK[style.ecLevel] < EC_RANK[ecFloor(style)]) {
    errors.push({
      code: 'ec-below-floor',
      message: `EC level ${style.ecLevel} is below the minimum ${ecFloor(style)} for this style`,
    });
  }

  const frame = style.frame;
  if (frame && frame.template !== 'none') {
    const codes = { error: 'frame-contrast-too-low', warn: 'frame-contrast-low' } as const;
    if (frame.template === 'caption') {
      // A caption is text on the background, with no filled frame.
      add(contrastIssues(frame.textColor, style.bg, codes, 'Caption text', FRAME_TEXT_CONTRAST_MIN));
    } else {
      add(contrastIssues(frame.color, frame.textColor, codes, 'Frame text', FRAME_TEXT_CONTRAST_MIN));
      add(contrastIssues(frame.color, style.bg, codes, 'Frame and background'));
    }
    if (!isFrameTextSupported(frame.text)) {
      errors.push({ code: 'frame-glyph-unsupported', message: FRAME_GLYPH_UNSUPPORTED_MESSAGE });
    }
  }

  if (style.logo && version !== undefined && version > MAX_LOGO_VERSION) {
    errors.push({
      code: 'logo-version-too-high',
      message: `A logo needs symbol version ${MAX_LOGO_VERSION} or lower at EC level H`,
    });
  }

  return { errors, warnings };
}
