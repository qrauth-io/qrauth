// SPDX-License-Identifier: MIT
import { roundedRect } from '../shape.js';

/** Frame templates that draw something (ADR-0005 D2); `none` draws no frame. */
export type DrawnFrameTemplate = 'caption' | 'banner-bottom' | 'banner-top' | 'rounded-label' | 'badge';

/** Frame border around the code, in modules. */
export const FRAME_BORDER = 1;
/** Corner radius of the frame's outer shape, in modules. */
export const FRAME_RADIUS = 1.5;
/** Text band height as a share of the code's side (quiet zone included), at least FRAME_BAND_MIN. */
export const FRAME_BAND_RATIO = 0.2;
export const FRAME_BAND_MIN = 6;
/** The badge's band holds two lines, so it is this much taller. */
export const BADGE_BAND_FACTOR = 1.5;
/** Width of the rounded label's tab as a share of the artwork width. */
export const LABEL_TAB_RATIO = 0.6;
/** Capital-letter height as a share of a text box's height. */
export const TEXT_CAP_RATIO = 0.4;
/** Horizontal space kept free between text and the frame's edge, in modules. */
export const TEXT_INSET = 2;
/**
 * The fixed mark the badge template draws under the customer's text, by the
 * issuer's status (ADR-0005 D9, amendment of 2026-10-30). The badge asserts
 * verification only when QRAuth has verified the issuer (`isIssuerVerified`
 * in packages/shared/src/issuer.ts); every QRAuth code is signed, so the
 * other wording is true for all of them. Both strings are in the frame font.
 */
export const BADGE_MARK_VERIFIED = 'Verified by QRAuth';
export const BADGE_MARK_SIGNED = 'Signed with QRAuth';

/** The badge mark for an issuer that is (or is not) verified. */
export function badgeMark(issuerVerified: boolean): string {
  return issuerVerified ? BADGE_MARK_VERIFIED : BADGE_MARK_SIGNED;
}

/** A box text is centred in; `cap` is the largest capital height, in modules. */
export interface TextBox {
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly height: number;
  readonly cap: number;
  /** `text` draws the frame text, `mark` the badge's fixed mark. */
  readonly role: 'text' | 'mark';
}

/**
 * Geometry of a frame around a code square of `side` modules (symbol plus
 * quiet zone). The code square is drawn at (`codeX`, `codeY`); the frame's
 * paint (`underlay`, in the frame colour) is drawn first and the code's
 * opaque background over it, so frame paint never shows inside the quiet
 * zone, and text boxes lie entirely outside the code square (D2, D4.5).
 * Dimensions depend only on the template and the side, never on the text.
 */
export interface FrameLayout {
  readonly width: number;
  readonly height: number;
  readonly codeX: number;
  readonly codeY: number;
  /** Path data of the frame-colour shape, or '' (caption: text on the background). */
  readonly underlay: string;
  /** Caption only: the code's background covers the whole artwork. */
  readonly backgroundCoversArtwork: boolean;
  readonly textBoxes: readonly TextBox[];
}

/** Text band height for a code square of `side` modules. */
export function frameBand(side: number): number {
  return Math.max(FRAME_BAND_MIN, Math.round(side * FRAME_BAND_RATIO));
}

function box(x: number, y: number, width: number, height: number, role: TextBox['role'] = 'text', capRatio = TEXT_CAP_RATIO): TextBox {
  return { x, y, width, height, cap: height * capRatio, role };
}

/** The layout of `template` around a code square of `side` modules. */
export function frameLayout(template: DrawnFrameTemplate, side: number): FrameLayout {
  const b = FRAME_BORDER;
  const band = frameBand(side);
  const r = FRAME_RADIUS;
  switch (template) {
    case 'caption': {
      const width = side;
      const height = side + band;
      return {
        width,
        height,
        codeX: 0,
        codeY: 0,
        underlay: '',
        backgroundCoversArtwork: true,
        textBoxes: [box(TEXT_INSET, side, width - 2 * TEXT_INSET, band)],
      };
    }
    case 'banner-bottom': {
      const width = side + 2 * b;
      const height = side + b + band;
      return {
        width,
        height,
        codeX: b,
        codeY: b,
        underlay: roundedRect(0, 0, width, height, [r, r, r, r]),
        backgroundCoversArtwork: false,
        textBoxes: [box(TEXT_INSET, b + side, width - 2 * TEXT_INSET, band)],
      };
    }
    case 'banner-top': {
      const width = side + 2 * b;
      const height = band + side + b;
      return {
        width,
        height,
        codeX: b,
        codeY: band,
        underlay: roundedRect(0, 0, width, height, [r, r, r, r]),
        backgroundCoversArtwork: false,
        textBoxes: [box(TEXT_INSET, 0, width - 2 * TEXT_INSET, band)],
      };
    }
    case 'rounded-label': {
      const width = side + 2 * b;
      const height = band + side + b;
      const tab = Math.round(width * LABEL_TAB_RATIO);
      const tabX = (width - tab) / 2;
      return {
        width,
        height,
        codeX: b,
        codeY: band,
        // A border one module thick around the code, and a tab above it that
        // holds the text. Both sub-paths wind clockwise (nonzero union).
        underlay:
          roundedRect(0, band - b, width, side + 2 * b, [r, r, r, r]) + roundedRect(tabX, 0, tab, band, [r, r, 0, 0]),
        backgroundCoversArtwork: false,
        textBoxes: [box(tabX + r, 0, tab - 2 * r, band - b)],
      };
    }
    case 'badge': {
      const width = side + 2 * b;
      const tall = Math.round(band * BADGE_BAND_FACTOR);
      const height = side + b + tall;
      const top = b + side;
      const textHeight = tall * 0.6;
      return {
        width,
        height,
        codeX: b,
        codeY: b,
        underlay: roundedRect(0, 0, width, height, [r, r, r, r]),
        backgroundCoversArtwork: false,
        textBoxes: [
          box(TEXT_INSET, top, width - 2 * TEXT_INSET, textHeight),
          box(TEXT_INSET, top + textHeight, width - 2 * TEXT_INSET, tall - textHeight - b / 2, 'mark', 0.45),
        ],
      };
    }
    default:
      throw new Error(`qr-render: unknown frame template ${JSON.stringify(template)}`);
  }
}
