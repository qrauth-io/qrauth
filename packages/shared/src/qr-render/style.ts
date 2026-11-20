// SPDX-License-Identifier: MIT
import { z } from 'zod';

import { isLighter } from './colour.js';

const hexColour = z.string().regex(/^#[0-9a-fA-F]{6}$/, 'Must be a #RRGGBB hex color');

/**
 * Style v1: the shape stored today (no `version` field). Same rules as the
 * API's current schema; v1 rows are read and upgraded in memory.
 */
export const qrStyleV1Schema = z
  .object({
    templateId: z.string().min(1).max(64),
    fgColor: hexColour,
    bgColor: hexColour,
    showLogo: z.boolean(),
    captionText: z.string().max(120),
  })
  .strict();

export const MODULE_STYLES = ['square', 'rounded', 'dots', 'classy'] as const;
export const EYE_STYLES = ['square', 'rounded', 'circle', 'leaf'] as const;
export const EC_LEVELS = ['auto', 'M', 'Q', 'H'] as const;
export const FRAME_TEMPLATES = [
  'none',
  'caption',
  'banner-bottom',
  'banner-top',
  'rounded-label',
  'badge',
] as const;

export const QUIET_ZONE_MIN = 4;
export const QUIET_ZONE_MAX = 10;
export const FRAME_TEXT_MAX = 40;
export const LOGO_SCALE_MIN = 0.5;
export const LOGO_SCALE_MAX = 1;

const logoSchema = z.union([
  z.null(),
  z.object({ kind: z.literal('qrauth') }).strict(),
  z
    .object({
      kind: z.literal('asset'),
      assetId: z.string().min(1).max(64),
      scale: z.number().min(LOGO_SCALE_MIN).max(LOGO_SCALE_MAX),
    })
    .strict(),
]);

/** Line terminators: CR, LF, NEL (U+0085), LINE SEPARATOR, PARAGRAPH SEPARATOR. */
const LINE_TERMINATORS = /[\r\n\u0085\u2028\u2029]/u;
/** C0 controls, DEL and C1 controls (the line terminators above included). */
const CONTROL_CHARS = /[\u0000-\u001F\u007F-\u009F]/u;
/** Bidi controls: LRM, RLM, embeddings and overrides, isolates. */
const BIDI_CONTROLS = /[\u200E\u200F\u202A-\u202E\u2066-\u2069]/u;

/** True for frame text that is safe to draw as a single line. */
export function isValidFrameText(text: string): boolean {
  return !LINE_TERMINATORS.test(text) && !CONTROL_CHARS.test(text) && !BIDI_CONTROLS.test(text);
}

/** Line terminators become spaces; other control and bidi characters are removed. */
function toFrameText(text: string): string {
  return text
    .replace(new RegExp(LINE_TERMINATORS.source, 'gu'), ' ')
    .replace(new RegExp(CONTROL_CHARS.source, 'gu'), '')
    .replace(new RegExp(BIDI_CONTROLS.source, 'gu'), '')
    .replace(/ {2,}/g, ' ')
    .trim();
}

const frameSchema = z
  .object({
    template: z.enum(FRAME_TEMPLATES),
    text: z
      .string()
      .max(FRAME_TEXT_MAX)
      .refine(isValidFrameText, 'Frame text must be a single line without control or bidi characters'),
    color: hexColour,
    textColor: hexColour,
  })
  .strict();

/** Style v2 (ADR-0005 D2). `version` is required from v2 on. */
export const qrStyleV2Schema = z
  .object({
    version: z.literal(2),
    presetId: z.string().min(1).max(64),
    fg: hexColour,
    bg: hexColour,
    inverted: z.boolean(),
    modules: z.enum(MODULE_STYLES),
    eyes: z.enum(EYE_STYLES),
    ecLevel: z.enum(EC_LEVELS),
    quietZone: z.number().int().min(QUIET_ZONE_MIN).max(QUIET_ZONE_MAX),
    logo: logoSchema,
    frame: frameSchema.optional(),
  })
  .strict();

export type QrStyleV1 = z.infer<typeof qrStyleV1Schema>;
export type QrStyleV2 = z.infer<typeof qrStyleV2Schema>;
export type QrStyle = QrStyleV2;
export type QrLogo = QrStyleV2['logo'];
export type QrFrame = NonNullable<QrStyleV2['frame']>;

/**
 * Pure v1 -> v2 upgrade (ADR-0005 D2). A non-empty caption becomes a
 * `caption` frame truncated to 40 characters; the stored v1 row keeps the
 * full text until the user edits it, because reads upgrade in memory only.
 */
export function upgradeStyle(v1: QrStyleV1): QrStyleV2 {
  const caption = toFrameText(v1.captionText);
  return {
    version: 2,
    presetId: v1.templateId,
    fg: v1.fgColor,
    bg: v1.bgColor,
    inverted: isLighter(v1.fgColor, v1.bgColor),
    modules: 'square',
    eyes: 'square',
    ecLevel: 'auto',
    quietZone: QUIET_ZONE_MIN,
    logo: v1.showLogo ? { kind: 'qrauth' } : null,
    ...(caption
      ? {
          frame: {
            template: 'caption' as const,
            text: caption.slice(0, FRAME_TEXT_MAX).trim(),
            color: v1.bgColor,
            textColor: v1.fgColor,
          },
        }
      : {}),
  };
}

/** The default style for a new code: black on white, square, no logo. */
export const DEFAULT_STYLE: QrStyleV2 = {
  version: 2,
  presetId: 'classic',
  fg: '#000000',
  bg: '#FFFFFF',
  inverted: false,
  modules: 'square',
  eyes: 'square',
  ecLevel: 'auto',
  quietZone: QUIET_ZONE_MIN,
  logo: null,
};

/**
 * Read a stored or submitted style: v2 as is, v1 upgraded in memory.
 * Throws a ZodError for anything else.
 */
export function parseStyle(input: unknown): QrStyleV2 {
  if (input !== null && typeof input === 'object' && 'version' in input) {
    return qrStyleV2Schema.parse(input);
  }
  return upgradeStyle(qrStyleV1Schema.parse(input));
}

/**
 * Read the stored `style` column of a code. Most codes have none (null), and
 * those render with DEFAULT_STYLE; anything else goes through `parseStyle`.
 * Use `parseStyle` for submitted styles, where a style is required.
 */
export function parseStoredStyle(input: unknown): QrStyleV2 {
  if (input === null || input === undefined) return DEFAULT_STYLE;
  return parseStyle(input);
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const entries = Object.keys(value)
      .sort()
      .filter((k) => (value as Record<string, unknown>)[k] !== undefined)
      .map((k) => `${JSON.stringify(k)}:${canonical((value as Record<string, unknown>)[k])}`);
    return `{${entries.join(',')}}`;
  }
  return JSON.stringify(value);
}

/**
 * Canonical JSON of a v2 style: sorted keys, upper-case colours. Used for
 * cache keys and audit records, where equal styles must give equal strings.
 */
export function canonicalStyleJson(style: QrStyleV2): string {
  const v = qrStyleV2Schema.parse(style);
  return canonical({
    ...v,
    fg: v.fg.toUpperCase(),
    bg: v.bg.toUpperCase(),
    ...(v.frame
      ? {
          frame: {
            ...v.frame,
            color: v.frame.color.toUpperCase(),
            textColor: v.frame.textColor.toUpperCase(),
          },
        }
      : {}),
  });
}
