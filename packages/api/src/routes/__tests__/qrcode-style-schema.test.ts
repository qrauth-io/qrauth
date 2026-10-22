import { describe, it, expect } from 'vitest';
import { qrStyleSchema, extendedCreateSchema, extendedUpdateSchema } from '../qrcodes.js';

// Issue #4: QR style is persisted to a JSON column, so the API must validate
// the shape (never store arbitrary JSON). These tests pin the qrStyleSchema
// contract and confirm it is wired (optionally) into both the create and
// update API-side schemas — and NOT required, so existing callers are unaffected.

const VALID_STYLE = {
  templateId: 'dark',
  fgColor: '#1B2A4A',
  bgColor: '#FFFFFF',
  showLogo: false,
  captionText: 'Scan me',
};

describe('qrStyleSchema', () => {
  it('accepts a well-formed style', () => {
    expect(qrStyleSchema.safeParse(VALID_STYLE).success).toBe(true);
  });

  it('rejects a non-hex color', () => {
    const r = qrStyleSchema.safeParse({ ...VALID_STYLE, fgColor: 'red' });
    expect(r.success).toBe(false);
  });

  it('rejects a 3-digit hex (must be #RRGGBB)', () => {
    const r = qrStyleSchema.safeParse({ ...VALID_STYLE, bgColor: '#FFF' });
    expect(r.success).toBe(false);
  });

  it('rejects a non-boolean showLogo', () => {
    const r = qrStyleSchema.safeParse({ ...VALID_STYLE, showLogo: 'yes' });
    expect(r.success).toBe(false);
  });

  it('rejects unknown extra keys (no arbitrary JSON)', () => {
    const r = qrStyleSchema.safeParse({ ...VALID_STYLE, evil: 'payload' });
    expect(r.success).toBe(false);
  });

  it('rejects a missing required field', () => {
    const { captionText, ...partial } = VALID_STYLE;
    expect(qrStyleSchema.safeParse(partial).success).toBe(false);
  });
});

describe('extendedCreateSchema — qrStyle', () => {
  it('accepts a create with a valid qrStyle', () => {
    const r = extendedCreateSchema.safeParse({
      contentType: 'url',
      destinationUrl: 'https://example.com',
      qrStyle: VALID_STYLE,
    });
    expect(r.success).toBe(true);
  });

  it('accepts a create with no qrStyle (optional)', () => {
    const r = extendedCreateSchema.safeParse({
      contentType: 'url',
      destinationUrl: 'https://example.com',
    });
    expect(r.success).toBe(true);
    if (r.success) expect(r.data.qrStyle).toBeUndefined();
  });

  it('rejects a create with a malformed qrStyle', () => {
    const r = extendedCreateSchema.safeParse({
      contentType: 'url',
      destinationUrl: 'https://example.com',
      qrStyle: { ...VALID_STYLE, fgColor: 'not-a-hex' },
    });
    expect(r.success).toBe(false);
  });
});

describe('extendedUpdateSchema — qrStyle', () => {
  it('accepts an update carrying only a valid qrStyle', () => {
    const r = extendedUpdateSchema.safeParse({ qrStyle: VALID_STYLE });
    expect(r.success).toBe(true);
  });

  it('rejects an update with a malformed qrStyle', () => {
    const r = extendedUpdateSchema.safeParse({ qrStyle: { ...VALID_STYLE, showLogo: 1 } });
    expect(r.success).toBe(false);
  });
});
