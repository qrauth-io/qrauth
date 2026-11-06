import { describe, it, expect } from 'vitest';
import { extendedCreateSchema } from '../qrcodes.js';

// Regression: a url-type QR submitted with an empty Destination URL used to
// pass validation (destinationUrl is .optional() to support non-url content
// types) and then crash prisma.qRCode.create() with a PrismaClientValidationError
// → 500. The superRefine now re-requires destinationUrl for url-type QRs so the
// caller gets a clean 400 instead.

describe('extendedCreateSchema — destinationUrl requirement', () => {
  it('rejects a url-type QR with no destinationUrl', () => {
    const result = extendedCreateSchema.safeParse({ contentType: 'url' });

    expect(result.success).toBe(false);
    if (!result.success) {
      const issue = result.error.issues.find((i) => i.path[0] === 'destinationUrl');
      expect(issue?.message).toBe('Destination URL is required for URL QR codes');
    }
  });

  it('rejects when contentType is unset (defaults to url) and destinationUrl is missing', () => {
    const result = extendedCreateSchema.safeParse({ label: 'No URL' });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some((i) => i.path[0] === 'destinationUrl')).toBe(true);
    }
  });

  it('accepts a url-type QR when destinationUrl is present', () => {
    const result = extendedCreateSchema.safeParse({
      contentType: 'url',
      destinationUrl: 'https://example.com',
    });

    expect(result.success).toBe(true);
  });

  it('does not require destinationUrl for non-url content types', () => {
    const result = extendedCreateSchema.safeParse({
      contentType: 'vcard',
      content: { firstName: 'Ada', lastName: 'Lovelace' },
    });

    expect(result.success).toBe(true);
  });
});

describe('extendedCreateSchema — destinationUrl scheme', () => {
  it.each([
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'intent://example.com#Intent;scheme=https;end',
    'ftp://example.com/file',
  ])('rejects %s', (destinationUrl) => {
    const result = extendedCreateSchema.safeParse({ contentType: 'url', destinationUrl });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some((i) => i.path[0] === 'destinationUrl')).toBe(true);
    }
  });

  it.each(['http://example.com/path', 'https://example.com/path?q=1'])('accepts %s', (destinationUrl) => {
    const result = extendedCreateSchema.safeParse({ contentType: 'url', destinationUrl });

    expect(result.success).toBe(true);
  });

  it('rejects a destinationUrl longer than 2048 characters', () => {
    const destinationUrl = `https://example.com/${'a'.repeat(2048)}`;
    const result = extendedCreateSchema.safeParse({ contentType: 'url', destinationUrl });

    expect(result.success).toBe(false);
  });
});
