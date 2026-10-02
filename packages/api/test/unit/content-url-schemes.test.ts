import { describe, it, expect } from 'vitest';
import { httpUrl, safeImageUrl, getContentType } from '@qrauth/shared';

const schemaFor = (id: string) => {
  const def = getContentType(id);
  if (!def) throw new Error(`content type not registered: ${id}`);
  return def.schema;
};

/**
 * Pentest INJ-002/003: zod v3 `z.string().url()` accepts `javascript:`,
 * `data:text/html`, and `vbscript:`. These must be rejected on every URL
 * field rendered into an `href`/`src` on the public verify page.
 */
describe('httpUrl — link href validator', () => {
  it('rejects dangerous schemes', () => {
    for (const v of ['javascript:alert(1)', 'data:text/html,<script>1</script>', 'vbscript:msgbox(1)', '//evil.com/x']) {
      expect(httpUrl().safeParse(v).success, v).toBe(false);
    }
  });

  it('accepts absolute http(s) URLs', () => {
    expect(httpUrl().safeParse('https://ok.com/a.pdf').success).toBe(true);
    expect(httpUrl().safeParse('http://ok.com').success).toBe(true);
  });

  it('enforces a max length', () => {
    expect(httpUrl(50).safeParse(`https://ok.com/${'a'.repeat(100)}`).success).toBe(false);
  });
});

describe('safeImageUrl — img src validator', () => {
  it('rejects script-bearing schemes but allows data:image', () => {
    expect(safeImageUrl().safeParse('javascript:alert(1)').success).toBe(false);
    expect(safeImageUrl().safeParse('data:text/html,x').success).toBe(false);
    expect(safeImageUrl().safeParse('//evil/p.png').success).toBe(false);
    expect(safeImageUrl().safeParse('data:image/png;base64,iVBORw0KGgo=').success).toBe(true);
    expect(safeImageUrl().safeParse('https://cdn.example.com/p.png').success).toBe(true);
  });
});

describe('content-type schemas reject javascript: in URL fields', () => {
  it('url content', () => {
    expect(schemaFor('url').safeParse({ destinationUrl: 'javascript:alert(1)' }).success).toBe(false);
    expect(schemaFor('url').safeParse({ destinationUrl: 'https://example.com' }).success).toBe(true);
  });

  it('pdf fileUrl (rendered into <a href download>)', () => {
    expect(schemaFor('pdf').safeParse({ title: 'x', fileUrl: 'javascript:fetch("//e")' }).success).toBe(false);
    expect(schemaFor('pdf').safeParse({ title: 'x', fileUrl: 'https://cdn.example.com/a.pdf' }).success).toBe(true);
  });

  it('vcard website + socialLinks', () => {
    expect(schemaFor('vcard').safeParse({ firstName: 'A', website: 'javascript:1' }).success).toBe(false);
    expect(schemaFor('vcard').safeParse({ firstName: 'A', socialLinks: [{ platform: 'x', url: 'javascript:1' }] }).success).toBe(false);
    expect(schemaFor('vcard').safeParse({ firstName: 'A', website: 'https://jane.dev' }).success).toBe(true);
  });

  it('coupon redemptionUrl', () => {
    expect(schemaFor('coupon').safeParse({ company: 'A', headline: 'B', redemptionUrl: 'javascript:1' }).success).toBe(false);
    expect(schemaFor('coupon').safeParse({ company: 'A', headline: 'B', redemptionUrl: '' }).success).toBe(true);
  });
});
