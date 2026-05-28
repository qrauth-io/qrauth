import { z } from 'zod';

/**
 * A URL string constrained to absolute http(s). Unlike `z.string().url()`
 * (regex-based in zod v3, which accepts `javascript:`, `data:`, `vbscript:`),
 * this parses with the WHATWG URL and rejects every non-http(s) scheme.
 * Use for link targets rendered into `href`.
 */
export function httpUrl(maxLength = 2048) {
  return z
    .string()
    .max(maxLength, `URL must not exceed ${maxLength} characters`)
    .refine(
      (v) => {
        try {
          const proto = new URL(v).protocol;
          return proto === 'http:' || proto === 'https:';
        } catch {
          return false;
        }
      },
      { message: 'Must be an absolute http(s) URL' },
    );
}

/**
 * For image `src` fields (`photoUrl`, `imageUrl`, `logoUrl`). Permits absolute
 * http(s) URLs and inline `data:image/...;base64` images (the verify-page CSP
 * allows `img-src ... data:`, and `javascript:`/`vbscript:` do not execute in
 * an `<img src>` regardless). Blocks every other scheme, including
 * `data:text/html` and protocol-relative `//evil`.
 */
export function safeImageUrl() {
  return z.string().refine(
    (v) => {
      if (/^data:image\/(png|jpe?g|gif|webp|avif|svg\+xml);base64,/i.test(v)) return true;
      try {
        const proto = new URL(v).protocol;
        return proto === 'http:' || proto === 'https:';
      } catch {
        return false;
      }
    },
    { message: 'Must be an http(s) URL or a data:image' },
  );
}
