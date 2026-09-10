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

// Matches a registrable domain name: dot-separated labels (alphanumeric +
// hyphen, not leading/trailing hyphen) ending in a 2+ letter TLD.
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/;

/**
 * An organization domain, stored and used as a BARE HOSTNAME (e.g.
 * `example.com`) — that's what the DNS-TXT verification instructions and the
 * domain-similarity checks expect. Accepts a bare hostname, or a full http(s)
 * URL whose hostname is taken, and normalizes to a lowercase bare hostname.
 * Rejects anything that isn't a plausible domain. (The settings page presents
 * `domain` as a hostname — placeholder `example.com`, DNS TXT naming — so the
 * old `httpUrl()` validator rejected the very value the UI asks for.)
 */
export function domainName() {
  return z
    .string()
    .trim()
    .transform((v) => {
      // If a full URL was pasted, reduce it to its hostname.
      if (/^https?:\/\//i.test(v)) {
        try {
          return new URL(v).hostname.toLowerCase();
        } catch {
          return v.toLowerCase();
        }
      }
      return v.toLowerCase();
    })
    .refine((host) => DOMAIN_RE.test(host), {
      message: 'Must be a valid domain (e.g. example.com)',
    });
}
