import { z } from 'zod';

/**
 * A URL string constrained to absolute http(s). Unlike `z.string().url()`
 * (regex-based in zod v3, which accepts `javascript:`, `data:`, `vbscript:`),
 * this parses with the WHATWG URL and rejects every non-http(s) scheme.
 * Use for link targets rendered into `href`.
 */
// Whitespace and control characters: the URL parser silently drops or
// encodes them (`ht\ttps://`, a trailing newline), so the text a user typed
// would differ from the address that is opened.
// eslint-disable-next-line no-control-regex
const SPACE_OR_CONTROL = /[\s\u0000-\u001F\u007F-\u009F]/;
const NO_SPACE_MESSAGE = 'URL must not contain spaces or control characters';

/** The URL as the WHATWG parser writes it (lowercase scheme and host, punycode, default port dropped). */
export function normalizeUrl(value: string): string {
  return new URL(value).href;
}

export function httpUrl(maxLength = 2048) {
  return z
    .string()
    .max(maxLength, `URL must not exceed ${maxLength} characters`)
    .refine((v) => !SPACE_OR_CONTROL.test(v), { message: NO_SPACE_MESSAGE })
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

const IPV4_LITERAL = /^\d{1,3}(\.\d{1,3}){3}$/;
const PRIVATE_SUFFIXES = ['.localhost', '.local', '.internal', '.home.arpa'];

/**
 * Why a hostname (as `new URL(...).hostname` gives it) cannot be a QR
 * destination, or null when it can. A scanner's browser would open these
 * on its own device or network: IP literals (the URL parser has already
 * turned decimal, hex and octal IPv4 forms into dotted form, and IPv6 is
 * bracketed, IPv4-mapped included), localhost, single-label names, and the
 * .local, .internal and .home.arpa private namespaces. Web Risk has no
 * verdict for any of them.
 */
export function destinationHostRefusal(hostname: string): string | null {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (host.startsWith('[') || host.includes(':')) return 'IP addresses are not allowed';
  if (IPV4_LITERAL.test(host)) return 'IP addresses are not allowed';
  if (host === 'localhost' || host.endsWith('.localhost')) return 'localhost is not allowed';
  if (!host.includes('.')) return 'Single-label host names are not allowed';
  if (PRIVATE_SUFFIXES.some((suffix) => host.endsWith(suffix))) return 'Private network host names are not allowed';
  return null;
}

/** True when the URL parses and its host passes destinationHostRefusal. */
export function hasPublicHost(value: string): boolean {
  try {
    return destinationHostRefusal(new URL(value).hostname) === null;
  } catch {
    return false;
  }
}

const PUBLIC_HOST_MESSAGE =
  'Must use a public host name (no IP address, localhost, single-label or private network name)';

/**
 * A QR destination: httpUrl() plus a public host (destinationHostRefusal),
 * stored normalized (normalizeUrl).
 * Used where a destination is set (create, bulk, demo, the url content
 * type); PATCH applies the host rule in the route, only to a changed URL,
 * so existing codes can still be edited.
 */
export function destinationHttpUrl(maxLength = 2048) {
  return httpUrl(maxLength).refine(hasPublicHost, { message: PUBLIC_HOST_MESSAGE }).transform(normalizeUrl);
}

/**
 * True for an absolute https URL with a host and no user name or password.
 * Credentials are refused because `https://bank.example@evil.example/`
 * shows one host and opens another.
 */
export function isSafeHttpsUrl(value: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  return parsed.protocol === 'https:' && parsed.hostname !== '' && parsed.username === '' && parsed.password === '';
}

/**
 * An absolute https URL (see isSafeHttpsUrl) with a public host, without
 * spaces or control characters, parsed to its normalized form. Used for the links of the
 * smart link and link list content types; `http:`, `javascript:`, `data:`,
 * `intent:` and every other scheme are refused.
 */
export function httpsUrl(maxLength = 2048) {
  return z
    .string()
    .max(maxLength, `URL must not exceed ${maxLength} characters`)
    .refine((v) => !SPACE_OR_CONTROL.test(v), { message: NO_SPACE_MESSAGE })
    .refine(isSafeHttpsUrl, { message: 'Must be an absolute https URL without a user name or password' })
    .refine(hasPublicHost, { message: PUBLIC_HOST_MESSAGE })
    .transform(normalizeUrl);
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
