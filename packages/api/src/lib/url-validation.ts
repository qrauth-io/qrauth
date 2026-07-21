import { URL } from 'node:url';
import { isIP } from 'node:net';

/**
 * Decompose a URL hostname into a canonical IPv4/IPv6 form for range checks.
 *
 * Handles the bypasses Node's bare `isIP()` misses:
 *  - bracketed IPv6 (`[::1]` -> `::1`)
 *  - IPv4-mapped IPv6 in dotted form (`::ffff:169.254.169.254`)
 *  - IPv4-mapped IPv6 in hex form (`::ffff:a9fe:a9fe`, which is how the URL
 *    parser normalizes the dotted mapped address)
 */
function normalizeHostname(raw: string): { host: string; ipv4?: string; ipv6?: string } {
  let host = raw.toLowerCase();

  // URL.hostname keeps the brackets for IPv6 literals.
  if (host.startsWith('[') && host.endsWith(']')) {
    host = host.slice(1, -1);
  }

  // IPv4-mapped IPv6: ::ffff:<v4>
  const mapped = host.match(/^::ffff:(.+)$/i);
  if (mapped) {
    const tail = mapped[1];
    if (isIP(tail) === 4) {
      return { host, ipv4: tail };
    }
    const hex = tail.match(/^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
    if (hex) {
      const hi = parseInt(hex[1], 16);
      const lo = parseInt(hex[2], 16);
      const dotted = [(hi >> 8) & 0xff, hi & 0xff, (lo >> 8) & 0xff, lo & 0xff].join('.');
      return { host, ipv4: dotted };
    }
  }

  const fam = isIP(host);
  if (fam === 4) return { host, ipv4: host };
  if (fam === 6) return { host, ipv6: host };
  return { host };
}

/** Returns a rejection reason for a private/reserved IPv4 address, else null. */
function rejectIPv4(ip: string): string | null {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) {
    return 'Malformed IPv4 address';
  }
  const [a, b] = parts;
  if (a === 0) return 'Reserved IP range (0.0.0.0/8) not allowed';
  if (a === 10) return 'Private IP range (10.0.0.0/8) not allowed';
  if (a === 127) return 'Loopback range (127.0.0.0/8) not allowed';
  if (a === 100 && b >= 64 && b <= 127) return 'CGNAT range (100.64.0.0/10) not allowed';
  if (a === 169 && b === 254) return 'Link-local / metadata address (169.254.0.0/16) not allowed';
  if (a === 172 && b >= 16 && b <= 31) return 'Private IP range (172.16.0.0/12) not allowed';
  if (a === 192 && b === 168) return 'Private IP range (192.168.0.0/16) not allowed';
  return null;
}

/** Returns a rejection reason for a private/reserved IPv6 address, else null. */
function rejectIPv6(ip: string): string | null {
  const norm = ip.toLowerCase();
  if (norm === '::1') return 'IPv6 loopback (::1) not allowed';
  if (norm === '::') return 'Unspecified address (::) not allowed';

  const firstHextet = parseInt(norm.split(':')[0] || '0', 16) || 0;
  // fe80::/10 link-local
  if ((firstHextet & 0xffc0) === 0xfe80) return 'IPv6 link-local (fe80::/10) not allowed';
  // fc00::/7 unique-local (fc00:: and fd00::)
  if ((firstHextet & 0xfe00) === 0xfc00) return 'IPv6 unique-local (fc00::/7) not allowed';
  return null;
}

/**
 * Returns a rejection reason for a RAW resolved IP literal (v4 or v6), else
 * null. This is the address-level counterpart to {@link isSafeWebhookUrl}'s
 * hostname check: `safeFetch` calls it on every address `dns.lookup` returns,
 * applying the exact same reserved-range blocklist so a hostname cannot resolve
 * past the URL check and then connect to an internal address (INJ-005).
 *
 * `true` for `isLoopback` is returned alongside so callers can selectively
 * permit loopback in non-production (the E2E webhook-capture affordance)
 * without widening the rest of the blocklist.
 */
export function reservedAddressReason(ip: string): { reason: string | null; isLoopback: boolean } {
  const fam = isIP(ip);
  if (fam === 4) {
    return { reason: rejectIPv4(ip), isLoopback: ip.startsWith('127.') };
  }
  if (fam === 6) {
    const norm = ip.toLowerCase();
    // dns.lookup can hand back an IPv4-mapped IPv6 literal (e.g. ::ffff:10.0.0.1).
    const mapped = norm.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) {
      return { reason: rejectIPv4(mapped[1]), isLoopback: mapped[1].startsWith('127.') };
    }
    return { reason: rejectIPv6(ip), isLoopback: norm === '::1' };
  }
  return { reason: 'Unresolvable or malformed address', isLoopback: false };
}

/**
 * Validates that a URL is safe for server-side requests (SSRF protection).
 * Rejects private/reserved IPs (v4 + v6, including IPv4-mapped IPv6),
 * loopback, link-local/metadata, and non-HTTP protocols.
 *
 * This is a string-level (hostname) check. On its own it does NOT defend
 * against DNS rebinding — a hostname can resolve to a public IP here and a
 * private IP at connect time. That residual (pentest INJ-005) is now closed by
 * {@link safeFetch} in `lib/safe-fetch.ts`, which resolves the host once,
 * validates every resolved address with {@link reservedAddressReason}, and pins
 * the connection to a validated address (and still uses `redirect: 'manual'`).
 * Webhook delivery goes through `safeFetch`; call this directly only for the
 * cheap up-front check at registration time (where no connection is made).
 */
export function isSafeWebhookUrl(
  urlString: string,
  opts: { allowLoopback?: boolean } = {},
): { safe: boolean; reason?: string } {
  // `allowLoopback` relaxes ONLY loopback (localhost / 127.0.0.0/8 / ::1) and is
  // used solely by the non-production E2E webhook-capture affordance. Every
  // other reserved range stays blocked. Default off → existing callers (e.g.
  // app.ts registration checks) are unchanged.
  const allowLoopback = opts.allowLoopback === true;

  let parsed: URL;
  try {
    parsed = new URL(urlString);
  } catch {
    return { safe: false, reason: 'Invalid URL' };
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return { safe: false, reason: `Protocol "${parsed.protocol}" not allowed` };
  }

  const { host, ipv4, ipv6 } = normalizeHostname(parsed.hostname);

  if (!allowLoopback && (host === 'localhost' || host.endsWith('.localhost'))) {
    return { safe: false, reason: 'Loopback hostname not allowed' };
  }
  if (host === 'metadata.google.internal' || host === 'metadata.google') {
    return { safe: false, reason: 'Cloud metadata endpoint not allowed' };
  }

  if (ipv4) {
    const reason = rejectIPv4(ipv4);
    if (reason && !(allowLoopback && ipv4.startsWith('127.'))) return { safe: false, reason };
  }
  if (ipv6) {
    const reason = rejectIPv6(ipv6);
    if (reason && !(allowLoopback && ipv6.toLowerCase() === '::1')) return { safe: false, reason };
  }

  return { safe: true };
}
