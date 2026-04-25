import { URL } from 'node:url';
import { isIP } from 'node:net';

/**
 * Validates that a URL is safe for server-side requests (SSRF protection).
 * Rejects private IPs, link-local, loopback, metadata endpoints, and non-HTTP protocols.
 */
export function isSafeWebhookUrl(urlString: string): { safe: boolean; reason?: string } {
  let parsed: URL;
  try {
    parsed = new URL(urlString);
  } catch {
    return { safe: false, reason: 'Invalid URL' };
  }

  // Only allow HTTP(S)
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return { safe: false, reason: `Protocol "${parsed.protocol}" not allowed` };
  }

  const hostname = parsed.hostname.toLowerCase();

  // Reject loopback
  if (
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '[::1]' ||
    hostname === '::1' ||
    hostname === '0.0.0.0'
  ) {
    return { safe: false, reason: 'Loopback addresses not allowed' };
  }

  // Check if hostname is a raw IP
  const ip = isIP(hostname) ? hostname : null;
  if (ip) {
    const parts = ip.split('.').map(Number);

    // 10.0.0.0/8
    if (parts[0] === 10) {
      return { safe: false, reason: 'Private IP range (10.x) not allowed' };
    }
    // 172.16.0.0/12
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) {
      return { safe: false, reason: 'Private IP range (172.16-31.x) not allowed' };
    }
    // 192.168.0.0/16
    if (parts[0] === 192 && parts[1] === 168) {
      return { safe: false, reason: 'Private IP range (192.168.x) not allowed' };
    }
    // 169.254.0.0/16 (link-local / cloud metadata)
    if (parts[0] === 169 && parts[1] === 254) {
      return { safe: false, reason: 'Link-local / metadata address not allowed' };
    }
    // 0.0.0.0/8
    if (parts[0] === 0) {
      return { safe: false, reason: 'Reserved IP range not allowed' };
    }
  }

  // Reject common metadata hostnames
  if (hostname === 'metadata.google.internal' || hostname === 'metadata.google') {
    return { safe: false, reason: 'Cloud metadata endpoint not allowed' };
  }

  return { safe: true };
}
