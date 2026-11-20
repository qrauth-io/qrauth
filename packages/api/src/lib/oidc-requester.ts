import { cityFromHeaders, parseUserAgent } from './metadata.js';

/**
 * What the approving user is shown about the browser that asked to sign in
 * (audit 2026-10 FINDING-003): device class, browser and OS from the
 * User-Agent, and an approximate place from the location headers Cloudflare
 * adds at the edge. No lookup is made from here — when those headers are
 * absent the place is simply left out.
 *
 * Every value is advisory. It comes from the requesting browser or the edge,
 * so it helps a user notice "that is not my computer"; it proves nothing.
 */
export interface RequesterInfo {
  deviceType: string;
  browser: string;
  os: string;
  country?: string;
  city?: string;
}

// Place names: letters (any script), spaces and the punctuation real names use.
const PLACE_NAME = /^[\p{L}\p{M}][\p{L}\p{M} .'’()-]{0,63}$/u;
const COUNTRY_CODE = /^[A-Z]{2}$/;

function headerValue(value: string | string[] | undefined): string | undefined {
  const first = Array.isArray(value) ? value[0] : value;
  return first?.trim() || undefined;
}

export function describeRequester(headers: Record<string, string | string[] | undefined>): RequesterInfo {
  const device = parseUserAgent(headerValue(headers['user-agent']));
  const country = headerValue(headers['cf-ipcountry']);
  // Only when Cloudflare is known to set it; otherwise the header is the
  // visitor's own and would let them choose what the approver is shown.
  const city = cityFromHeaders(headers);
  return {
    ...device,
    // XX and T1 are Cloudflare's "unknown" and "Tor" markers, not countries.
    ...(country && COUNTRY_CODE.test(country) && country !== 'XX' && country !== 'T1' ? { country } : {}),
    ...(city ? { city } : {}),
  };
}

/** Narrow whatever was stored in AuthSession.metadata back to a RequesterInfo. */
export function readRequester(metadata: unknown): RequesterInfo | null {
  const requester = (metadata as { requester?: unknown } | null)?.requester;
  if (!requester || typeof requester !== 'object') return null;
  const { deviceType, browser, os, country, city } = requester as Record<string, unknown>;
  if (typeof deviceType !== 'string' || typeof browser !== 'string' || typeof os !== 'string') return null;
  return {
    deviceType,
    browser,
    os,
    ...(typeof country === 'string' && COUNTRY_CODE.test(country) ? { country } : {}),
    ...(typeof city === 'string' && PLACE_NAME.test(city) ? { city } : {}),
  };
}

const DEVICE_LABELS: Record<string, string> = {
  desktop: 'Computer',
  mobile: 'Phone',
  tablet: 'Tablet',
};

/** One line for the approval page, e.g. "Computer · Chrome 130 on macOS · Athens, GR". */
export function formatRequester(info: RequesterInfo): string {
  const device = DEVICE_LABELS[info.deviceType] ?? 'Unknown device';
  const software = [info.browser, info.os].filter((part) => part !== 'unknown').join(' on ');
  const place = [info.city, info.country].filter(Boolean).join(', ');
  return [device, software, place].filter(Boolean).join(' · ');
}
