import type { FastifyRequest } from 'fastify';
import { config } from './config.js';

// ---------------------------------------------------------------------------
// User-Agent parsing (lightweight, no dependency)
// ---------------------------------------------------------------------------

interface DeviceInfo {
  deviceType: string; // 'mobile' | 'tablet' | 'desktop' | 'bot' | 'unknown'
  browser: string;
  os: string;
}

export function parseUserAgent(ua?: string | null): DeviceInfo {
  if (!ua) return { deviceType: 'unknown', browser: 'unknown', os: 'unknown' };

  // Device type
  let deviceType = 'desktop';
  if (/bot|crawler|spider|scraper/i.test(ua)) deviceType = 'bot';
  else if (/Mobile|Android.*Mobile|iPhone|iPod/i.test(ua)) deviceType = 'mobile';
  else if (/iPad|Android(?!.*Mobile)|Tablet/i.test(ua)) deviceType = 'tablet';

  // Browser
  let browser = 'unknown';
  if (/Edg\//i.test(ua)) browser = 'Edge';
  else if (/OPR\//i.test(ua)) browser = 'Opera';
  else if (/Chrome\//i.test(ua)) browser = 'Chrome';
  else if (/Safari\//i.test(ua) && !/Chrome/i.test(ua)) browser = 'Safari';
  else if (/Firefox\//i.test(ua)) browser = 'Firefox';

  // Extract version
  const versionMatch = ua.match(new RegExp(`${browser === 'Edge' ? 'Edg' : browser === 'Opera' ? 'OPR' : browser}/([\\d.]+)`));
  if (versionMatch) browser = `${browser} ${versionMatch[1].split('.')[0]}`;

  // OS
  let os = 'unknown';
  if (/Windows NT 10/i.test(ua)) os = 'Windows 10+';
  else if (/Windows/i.test(ua)) os = 'Windows';
  else if (/Mac OS X/i.test(ua)) os = 'macOS';
  else if (/iPhone|iPad/i.test(ua)) os = 'iOS';
  else if (/Android/i.test(ua)) os = 'Android';
  else if (/Linux/i.test(ua)) os = 'Linux';

  return { deviceType, browser, os };
}

// ---------------------------------------------------------------------------
// Location, from Cloudflare's visitor-location headers
// ---------------------------------------------------------------------------
//
// No lookup service is called and no client IP leaves the platform (audit
// 2026-10 FINDING-015). Cloudflare sets CF-IPCountry on every request,
// replacing whatever the visitor sent. CF-IPCity is different: Cloudflare
// sets it only when the "Add visitor location headers" managed transform is
// on, and otherwise passes a visitor's own CF-IPCity through. The city is
// therefore read only when CF_VISITOR_LOCATION_HEADERS says the transform is
// on. When a header is absent there is simply no location: callers treat
// that as unknown, never as suspicious.

interface GeoInfo {
  country?: string;
  city?: string;
}

const COUNTRY_CODE = /^[A-Z]{2}$/;
/** Cloudflare's markers for "unknown" and "Tor exit": not countries. */
const NOT_A_COUNTRY: ReadonlySet<string> = new Set(['XX', 'T1']);
// Place names: letters (any script), spaces and the punctuation real names use.
const PLACE_NAME = /^[\p{L}\p{M}][\p{L}\p{M} .'’()-]{0,63}$/u;
const LOOPBACK: ReadonlySet<string> = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);

// Stored and shown as English country names, as before ("Greece", not "GR").
const countryNames = new Intl.DisplayNames(['en'], { type: 'region' });

function headerValue(value: string | string[] | undefined): string | undefined {
  const first = Array.isArray(value) ? value[0] : value;
  return first?.trim() || undefined;
}

/**
 * Location of the client, or `{}`. The headers are believed only on a
 * request that reached this process through the local reverse proxy; on a
 * direct connection anyone could have written them.
 */
export function geoFromRequest(request: FastifyRequest): GeoInfo {
  const peer = request.raw?.socket?.remoteAddress;
  if (!peer || !LOOPBACK.has(peer)) return {};

  const code = headerValue(request.headers['cf-ipcountry']);
  if (!code || !COUNTRY_CODE.test(code) || NOT_A_COUNTRY.has(code)) return {};
  const country = countryNames.of(code);
  if (!country || country === code) return {};

  const city = cityFromHeaders(request.headers);
  return city ? { country, city } : { country };
}

/**
 * The city Cloudflare reports, or undefined: when the visitor-location
 * transform is not known to be on, or the value is not a plain place name.
 */
export function cityFromHeaders(headers: Record<string, string | string[] | undefined>): string | undefined {
  if (!config.cloudflare.visitorLocationHeaders) return undefined;
  const city = headerValue(headers['cf-ipcity']);
  return city && PLACE_NAME.test(city) ? city : undefined;
}

// ---------------------------------------------------------------------------
// Collect full metadata from a Fastify request
// ---------------------------------------------------------------------------

export interface RequestMetadata {
  ipAddress: string;
  ipCountry?: string;
  ipCity?: string;
  userAgent?: string;
  deviceType?: string;
  browser?: string;
  os?: string;
  fingerprint?: string;
  referrer?: string;
}

export async function collectRequestMetadata(request: FastifyRequest): Promise<RequestMetadata> {
  const ip = request.ip || request.headers['x-forwarded-for']?.toString().split(',')[0]?.trim() || '';
  const ua = request.headers['user-agent'] || undefined;
  const fingerprint = (request.headers['x-device-fingerprint'] as string) || undefined;
  const referrer = request.headers.referer || request.headers.referrer || undefined;

  const device = parseUserAgent(ua);
  const geo = geoFromRequest(request);

  return {
    ipAddress: ip,
    ipCountry: geo.country,
    ipCity: geo.city,
    userAgent: ua,
    deviceType: device.deviceType,
    browser: device.browser,
    os: device.os,
    fingerprint,
    referrer: referrer as string | undefined,
  };
}
