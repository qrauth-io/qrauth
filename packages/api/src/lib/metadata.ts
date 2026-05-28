import type { FastifyRequest } from 'fastify';

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
// Geo-IP lookup (using free ip-api.com — 45 req/min limit)
// No API key needed, falls back gracefully on error/rate limit
// ---------------------------------------------------------------------------

interface GeoInfo {
  country?: string;
  city?: string;
}

const geoCache = new Map<string, { data: GeoInfo; expires: number }>();

export async function lookupGeoIP(ip: string): Promise<GeoInfo> {
  // Skip private/local IPs
  if (!ip || ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168.') || ip.startsWith('10.')) {
    return {};
  }

  // Check cache (10 minute TTL)
  const cached = geoCache.get(ip);
  if (cached && cached.expires > Date.now()) return cached.data;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);

    const res = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,city`, {
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!res.ok) return {};

    const data = await res.json() as { status: string; country?: string; city?: string };
    const geo: GeoInfo = data.status === 'success' ? { country: data.country, city: data.city } : {};

    // Cache result
    geoCache.set(ip, { data: geo, expires: Date.now() + 10 * 60 * 1000 });

    // Evict old entries if cache gets too big
    if (geoCache.size > 5000) {
      const now = Date.now();
      for (const [key, val] of geoCache) {
        if (val.expires < now) geoCache.delete(key);
      }
    }

    return geo;
  } catch {
    return {};
  }
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
  const geo = await lookupGeoIP(ip);

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
