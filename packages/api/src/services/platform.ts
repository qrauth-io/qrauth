import type { AppLinkContent } from '@qrauth/shared';

/**
 * Scanner platform for the smart link content type, from the User-Agent.
 *
 * iPadOS 13 and later ask for the desktop site by default and send a
 * Macintosh User-Agent that the server cannot tell from a Mac; those
 * scanners get `other` (the website link), and the page still lists the
 * App Store link. Windows Phone User-Agents mention Android and are `other`.
 */
export type Platform = 'ios' | 'android' | 'other';

export function detectPlatform(userAgent: string | null | undefined): Platform {
  const ua = userAgent ?? '';
  if (/Windows Phone/i.test(ua)) return 'other';
  if (/\b(iPhone|iPad|iPod)\b/.test(ua)) return 'ios';
  if (/\bAndroid\b/i.test(ua)) return 'android';
  return 'other';
}

export const PLATFORM_URL_FIELD: Record<Platform, keyof AppLinkContent> = {
  ios: 'iosUrl',
  android: 'androidUrl',
  other: 'fallbackUrl',
};
