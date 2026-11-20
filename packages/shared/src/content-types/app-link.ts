import { z } from 'zod';
import { registerContentType } from './registry.js';
import { httpsUrl } from '../http-url.js';

/**
 * Smart link ("app-store link"): one code for an app on both stores. The
 * verify page detects the platform from the User-Agent; a VERIFIED code in
 * scan mode FLASH continues to that platform's URL, every other scan shows
 * the three choices. All three URLs are https and screened (Web Risk and the
 * lookalike check) on create, on edit and in the daily re-scan.
 */
export const appLinkContentSchema = z
  .object({
    iosUrl: httpsUrl(),
    androidUrl: httpsUrl(),
    fallbackUrl: httpsUrl(),
  })
  .strict();

export type AppLinkContent = z.infer<typeof appLinkContentSchema>;

export const APP_LINK_URL_FIELDS = ['iosUrl', 'androidUrl', 'fallbackUrl'] as const;

registerContentType({
  id: 'app-link',
  label: 'App Store Link',
  description: 'One code for your app on the App Store, Google Play and the web',
  icon: 'solar:smartphone-bold',
  category: 'link',
  schema: appLinkContentSchema,
  fields: [
    { name: 'iosUrl', type: 'url', label: 'App Store URL', required: true, placeholder: 'https://apps.apple.com/app/id000000000', helpText: 'Opened on iPhone and iPad' },
    { name: 'androidUrl', type: 'url', label: 'Google Play URL', required: true, placeholder: 'https://play.google.com/store/apps/details?id=com.example', helpText: 'Opened on Android' },
    { name: 'fallbackUrl', type: 'url', label: 'Website URL', required: true, placeholder: 'https://example.com/app', helpText: 'Opened on every other device' },
  ],
  hasFileUpload: false,
  freeTierAllowed: false,
});
