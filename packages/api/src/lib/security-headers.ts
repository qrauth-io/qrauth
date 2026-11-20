import type { FastifyHelmetOptions } from '@fastify/helmet';

/**
 * helmet settings for every API-served path (/api/, /v/, /a/, /sdk/, /docs/,
 * /health, /internal/). The API is the only layer that sets these security
 * headers on those paths; nginx sets them only for paths it serves itself
 * (deploy/nginx-qrauth-io.conf, `location /`).
 *
 * Headers the qrauth.io nginx config used to duplicate, with the value the
 * API sends:
 *   X-Content-Type-Options     nosniff
 *   X-Frame-Options            SAMEORIGIN
 *   Strict-Transport-Security  max-age=31536000; includeSubDomains; preload
 *   Referrer-Policy            no-referrer
 *   X-XSS-Protection           0
 */
export const HELMET_OPTIONS: FastifyHelmetOptions = {
  // F-007 (audit 2026-05-17): CSP is owned by the onSend hook in server.ts
  // so it can set a per-response policy (nonce-based) for the verify page
  // while keeping every other route on a strict default. Helmet's single
  // static directive list can't express that, so its CSP is disabled and
  // the hook reproduces a stricter equivalent.
  contentSecurityPolicy: false,
  strictTransportSecurity: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  crossOriginResourcePolicy: false,
  crossOriginOpenerPolicy: false,
};
