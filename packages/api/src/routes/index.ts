import type { FastifyInstance, FastifyPluginAsync } from 'fastify';

import authRoutes from './auth.js';
import organizationRoutes from './organizations.js';
import securityWebhookRoutes from './organizations/security-webhook.js';
import appRoutes from './apps.js';
import qrcodeRoutes from './qrcodes.js';
import { folderRoutes, tagRoutes } from './qr-organize.js';
import qrcodeImageRoutes from './qrcode-image.js';
import assetRoutes from './assets.js';
import verifyRoutes from './verify.js';
import abuseReportRoutes from './abuse-reports.js';
import analyticsRoutes from './analytics.js';
import fraudRuleRoutes from './fraud-rules.js';
import transparencyRoutes from './transparency.js';
import authSessionRoutes from './auth-sessions.js';
import ephemeralRoutes from './ephemeral.js';
import proximityRoutes from './proximity.js';
import animatedQRRoutes from './animated-qr.js';
import approvalRoutes from './approval.js';
import apiKeyRoutes from './api-keys.js';
import usageRoutes from './usage.js';
import webhookDeliveryRoutes from './webhook-deliveries.js';
import billingRoutes from './billing.js';
import adminRoutes from './admin.js';
import adminAbuseRoutes from './admin-abuse.js';
import deviceRoutes from './devices.js';
import webauthnRoutes from './webauthn.js';
import gdprRoutes from './gdpr.js';
import sessionRoutes from './sessions.js';
import demoRoutes from './demo.js';
import internalMacStatsRoutes from './internal-mac-stats.js';
import oidcRoutes from './oidc.js';
import oidcFlowRoutes from './oidc-flow.js';
import oidcClientRoutes from './oidc-clients.js';
import oidcConsentRoutes from './oidc-consents.js';
import auditRoutes from './audit.js';
import orgPolicyRoutes from './org-policies.js';
import bulkRoutes from './bulk.js';

/**
 * Every route plugin and its prefix, in registration order. server.ts
 * registers them; the audit coverage test (routes/__tests__/audit-coverage)
 * registers them on a bare instance to list every mutating route.
 */
export const ROUTE_PLUGINS: ReadonlyArray<readonly [FastifyPluginAsync, string | undefined]> = [
  [authRoutes, '/api/v1/auth'],
  [organizationRoutes, '/api/v1/organizations'],
  [securityWebhookRoutes, '/api/v1/organizations'],
  [appRoutes, '/api/v1/apps'],
  [qrcodeRoutes, '/api/v1/qrcodes'],
  [qrcodeImageRoutes, '/api/v1/qrcodes'],
  [tagRoutes, '/api/v1/tags'],
  [folderRoutes, '/api/v1/folders'],
  [assetRoutes, '/api/v1/assets'],
  // Verify is on the short public URL (/v/:token) and the REST path.
  [verifyRoutes, '/v'],
  [abuseReportRoutes, '/v'],
  [verifyRoutes, '/api/v1/verify'],
  [analyticsRoutes, '/api/v1/analytics'],
  [fraudRuleRoutes, '/api/v1/analytics'],
  [transparencyRoutes, '/api/v1/transparency'],
  [authSessionRoutes, '/api/v1/auth-sessions'],
  [ephemeralRoutes, '/api/v1/ephemeral'],
  [proximityRoutes, '/api/v1/proximity'],
  [animatedQRRoutes, '/api/v1/animated-qr'],
  [approvalRoutes, '/a'],
  [apiKeyRoutes, '/api/v1/api-keys'],
  [usageRoutes, '/api/v1/usage'],
  [webhookDeliveryRoutes, '/api/v1/webhook-deliveries'],
  [billingRoutes, '/api/v1/billing'],
  [adminRoutes, '/api/v1/admin'],
  [adminAbuseRoutes, '/api/v1/admin'],
  [deviceRoutes, '/api/v1/devices'],
  [webauthnRoutes, '/api/v1/webauthn'],
  [gdprRoutes, '/api/v1/account'],
  [sessionRoutes, '/api/v1/sessions'],
  [demoRoutes, '/api/v1/demo'],
  [internalMacStatsRoutes, '/internal'],
  [oidcRoutes, '/.well-known'],
  // OIDC flow and OP-hosted login at the root (/authorize, /token, /login).
  [oidcFlowRoutes, undefined],
  [oidcClientRoutes, '/api/v1/oidc/clients'],
  [oidcConsentRoutes, '/api/v1/oidc/consents'],
  [auditRoutes, '/api/v1/audit'],
  [orgPolicyRoutes, '/api/v1/policies'],
  [bulkRoutes, '/api/v1/bulk'],
];

export async function registerRoutes(app: FastifyInstance): Promise<void> {
  for (const [plugin, prefix] of ROUTE_PLUGINS) {
    await app.register(plugin, prefix ? { prefix } : {});
  }
}
