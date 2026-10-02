/**
 * Seed the Phase 1 internal OIDC test client (ADR-0003 Slice 3b.2).
 *
 * Mints one confidential `OidcClient` (`phase1-test-client`) on the QRAuth
 * Platform org so a stock OIDC client library can drive the auth-code flow
 * end-to-end against id.qrauth.io. Phase 1 is internal-only — no public RP.
 *
 * IDEMPOTENT: a no-op (and NO secret printed) when the row already exists.
 * The plaintext client_secret is printed exactly ONCE, on first creation —
 * store it, it cannot be recovered (only its SHA-256 hash is persisted,
 * matching App.clientSecretHash's algorithm).
 *
 * MANUAL ONLY:
 *   npm run oidc:seed-test-client -w packages/api
 * Companion teardown:
 *   npm run oidc:teardown-test-client -w packages/api
 */

import { PrismaClient } from '@prisma/client';
import { randomBytes, createHash } from 'node:crypto';
import { QRAUTH_PLATFORM_ORG_SLUG } from '../src/lib/oidc-metadata.js';

const CLIENT_ID = 'phase1-test-client';
const REDIRECT_URIS = ['http://localhost:9000/callback'];
const ALLOWED_SCOPES = [
  'openid',
  'profile',
  'email',
  'offline_access',
  'qrauth:device_trust',
  'qrauth:proximity',
  'qrauth:fraud_signals',
  'qrauth:auth_method',
];

function sha256hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

async function main(): Promise<void> {
  const prisma = new PrismaClient({ log: [{ level: 'warn', emit: 'stdout' }] });
  try {
    const existing = await prisma.oidcClient.findUnique({ where: { clientId: CLIENT_ID } });
    if (existing) {
      console.log(`OIDC test client "${CLIENT_ID}" already present. No action (secret not reprinted).`);
      return;
    }

    const org = await prisma.organization.findUnique({
      where: { slug: QRAUTH_PLATFORM_ORG_SLUG },
      select: { id: true },
    });
    if (!org) {
      throw new Error(
        `QRAuth Platform org (slug=${QRAUTH_PLATFORM_ORG_SLUG}) not found. ` +
          'Run "prisma migrate deploy" first.',
      );
    }

    const clientSecret = `qrauth_oidc_secret_${randomBytes(32).toString('hex')}`;
    await prisma.oidcClient.create({
      data: {
        organizationId: org.id,
        clientId: CLIENT_ID,
        clientSecretHash: sha256hex(clientSecret),
        name: 'Phase 1 internal test client',
        redirectUris: REDIRECT_URIS,
        allowedScopes: ALLOWED_SCOPES,
        tier: 'FIRST_PARTY',
        sectorIdentifierUri: null,
      },
    });

    console.log('Provisioned OIDC test client:');
    console.log(`  client_id:     ${CLIENT_ID}`);
    console.log(`  redirect_uris: ${REDIRECT_URIS.join(', ')}`);
    console.log(`  scopes:        ${ALLOWED_SCOPES.join(' ')}`);
    console.log('');
    console.log('  ┌──────────────────────────────────────────────────────────────┐');
    console.log('  │  STORE THIS — the client_secret is shown ONCE and cannot be   │');
    console.log('  │  recovered (only its hash is stored).                         │');
    console.log('  └──────────────────────────────────────────────────────────────┘');
    console.log(`  client_secret: ${clientSecret}`);
  } finally {
    await prisma.$disconnect();
  }
}

main().catch((err) => {
  console.error('[seed-phase1-test-client] FAILED:', err instanceof Error ? err.message : err);
  process.exit(1);
});
