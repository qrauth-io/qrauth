/**
 * One-time bootstrap: provision the QRAuth Platform org's ES256 signing key
 * for the OIDC Provider (ADR-0003 Phase 1 Slice 2).
 *
 * The OP signs every ID token with this key and JWKS publishes its public
 * half. The platform org (provisioned keyless by migration
 * 20260521120100_provision_qrauth_cli_app) has no signing key, so this script
 * mints one through the audited `SigningService.createKeyPair` path — which
 * encrypts the private key at rest and pushes it to the standalone signer
 * service, preserving the Finding-016 posture (production signing never reads
 * local PEMs; the signer holds the private bytes).
 *
 * IDEMPOTENT: a no-op when an ACTIVE ES256 key already exists on the org.
 * MANUAL ONLY: deliberately not wired into migrations, `db:seed`, or
 * `npm run dev`. This is a one-time bootstrap — future key rotations go
 * through the existing rotation machinery (`SigningService.rotateKey` /
 * the cleanup worker), never this script.
 *
 * Run on the prod host (the signer must be reachable):
 *   cd /home/progressnet/vqr/packages/api
 *   npx tsx scripts/bootstrap-platform-oidc-key.ts
 * or, from the repo:
 *   npm run oidc:bootstrap-key -w packages/api
 *
 * Note: if a run fails at the signer step, the SigningKey row may already
 * exist. Bring the signer up and re-run — this script reports the existing
 * key as present. Independently confirm signing works before relying on it.
 */

import { PrismaClient } from '@prisma/client';
import { config } from '../src/lib/config.js';
import { SigningService } from '../src/services/signing.js';
import {
  HttpEcdsaSigner,
  LocalEcdsaSigner,
  type EcdsaSigner,
} from '../src/services/ecdsa-signer/index.js';
import { QRAUTH_PLATFORM_ORG_SLUG } from '../src/lib/oidc-metadata.js';

/**
 * Mirror plugins/ecdsa-signer.ts backend selection. Inlined because this
 * script runs standalone, outside the Fastify plugin graph.
 */
function buildEcdsaSigner(): EcdsaSigner {
  if (config.ecdsaSigner.backend === 'http') {
    if (!config.ecdsaSigner.url || !config.ecdsaSigner.token) {
      throw new Error(
        'ECDSA_SIGNER=http requires ECDSA_SIGNER_URL and ECDSA_SIGNER_TOKEN',
      );
    }
    return new HttpEcdsaSigner(config.ecdsaSigner.url, config.ecdsaSigner.token);
  }
  return new LocalEcdsaSigner();
}

async function main(): Promise<void> {
  const prisma = new PrismaClient({ log: [{ level: 'warn', emit: 'stdout' }] });

  try {
    const org = await prisma.organization.findUnique({
      where: { slug: QRAUTH_PLATFORM_ORG_SLUG },
      select: { id: true },
    });

    if (!org) {
      throw new Error(
        `QRAuth Platform org (slug=${QRAUTH_PLATFORM_ORG_SLUG}) not found. ` +
          `Run "prisma migrate deploy" first — migration ` +
          `20260521120100_provision_qrauth_cli_app provisions it.`,
      );
    }

    // Reuse the rotation machinery's notion of "active": status === 'ACTIVE'.
    const existing = await prisma.signingKey.findFirst({
      where: { organizationId: org.id, algorithm: 'ES256', status: 'ACTIVE' },
      orderBy: { createdAt: 'desc' },
      select: { keyId: true },
    });

    if (existing) {
      console.log(
        `ES256 SigningKey already present on QRAuth Platform org ` +
          `(kid=${existing.keyId}). No action.`,
      );
      return;
    }

    const signingService = new SigningService(prisma, buildEcdsaSigner());
    const key = await signingService.createKeyPair(org.id);

    // createKeyPair's pushKeysToSigner swallows signer errors (it logs but
    // never throws), so a broken/unreachable signer would otherwise leave a
    // DB row the signer can't actually sign with. Verify end-to-end that the
    // configured signer can sign with the new key, and fail loudly if not.
    const probe = `qrauth:oidc-bootstrap-probe:${key.keyId}`;
    const signature = await signingService.signCanonical(key.keyId, probe);
    if (!signingService.verifyCanonical(key.publicKey, signature, probe)) {
      throw new Error(
        `Provisioned SigningKey kid=${key.keyId} but a verification sign did ` +
          `not verify against its public key — investigate the signer before use.`,
      );
    }

    console.log(
      `Provisioned ES256 SigningKey on QRAuth Platform org (kid=${key.keyId}).`,
    );
  } finally {
    await prisma.$disconnect();
  }
}

main().catch((err) => {
  console.error(
    '[bootstrap-platform-oidc-key] FAILED:',
    err instanceof Error ? err.message : err,
  );
  process.exit(1);
});
