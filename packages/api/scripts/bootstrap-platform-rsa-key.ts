/**
 * One-time bootstrap: provision the QRAuth Platform org's RS256 (RSA-2048)
 * signing key for the OIDC Provider (ADR-0003 Phase 1 Slice 7b).
 *
 * RS256 is mandatory-to-implement per OIDC Core §15.1 — the Config OP
 * conformance run blocked on `id_token_signing_alg_values_supported` lacking
 * RS256. This mints the RSA key through the audited
 * `SigningService.createRsaKeyPair` path — encrypts the private key at rest and
 * pushes it to the standalone signer service, preserving Finding-016 (the API
 * box never serves signatures from local PEM in production; the signer holds
 * the private bytes). JWKS then publishes the RSA public key alongside ES256.
 *
 * IDEMPOTENT: a no-op when an ACTIVE RS256 key already exists on the org.
 * MANUAL ONLY: not wired into migrations, `db:seed`, or `npm run dev`.
 *
 * ORDER: the signer must already carry Slice 7a's `/v1/sign-rsa-jws` AND Slice
 * 7b's `/v1/keys` RSA-envelope support (redeploy the signer first). Run on the
 * prod host (signer reachable):
 *   cd /home/progressnet/vqr/packages/api
 *   npx tsx scripts/bootstrap-platform-rsa-key.ts
 * or, from the repo:
 *   npm run oidc:bootstrap-rsa-key -w packages/api
 *
 * Note: if a run fails at the signer step, the SigningKey row may already
 * exist. Bring the signer up and re-run — this reports the existing key as
 * present. The end-to-end RS256 sign+verify probe below fails loudly if the
 * signer cannot actually sign with the new key.
 */

import { PrismaClient } from '@prisma/client';
import { config } from '../src/lib/config.js';
import { SigningService } from '../src/services/signing.js';
import {
  HttpEcdsaSigner,
  LocalEcdsaSigner,
  type EcdsaSigner,
} from '../src/services/ecdsa-signer/index.js';
import {
  HttpRsaSigner,
  LocalRsaSigner,
  type RsaSigner,
} from '../src/services/rsa-signer/index.js';
import { QRAUTH_PLATFORM_ORG_SLUG } from '../src/lib/oidc-metadata.js';

/** Mirror plugins/ecdsa-signer.ts backend selection (inlined for standalone use). */
function buildEcdsaSigner(): EcdsaSigner {
  if (config.ecdsaSigner.backend === 'http') {
    if (!config.ecdsaSigner.url || !config.ecdsaSigner.token) {
      throw new Error('ECDSA_SIGNER=http requires ECDSA_SIGNER_URL and ECDSA_SIGNER_TOKEN');
    }
    return new HttpEcdsaSigner(config.ecdsaSigner.url, config.ecdsaSigner.token);
  }
  return new LocalEcdsaSigner();
}

/** RSA signer reuses the ECDSA backend decision — same signer host/credentials. */
function buildRsaSigner(): RsaSigner {
  if (config.ecdsaSigner.backend === 'http') {
    if (!config.ecdsaSigner.url || !config.ecdsaSigner.token) {
      throw new Error('ECDSA_SIGNER=http requires ECDSA_SIGNER_URL and ECDSA_SIGNER_TOKEN');
    }
    return new HttpRsaSigner(config.ecdsaSigner.url, config.ecdsaSigner.token);
  }
  return new LocalRsaSigner();
}

function b64url(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
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
          `Run "prisma migrate deploy" first.`,
      );
    }

    const existing = await prisma.signingKey.findFirst({
      where: { organizationId: org.id, algorithm: 'RS256', status: 'ACTIVE' },
      orderBy: { createdAt: 'desc' },
      select: { keyId: true },
    });

    if (existing) {
      console.log(
        `RS256 SigningKey already present on QRAuth Platform org ` +
          `(kid=${existing.keyId}). No action.`,
      );
      return;
    }

    const signingService = new SigningService(prisma, buildEcdsaSigner(), buildRsaSigner());
    const key = await signingService.createRsaKeyPair(org.id);

    // createRsaKeyPair's pushRsaKeyToSigner swallows signer errors (logs, never
    // throws), so a broken/unreachable signer would otherwise leave a DB row
    // the signer can't sign with. Probe end-to-end that the configured signer
    // can produce an RS256 JWS signature that verifies against the public key.
    const canonicalInput = `${b64url({ alg: 'RS256', typ: 'JWT', kid: key.keyId })}.${b64url({
      probe: key.keyId,
    })}`;
    const signature = await signingService.signRsaJws(key.keyId, canonicalInput);
    if (!(await signingService.verifyRsaJws(key.publicKey, canonicalInput, signature))) {
      throw new Error(
        `Provisioned RS256 SigningKey kid=${key.keyId} but an RS256 verification ` +
          `sign did not verify against its public key — investigate the signer before use.`,
      );
    }

    console.log(
      `Provisioned RS256 SigningKey on QRAuth Platform org (kid=${key.keyId}).`,
    );
  } finally {
    await prisma.$disconnect();
  }
}

main().catch((err) => {
  console.error(
    '[bootstrap-platform-rsa-key] FAILED:',
    err instanceof Error ? err.message : err,
  );
  process.exit(1);
});
