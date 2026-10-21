import type { PrismaClient } from '@prisma/client';
import { config } from '../lib/config.js';
import type { SigningService } from '../services/signing.js';

/**
 * Signing-key lifecycle steps for the hourly cleanup worker
 * (docs/ops/signing-key-rotation-loop.md).
 *
 * Extracted from the inline body of `createCleanupWorker` so the loop
 * behaviour is directly testable without BullMQ/Redis in the graph.
 */

const DAY_MS = 24 * 60 * 60 * 1000;

export interface StaleKeyRotation {
  organizationId: string;
  staleKeyId: string;
  newKeyId: string;
  algorithm: string;
}

/**
 * Auto-rotate signing keys older than `config.signingKeys.rotationDays`
 * (ISO 27001 A.10.1.2).
 *
 * Rotates BY KEY, not by org: `rotateKeyById` demotes exactly the stale row
 * the query matched and mints a same-algorithm replacement. The previous
 * org-level rotation was defect 2 of the rotation-loop incident — for an org
 * holding more than one ACTIVE key, the stale key was never the key that got
 * rotated, so the trigger condition never cleared and the worker minted one
 * key per hour, forever.
 */
export async function rotateStaleSigningKeys(
  db: PrismaClient,
  signingService: SigningService,
  now: Date = new Date(),
): Promise<StaleKeyRotation[]> {
  const keyRotationCutoff = new Date(now.getTime() - config.signingKeys.rotationDays * DAY_MS);
  const staleKeys = await db.signingKey.findMany({
    where: {
      status: 'ACTIVE',
      createdAt: { lt: keyRotationCutoff },
    },
    select: { organizationId: true, keyId: true, algorithm: true },
  });

  const rotated: StaleKeyRotation[] = [];
  for (const stale of staleKeys) {
    try {
      const newKey = await signingService.rotateKeyById(stale.keyId);
      console.log(
        `[cleanup] Auto-rotated ${stale.algorithm} signing key ${stale.keyId} ` +
          `for org ${stale.organizationId}: ${newKey.keyId}`,
      );
      rotated.push({
        organizationId: stale.organizationId,
        staleKeyId: stale.keyId,
        newKeyId: newKey.keyId,
        algorithm: stale.algorithm,
      });
    } catch (err) {
      console.error(
        `[cleanup] Failed to auto-rotate key ${stale.keyId} for org ${stale.organizationId}:`,
        err,
      );
    }
  }
  return rotated;
}

/**
 * Transition ROTATED signing keys to REVOKED once their grace window
 * (`config.signingKeys.revokeGraceDays`) has elapsed, so JWKS stops serving
 * them and the published key set stays bounded (defect 4 of the incident:
 * nothing ever pruned, so every rotated key stayed in JWKS forever).
 *
 * Status transition only — rows are NEVER deleted (`qr_codes.signingKeyId`
 * is ON DELETE RESTRICT). The grace window covers every status-filtered
 * verifier (see the derivation on SIGNING_KEY_REVOKE_GRACE_DAYS in
 * lib/config.ts).
 *
 * The sweep is UNIFORM — deliberately no qr_codes/signed_batches reference
 * guard. A guard was proposed and rejected before shipping (2026-09-08
 * design note in docs/ops/signing-key-rotation-loop.md): with JWKS
 * publication time-bounded, every status-filtered verifier is bounded far
 * below the 30-day grace (proximity attestations 5 min, auth-session
 * approvals 24 h, ID tokens via the JWKS window), and QR/batch verification
 * resolves keys by FK ignoring status — so REVOKED cannot break anything,
 * while a reference guard would have pinned rows ROTATED forever and
 * permanently muddied the retention-drain signal (`retained` in /health).
 * REVOKED means: excluded from every status-filtered path and from JWKS;
 * FK-resolved historical verification is deliberately unaffected; the row
 * is retained forever as the audit record.
 */
export async function revokeExpiredRotatedKeys(
  db: PrismaClient,
  now: Date = new Date(),
): Promise<{ count: number }> {
  const revokeCutoff = new Date(now.getTime() - config.signingKeys.revokeGraceDays * DAY_MS);
  return db.signingKey.updateMany({
    where: {
      status: 'ROTATED',
      rotatedAt: { lt: revokeCutoff },
    },
    data: { status: 'REVOKED', revokedAt: now },
  });
}
