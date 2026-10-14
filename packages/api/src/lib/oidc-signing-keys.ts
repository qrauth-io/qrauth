import type { Prisma, PrismaClient } from '@prisma/client';
import { config } from './config.js';

/**
 * The two views of the OP keystore, derived from ONE place so they can only
 * diverge deliberately (docs/ops/signing-key-rotation-loop.md, fix 9).
 *
 * - SIGNING (ID-token minting): ACTIVE keys only, per algorithm. A ROTATED
 *   key must never sign a new token.
 * - PUBLISHING (JWKS): ACTIVE keys, plus ROTATED keys inside the
 *   TIME-BOUNDED publication window (config.signingKeys.jwksWindowHours,
 *   floor-validated at boot against the ID-token lifetime). Publication is
 *   deliberately keyed off TIME, not row status: retention ("may this row
 *   be revoked?") and publication ("should RPs still see this key?") are
 *   different questions, and keying JWKS off status is how the key set
 *   grew to 228 unbounded (2026-09-08 design note in
 *   docs/ops/signing-key-rotation-loop.md). JWKS's only consumer class is
 *   OIDC RPs verifying ID tokens (1 h lifetime) — every other verifier
 *   resolves keys via direct DB lookups or FK relations — so a key rotated
 *   longer than the window ago has no verification consumer left,
 *   whatever its retention status. OIDC Core §10.1.1 prescribes exactly
 *   this: retain "recently decommissioned" keys "for a reasonable period",
 *   then remove them.
 *
 * The signing set is therefore a strict SUBSET of the publishing set — that
 * asymmetry is correct and required. What the incident exposed was code
 * commenting the two sets as identical, which turned a
 * published-but-unsignable RS256 key into a confusing 503 instead of an
 * alert.
 */

/**
 * Stable slug of the QRAuth Platform system org (provisioned by migration
 * 20260521120100_provision_qrauth_cli_app). The OP signs every ID token
 * with this org's SigningKeys, and JWKS publishes only its keys — one
 * issuer, one key set (ADR-0003).
 */
export const QRAUTH_PLATFORM_ORG_SLUG = 'qrauth-platform';

/**
 * ID-token signing algorithms the OP advertises in
 * `id_token_signing_alg_values_supported` (ADR-0003 Slice 7b: RS256 first —
 * the default, OIDC Core §15.1 mandatory baseline; ES256 for opt-in
 * clients). Discovery, JWKS, and the key health check all derive from this
 * single list.
 */
export const OIDC_ID_TOKEN_SIGNING_ALGS = ['RS256', 'ES256'] as const;

export type OidcIdTokenAlg = (typeof OIDC_ID_TOKEN_SIGNING_ALGS)[number];

/**
 * Where-clause selecting the platform key allowed to SIGN new ID tokens of
 * the given algorithm: ACTIVE only. Callers pair this with
 * `orderBy: { createdAt: 'desc' }` (the partial unique index on
 * (organizationId, algorithm) WHERE status = 'ACTIVE' makes the row unique;
 * the ordering is a belt-and-braces tiebreak).
 */
export function platformSigningKeyWhere(algorithm: OidcIdTokenAlg): Prisma.SigningKeyWhereInput {
  return {
    organization: { slug: QRAUTH_PLATFORM_ORG_SLUG },
    algorithm,
    status: 'ACTIVE',
  };
}

/** Publication cutoff for `now`: ROTATED keys older than this are not served. */
export function jwksPublicationCutoff(now: Date = new Date()): Date {
  return new Date(now.getTime() - config.signingKeys.jwksWindowHours * 60 * 60 * 1000);
}

/**
 * Where-clause selecting every platform key JWKS PUBLISHES for verification:
 * ACTIVE keys, plus ROTATED keys whose rotation is inside the publication
 * window. REVOKED keys and long-rotated keys are excluded — JWKS is bounded
 * by construction (steady state: one ACTIVE key per advertised algorithm,
 * plus at most a rotation event's worth of recently-rotated keys),
 * regardless of any retention policy. `rotatedAt` is guaranteed non-null
 * for ROTATED rows by the CHECK constraint
 * `signing_keys_rotated_requires_rotatedat` (raw migration
 * 20260908120000) — a null here would silently unpublish the key, so the
 * invalid state is made unrepresentable instead of handled in the query.
 */
export function platformJwksKeyWhere(now: Date = new Date()): Prisma.SigningKeyWhereInput {
  return {
    organization: { slug: QRAUTH_PLATFORM_ORG_SLUG },
    algorithm: { in: [...OIDC_ID_TOKEN_SIGNING_ALGS] },
    OR: [
      { status: 'ACTIVE' },
      { status: 'ROTATED', rotatedAt: { gte: jwksPublicationCutoff(now) } },
    ],
  };
}

/**
 * Runtime secrets the advertised OP surface cannot function without. A
 * missing one does NOT crash boot (deliberate — see the lazy-validation
 * rationale in lib/config.ts) but silently turns every /token call into a
 * 503; that exact gap is how the OIDC happy path went untested in CI while
 * the RS256 key demotion shipped (docs/ops/signing-key-rotation-loop.md).
 * /health folds this into the same degraded/503 failure mode as the
 * signing-key check so the absence is loud everywhere, including the E2E
 * web-server readiness gate.
 *
 * Pure function: callers pass the values so this module stays config-free
 * and trivially testable.
 *
 * - `pairwiseSecret` — required in EVERY environment that serves /token
 *   (no fallback exists; unset → 503 "OP not fully provisioned").
 * - `signerMasterKey` — required in production only; the dev/test
 *   per-process-random fallback is by design but unfit for prod
 *   (pentest F-006, .pentest/findings/auth.md).
 */
export function checkOidcRuntimeSecrets(opts: {
  pairwiseSecret: Buffer | undefined;
  signerMasterKey: string | undefined;
  requireSignerMasterKey: boolean;
}): string[] {
  const missing: string[] = [];
  if (!opts.pairwiseSecret || opts.pairwiseSecret.length === 0) {
    missing.push('OIDC_PAIRWISE_SECRET');
  }
  if (opts.requireSignerMasterKey && !opts.signerMasterKey) {
    missing.push('SIGNER_MASTER_KEY');
  }
  return missing;
}

export interface PlatformSigningKeyHealth {
  healthy: boolean;
  /** Advertised algorithms with key rows but NO ACTIVE row — always a failure. */
  missing: OidcIdTokenAlg[];
  /**
   * Advertised algorithms with no key rows at all. A failure in production;
   * informational in dev/test where the platform org may simply not have
   * been bootstrapped yet.
   */
  unprovisioned: OidcIdTokenAlg[];
  /**
   * Number of keys JWKS currently publishes: ACTIVE, plus ROTATED inside
   * the time-bounded publication window. Bounded by construction — steady
   * state is one key per advertised algorithm (2–3 during a rotation
   * event). A larger number means keys are being minted abnormally fast.
   */
  published: number;
  /**
   * Number of ROTATED rows regardless of age — the RETENTION observable.
   * This is the count that must drain to zero as the worker's grace-window
   * pruning (revokeExpiredRotatedKeys) moves rows to REVOKED; a `retained`
   * that stops decreasing means the pruning is not running
   * (rs256-repair-runbook.md step 7). Kept separate from `published`
   * because publication is time-keyed and says nothing about retention.
   */
  retained: number;
  /**
   * ACTIVE keys whose age exceeds SIGNING_KEY_ROTATION_DAYS plus the
   * overdue grace (config.signingKeys.rotationOverdueGraceDays). Always a
   * failure: rotation is either aborting repeatedly (e.g. the
   * verify-then-commit probe failing every hourly retry) or not firing at
   * all. Deliberately a pure DB-age check with no dependency on the
   * canary, the signer, or Redis — an unwatched abort loop is precisely
   * how the original incident ran for 9.5 days (2026-09-08 addition,
   * ISO 27001 A.10.1.2).
   */
  overdue: Array<{ keyId: string; algorithm: OidcIdTokenAlg; ageDays: number }>;
}

/**
 * Health check for the OP keystore (docs/ops/signing-key-rotation-loop.md,
 * fix 8): every algorithm advertised in
 * `id_token_signing_alg_values_supported` must have >= 1 ACTIVE platform
 * key, otherwise /token 503s for clients registered with that algorithm.
 *
 * This is the check that would have caught the incident on day one: the
 * platform org's only RS256 key was demoted to ROTATED (rows present, none
 * ACTIVE) and nothing alerted until a relying party hit the 503.
 *
 * `requireProvisioned` controls how "no rows at all for this algorithm" is
 * scored: in production a fully provisioned OP losing all rows of an
 * advertised algorithm is exactly as broken as a demoted key, but dev/CI
 * environments run without the bootstrap scripts and must not report a
 * permanently degraded /health.
 */
export async function checkPlatformSigningKeyHealth(
  prisma: PrismaClient,
  opts: { requireProvisioned: boolean },
): Promise<PlatformSigningKeyHealth> {
  const rows = await prisma.signingKey.findMany({
    where: {
      organization: { slug: QRAUTH_PLATFORM_ORG_SLUG },
      algorithm: { in: [...OIDC_ID_TOKEN_SIGNING_ALGS] },
    },
    select: { keyId: true, algorithm: true, status: true, rotatedAt: true, createdAt: true },
  });

  const missing: OidcIdTokenAlg[] = [];
  const unprovisioned: OidcIdTokenAlg[] = [];
  for (const alg of OIDC_ID_TOKEN_SIGNING_ALGS) {
    const algRows = rows.filter((r) => r.algorithm === alg);
    if (algRows.length === 0) {
      unprovisioned.push(alg);
    } else if (!algRows.some((r) => r.status === 'ACTIVE')) {
      missing.push(alg);
    }
  }

  // Same publication rule as platformJwksKeyWhere — one source of truth for
  // "what does JWKS serve" (fix 9), evaluated here over the fetched rows.
  const cutoff = jwksPublicationCutoff();
  const published = rows.filter(
    (r) =>
      r.status === 'ACTIVE' ||
      (r.status === 'ROTATED' && r.rotatedAt !== null && r.rotatedAt >= cutoff),
  ).length;
  const retained = rows.filter((r) => r.status === 'ROTATED').length;

  const DAY_MS = 24 * 60 * 60 * 1000;
  const overdueCutoff = new Date(
    Date.now() -
      (config.signingKeys.rotationDays + config.signingKeys.rotationOverdueGraceDays) * DAY_MS,
  );
  const overdue = rows
    .filter((r) => r.status === 'ACTIVE' && r.createdAt < overdueCutoff)
    .map((r) => ({
      keyId: r.keyId,
      algorithm: r.algorithm as OidcIdTokenAlg,
      ageDays: Math.floor((Date.now() - r.createdAt.getTime()) / DAY_MS),
    }));

  const healthy =
    missing.length === 0 &&
    overdue.length === 0 &&
    (!opts.requireProvisioned || unprovisioned.length === 0);
  return { healthy, missing, unprovisioned, published, retained, overdue };
}
