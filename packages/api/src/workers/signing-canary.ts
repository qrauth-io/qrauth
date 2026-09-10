import type { PrismaClient } from '@prisma/client';
import { importJWK, flattenedVerify } from 'jose';
import type { SigningService } from '../services/signing.js';
import {
  OIDC_ID_TOKEN_SIGNING_ALGS,
  platformSigningKeyWhere,
  platformJwksKeyWhere,
  type OidcIdTokenAlg,
} from '../lib/oidc-signing-keys.js';
import { signingKeyToJwk } from '../lib/oidc-metadata.js';

/**
 * Signing canary — mechanism 2 of the incident's closure
 * (docs/ops/rs256-repair-runbook.md step 6b; design + Ari's additions
 * approved 2026-09-08). Every hourly cleanup tick, for each algorithm the
 * OP advertises: sign an inert token-shaped payload through the REAL
 * signing path and verify it against the PUBLISHED JWK. This is the drift
 * detector for everything the verify-then-commit rotation probe
 * (mechanism 1) cannot see: the signer losing key material later, backup
 * restores, disk/config drift, out-of-band DB edits.
 *
 * Assertions, separately reported:
 *   (a) the signing kid is present in the set JWKS publishes
 *       (fix 9's signing ⊂ publishing invariant, tested live), and
 *   (b) the JWS verifies under that key's published JWK via
 *       signingKeyToJwk — which also catches PEM→JWK conversion bugs and a
 *       signer holding a private half that doesn't match the row.
 *
 * Three states, anti-flap (mirrors the MAC-signer circuit-breaker posture):
 *   OK     — signed and verified.
 *   STALE  — transport-level failure after in-tick retries (signer
 *            unreachable/timeout). Health stays green until staleness
 *            exceeds STALE_ALARM_AFTER_MS; a signer unreachable that long
 *            is itself alarm-worthy.
 *   FAILED — definitive: no active key, signer key-not-found (4xx),
 *            kid unpublished, or signature invalid. Deterministic — no
 *            debounce beyond one re-resolve retry (guards the race with an
 *            in-flight rotation).
 *
 * State lives in Redis (never per-instance memory — /health answers
 * through a load balancer) under TWO keys:
 *   LATEST — every tick's full result.
 *   STICKY — last DEFINITIVE outcome per algorithm (OK or FAILED, never
 *            STALE). This is what makes "STALE/UNKNOWN never masks a
 *            previously-recorded FAILED" hold: the health evaluation
 *            reports FAILED whenever sticky says so, regardless of what
 *            the latest reading (or its absence) says.
 *
 * The canary JWS is NEVER logged or stored — kid and outcome only.
 */

export const CANARY_LATEST_KEY = 'qrauth:canary:signing:latest';
export const CANARY_STICKY_KEY = 'qrauth:canary:signing:sticky';

/** Transport-STALE and handler-UNKNOWN both alarm after 3 hourly ticks. */
export const STALE_ALARM_AFTER_MS = 3 * 60 * 60 * 1000;
export const UNKNOWN_ALARM_AFTER_MS = 3 * 60 * 60 * 1000;

const SIGN_RETRIES_IN_TICK = 2;

export type CanaryAlgStatus = 'OK' | 'STALE' | 'FAILED';

export interface CanaryAlgResult {
  status: CanaryAlgStatus;
  /** kid the probe signed with (absent when no key could be resolved). */
  kid?: string;
  reason?: string;
  lastSuccessAt?: string;
  /** First tick at which the current STALE streak began. */
  staleSince?: string;
  checkedAt: string;
}

export type CanaryState = Partial<Record<OidcIdTokenAlg, CanaryAlgResult>>;

/** Minimal Redis surface the canary needs — injectable for tests. */
export interface CanaryStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<unknown>;
}

function inertProbeInput(alg: OidcIdTokenAlg, kid: string): string {
  const header = Buffer.from(JSON.stringify({ alg, typ: 'JWT', kid })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({ aud: 'qrauth:canary', probe: 'hourly' }),
  ).toString('base64url');
  return `${header}.${payload}`;
}

/**
 * A thrown sign error is DEFINITIVE (FAILED) when the signer answered and
 * rejected — an HTTP 4xx ("signer returned 4xx" per the Http*Signer message
 * format) or a missing local envelope. Anything else (timeout, connection
 * refused, 5xx) is transport → STALE.
 */
function isDefinitiveSignError(err: Error): boolean {
  return /signer returned 4\d\d/.test(err.message) || /ENOENT/.test(err.message);
}

async function probeAlg(
  db: PrismaClient,
  signingService: SigningService,
  alg: OidcIdTokenAlg,
  previous: CanaryAlgResult | undefined,
  now: Date,
): Promise<CanaryAlgResult> {
  const checkedAt = now.toISOString();
  const carry = { lastSuccessAt: previous?.lastSuccessAt };

  // Resolve the key the signing path would use. Re-resolved on the retry so
  // an in-flight rotation between resolve and sign cannot fake a failure.
  for (let attempt = 0; ; attempt++) {
    const key = await db.signingKey.findFirst({
      where: platformSigningKeyWhere(alg),
      orderBy: { createdAt: 'desc' },
      select: { keyId: true, publicKey: true },
    });
    if (!key) {
      return { status: 'FAILED', reason: 'no_active_key', checkedAt, ...carry };
    }

    const canonicalInput = inertProbeInput(alg, key.keyId);
    let signature: string;
    try {
      signature =
        alg === 'RS256'
          ? await signingService.signRsaJws(key.keyId, canonicalInput)
          : await signingService.signJws(key.keyId, canonicalInput);
    } catch (err) {
      if (attempt < SIGN_RETRIES_IN_TICK) continue;
      if (isDefinitiveSignError(err as Error)) {
        return {
          status: 'FAILED',
          kid: key.keyId,
          reason: `signer_rejected: ${(err as Error).message}`,
          checkedAt,
          ...carry,
        };
      }
      return {
        status: 'STALE',
        kid: key.keyId,
        reason: `signer_unreachable: ${(err as Error).message}`,
        staleSince: previous?.status === 'STALE' && previous.staleSince ? previous.staleSince : checkedAt,
        checkedAt,
        ...carry,
      };
    }

    // (a) the kid must be in the published set.
    const published = await db.signingKey.findMany({
      where: platformJwksKeyWhere(now),
      select: { keyId: true, publicKey: true, algorithm: true },
    });
    const publishedRow = published.find((p) => p.keyId === key.keyId);
    if (!publishedRow) {
      return { status: 'FAILED', kid: key.keyId, reason: 'kid_unpublished', checkedAt, ...carry };
    }

    // (b) the signature must verify under the PUBLISHED JWK.
    try {
      const jwk = await signingKeyToJwk(publishedRow.publicKey, publishedRow.keyId, alg);
      const joseKey = await importJWK(jwk, alg);
      const [protectedHeader, payload] = canonicalInput.split('.');
      await flattenedVerify(
        { protected: protectedHeader, payload, signature },
        joseKey,
        { algorithms: [alg] },
      );
    } catch {
      return {
        status: 'FAILED',
        kid: key.keyId,
        reason: 'signature_invalid_under_published_jwk',
        checkedAt,
        ...carry,
      };
    }

    return { status: 'OK', kid: key.keyId, lastSuccessAt: checkedAt, checkedAt };
  }
}

/**
 * One canary run over every advertised algorithm. Writes LATEST always and
 * updates STICKY on definitive outcomes (OK / FAILED). Never throws for a
 * probe outcome; store failures propagate to the caller's try/catch so a
 * Redis outage is logged, not fatal to the cleanup tick.
 */
export async function runSigningCanary(
  db: PrismaClient,
  signingService: SigningService,
  store: CanaryStore,
  now: Date = new Date(),
): Promise<CanaryState> {
  let previous: CanaryState = {};
  try {
    const raw = await store.get(CANARY_LATEST_KEY);
    if (raw) previous = JSON.parse(raw) as CanaryState;
  } catch {
    /* unreadable previous state — staleSince restarts; acceptable */
  }

  const latest: CanaryState = {};
  for (const alg of OIDC_ID_TOKEN_SIGNING_ALGS) {
    latest[alg] = await probeAlg(db, signingService, alg, previous[alg], now);
    const outcome = latest[alg]!;
    if (outcome.status === 'OK') {
      console.log(`[signing-canary] ${alg} OK (kid ${outcome.kid})`);
    } else {
      console.error(
        `[signing-canary] ${alg} ${outcome.status} (kid ${outcome.kid ?? '-'}): ${outcome.reason}`,
      );
    }
  }

  let sticky: CanaryState = {};
  try {
    const raw = await store.get(CANARY_STICKY_KEY);
    if (raw) sticky = JSON.parse(raw) as CanaryState;
  } catch {
    /* rebuilt below from definitive outcomes */
  }
  for (const alg of OIDC_ID_TOKEN_SIGNING_ALGS) {
    if (latest[alg]!.status !== 'STALE') sticky[alg] = latest[alg];
  }

  await store.set(CANARY_LATEST_KEY, JSON.stringify(latest));
  await store.set(CANARY_STICKY_KEY, JSON.stringify(sticky));
  return latest;
}

// ---------------------------------------------------------------------------
// Health-side evaluation
// ---------------------------------------------------------------------------

export type CanaryHealthStatus = 'ok' | 'stale' | 'failed' | 'unknown';

export interface CanaryHealthView {
  status: CanaryHealthStatus;
  /** True when /health must degrade because of the canary. */
  degrade: boolean;
  reasons: string[];
  perAlg: Partial<Record<OidcIdTokenAlg, { status: CanaryHealthStatus; kid?: string; reason?: string }>>;
}

/**
 * Pure evaluation of canary state for /health. The rules, in priority order:
 *   - FAILED (from latest, OR from sticky when latest is STALE/absent —
 *     STALE and UNKNOWN never mask a recorded FAILED) → degrade now.
 *   - STALE → degrade only once the streak exceeds STALE_ALARM_AFTER_MS.
 *   - UNKNOWN (no readable state; `unknownSince` is the caller's clock for
 *     how long that has been true) → degrade only past
 *     UNKNOWN_ALARM_AFTER_MS. Distinct from STALE: UNKNOWN means WE cannot
 *     read the canary (Redis), STALE means the CANARY cannot reach the
 *     signer — different alarms, different runbooks.
 */
export function evaluateCanaryForHealth(opts: {
  latest: CanaryState | null;
  sticky: CanaryState | null;
  unknownSince: Date | null;
  now: Date;
}): CanaryHealthView {
  const { latest, sticky, now } = opts;
  const reasons: string[] = [];
  const perAlg: CanaryHealthView['perAlg'] = {};

  if (!latest) {
    const unknownFor = opts.unknownSince ? now.getTime() - opts.unknownSince.getTime() : 0;
    // Even with the fresh reading unreadable, a recorded FAILED wins.
    const stickyFailed = OIDC_ID_TOKEN_SIGNING_ALGS.filter(
      (a) => sticky?.[a]?.status === 'FAILED',
    );
    if (stickyFailed.length > 0) {
      for (const a of stickyFailed) {
        perAlg[a] = { status: 'failed', kid: sticky![a]!.kid, reason: sticky![a]!.reason };
        reasons.push(`canary_failed:${a}:${sticky![a]!.reason ?? 'recorded_failure'}`);
      }
      return { status: 'failed', degrade: true, reasons, perAlg };
    }
    const degrade = unknownFor > UNKNOWN_ALARM_AFTER_MS;
    if (degrade) reasons.push('canary_unknown: state unreadable beyond threshold');
    return { status: 'unknown', degrade, reasons, perAlg };
  }

  let worst: CanaryHealthStatus = 'ok';
  let degrade = false;
  for (const alg of OIDC_ID_TOKEN_SIGNING_ALGS) {
    const l = latest[alg];
    if (!l) {
      perAlg[alg] = { status: 'unknown' };
      continue;
    }
    if (l.status === 'FAILED' || (l.status === 'STALE' && sticky?.[alg]?.status === 'FAILED')) {
      const src = l.status === 'FAILED' ? l : sticky![alg]!;
      perAlg[alg] = { status: 'failed', kid: src.kid, reason: src.reason };
      reasons.push(`canary_failed:${alg}:${src.reason ?? 'unspecified'}`);
      worst = 'failed';
      degrade = true;
      continue;
    }
    if (l.status === 'STALE') {
      perAlg[alg] = { status: 'stale', kid: l.kid, reason: l.reason };
      const since = l.staleSince ? new Date(l.staleSince).getTime() : now.getTime();
      if (now.getTime() - since > STALE_ALARM_AFTER_MS) {
        reasons.push(`canary_stale:${alg}: signer unreachable beyond threshold`);
        degrade = true;
      }
      if (worst === 'ok') worst = 'stale';
      continue;
    }
    perAlg[alg] = { status: 'ok', kid: l.kid };
  }

  return { status: worst, degrade, reasons, perAlg };
}
