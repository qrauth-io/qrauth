import { createHmac } from 'node:crypto';

/** Minimum HMAC key length for pairwise `sub` derivation: 256 bits. */
const MIN_PAIRWISE_SECRET_BYTES = 32;

/**
 * Thrown by {@link computePairwiseSub} when no usable `OIDC_PAIRWISE_SECRET`
 * is configured (unset, or shorter than 32 bytes).
 *
 * Callers should treat this as a 503-class condition — OIDC routes refuse to
 * issue ID tokens but the rest of the API stays up. This is deliberately a
 * call-time failure, not a boot-time one: the foundation must never brick a
 * vqr-api restart before any consumer of the secret exists.
 */
export class OidcPairwiseSecretMissingError extends Error {
  constructor() {
    super(
      'OIDC_PAIRWISE_SECRET is not configured (unset or < 32 bytes). The OIDC ' +
        'provider cannot issue ID tokens until it is set. Generate with ' +
        '`openssl rand -base64 32` and add it to the API environment.',
    );
    this.name = 'OidcPairwiseSecretMissingError';
  }
}

/**
 * Pairwise subject identifier derivation (ADR-0003 §"Subject identifier —
 * pairwise pseudonymous", Slice 3b).
 *
 * Each RP sector sees a different, stable, opaque `sub` for the same QRAuth
 * user — so two RPs cannot correlate the same person across services by
 * comparing `sub` values. The value is deterministic (same inputs → same
 * output, forever) so a returning user keeps the same `sub` at a given RP.
 *
 * `HMAC-SHA256(pairwiseSecret, sectorIdentifier + '|' + userId)`, base64url
 * with no padding. The `|` delimiter is mandatory: without it,
 * (sector="ab", user="cd") and (sector="a", user="bcd") would hash the same
 * bytes and collide. `|` cannot appear in a hostname or a cuid, so the two
 * fields can never be ambiguously concatenated.
 *
 * Validation is LAZY: `pairwiseSecret` (from `config.oidc.pairwiseSecret`) may
 * be `undefined` when the operator hasn't set the secret yet. In that case
 * this throws {@link OidcPairwiseSecretMissingError} — a 503-class condition
 * the OIDC routes surface as "cannot issue ID tokens", leaving the rest of
 * the API running.
 */
export function computePairwiseSub(args: {
  userId: string;
  /** RP sector — e.g. "localhost:9000" or "claims.onlineinsuranceservices.gr". */
  sectorIdentifier: string;
  /** Raw HMAC key (>= 32 bytes), from config.oidc.pairwiseSecret; may be undefined. */
  pairwiseSecret: Buffer | undefined | null;
}): string {
  const { userId, sectorIdentifier, pairwiseSecret } = args;
  if (!pairwiseSecret || pairwiseSecret.length < MIN_PAIRWISE_SECRET_BYTES) {
    throw new OidcPairwiseSecretMissingError();
  }
  return createHmac('sha256', pairwiseSecret)
    .update(`${sectorIdentifier}|${userId}`, 'utf8')
    .digest('base64url');
}
