/**
 * Verify-page trust state: the single decision every verify response
 * (HTML and JSON) is rendered from.
 *
 *   VERIFIED                  signature valid, not revoked or expired, not
 *                             geo-blocked, trust score above the threshold,
 *                             no lookalike destination, and the issuer is
 *                             verified.
 *   SIGNED_UNVERIFIED_ISSUER  the same checks pass, but the issuer is not
 *                             verified. Demo codes (anyone can choose their
 *                             destination) never rise above this state.
 *   UNTRUSTED                 anything else, including every code of a
 *                             suspended organization and every code whose
 *                             destination is flagged by screening.
 */

import { isIssuerVerified, type IssuerVerificationFields } from '@qrauth/shared';

export const TRUST_STATES = ['VERIFIED', 'SIGNED_UNVERIFIED_ISSUER', 'UNTRUSTED'] as const;

export type TrustState = (typeof TRUST_STATES)[number];

/** Trust scores at or below this value make a code UNTRUSTED. */
export const TRUST_SCORE_THRESHOLD = 20;

// The predicate lives in @qrauth/shared, so customer-logo eligibility
// (plans.ts) uses the same definition as the verify page.
export { isIssuerVerified, type IssuerVerificationFields } from '@qrauth/shared';

/** QRCode.source value for codes issued by the demo endpoint. */
export const DEMO_SOURCE = 'demo';

export interface TrustInputs {
  signatureValid: boolean;
  revokedOrExpired: boolean;
  geoBlocked: boolean;
  trustScore: number;
  /** The destination looks like the domain of a different, verified org. */
  lookalikeDestination: boolean;
  /** The issuing organization is suspended by the platform. */
  issuerSuspended: boolean;
  /** Issued by the unauthenticated demo endpoint (QRCode.source = 'demo'). */
  demoCode: boolean;
  /** The destination is flagged as dangerous (QRCode.destinationFlaggedAt). */
  destinationFlagged: boolean;
  issuer: IssuerVerificationFields;
}

export function computeTrustState(input: TrustInputs): TrustState {
  const untrusted =
    !input.signatureValid ||
    input.revokedOrExpired ||
    input.issuerSuspended ||
    input.destinationFlagged ||
    input.geoBlocked ||
    input.trustScore <= TRUST_SCORE_THRESHOLD ||
    input.lookalikeDestination;

  if (untrusted) return 'UNTRUSTED';
  if (input.demoCode) return 'SIGNED_UNVERIFIED_ISSUER';
  return isIssuerVerified(input.issuer) ? 'VERIFIED' : 'SIGNED_UNVERIFIED_ISSUER';
}
