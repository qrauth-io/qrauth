/**
 * Issuer verification: whether QRAuth vouches for who an organization is.
 * The verify page shows VERIFIED only for codes of a verified issuer
 * (api/src/services/trust-state.ts), and customer logos need one too
 * (plans.ts, ADR-0005 D9 amendment of 2026-10-29).
 */

export interface IssuerVerificationFields {
  domainVerified: boolean;
  kycStatus: string;
}

/**
 * An issuer is verified when its domain is verified (DNS TXT, or the
 * superadmin override) or its KYC review was approved. UNDER_REVIEW and
 * every other KYC status do not count, and neither does trustLevel on its own.
 */
export function isIssuerVerified(org: IssuerVerificationFields): boolean {
  return org.domainVerified === true || org.kycStatus === 'VERIFIED';
}
