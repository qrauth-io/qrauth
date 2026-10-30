/**
 * Classify the `error` / `error_description` a provider sends back to the
 * OAuth callback instead of a `code`.
 *
 * Microsoft: a tenant that does not let users consent to apps on their own
 * answers with `consent_required` and/or an AADSTS code in the description
 * (65001 no consent yet, 90094 / 90095 admin approval required). Those users
 * cannot fix it themselves, so they get their own message pointing at their
 * administrator instead of the generic failure.
 */

export type ProviderErrorOutcome = 'microsoft_admin_consent' | 'cancelled' | 'failed';

export interface ClassifiedProviderError {
  outcome: ProviderErrorOutcome;
  /** Provider `error` value, only when it is a plain OAuth error token. */
  error?: string;
  /** Digits of the AADSTS code found in `error_description` (Microsoft only). */
  aadstsCode?: string;
}

// The AADSTS number only, never the rest of the description (it can carry
// tenant names, user names and trace ids).
const AADSTS_CODE_RE = /AADSTS(\d{1,8})(?!\d)/;
const ADMIN_CONSENT_AADSTS_CODES: ReadonlySet<string> = new Set(['65001', '90094', '90095']);
// OAuth 2.0 error codes are short ASCII tokens (RFC 6749 §4.1.2.1).
const ERROR_TOKEN_RE = /^[a-z0-9_]{1,64}$/i;

function asString(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

export function extractAadstsCode(errorDescription: unknown): string | undefined {
  return AADSTS_CODE_RE.exec(asString(errorDescription))?.[1];
}

export function classifyProviderError(
  provider: string,
  error: unknown,
  errorDescription: unknown,
): ClassifiedProviderError {
  const errorValue = asString(error);
  const safeError = ERROR_TOKEN_RE.test(errorValue) ? errorValue : undefined;
  const aadstsCode = provider === 'microsoft' ? extractAadstsCode(errorDescription) : undefined;
  const details = {
    ...(safeError ? { error: safeError } : {}),
    ...(aadstsCode ? { aadstsCode } : {}),
  };

  const needsAdminConsent =
    provider === 'microsoft' &&
    (errorValue === 'consent_required' || (aadstsCode !== undefined && ADMIN_CONSENT_AADSTS_CODES.has(aadstsCode)));
  if (needsAdminConsent) return { outcome: 'microsoft_admin_consent', ...details };
  if (errorValue === 'access_denied') return { outcome: 'cancelled', ...details };
  return { outcome: 'failed', ...details };
}
