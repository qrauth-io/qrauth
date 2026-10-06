/**
 * OIDC `prompt` request-parameter parsing (ADR-0003 Slice 8).
 *
 * `prompt` is a space-delimited, case-sensitive set of values (OIDC Core
 * §3.1.2.1). Phase 1 acts on two of them at the authorization endpoint:
 *   - `none`  — the OP MUST NOT display any UI; if it can't authenticate
 *               silently it returns `login_required` (§3.1.2.6).
 *   - `login` — the OP MUST re-authenticate the End-User even if a session
 *               exists.
 * `consent` / `select_account` are Phase 2 (consent screen) and are parsed but
 * not acted on here. Unrecognized values are ignored per RFC 6749 §3.1.
 *
 * Pure string parsing — no I/O, no crypto identifiers (AUDIT-FINDING-012 N/A).
 */
export interface PromptDirectives {
  /** `prompt` contained `none` — silent-only; no interactive login. */
  none: boolean;
  /** `prompt` contained `login` — force re-authentication. */
  login: boolean;
  /** All parsed values, in order — used to detect the invalid `none`+other combo. */
  values: string[];
}

export function parsePrompt(raw: string | undefined | null): PromptDirectives {
  const values = (raw ?? '').split(/\s+/).filter(Boolean);
  return {
    none: values.includes('none'),
    login: values.includes('login'),
    values,
  };
}

/**
 * OIDC Core §3.1.2.1: `none` MUST NOT be combined with any other `prompt`
 * value. Returns true when the combination is invalid.
 */
export function isInvalidPromptCombo(p: PromptDirectives): boolean {
  return p.none && p.values.length > 1;
}
