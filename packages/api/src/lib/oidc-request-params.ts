/**
 * Shape checks for the parameters /authorize and /token read (audit 2026-10
 * FINDING-021). Each must be a single string of bounded length; two have a
 * fixed format. A repeated parameter arrives as an array and is refused,
 * instead of reaching `.split()` or a database lookup and ending in a 500.
 *
 * Parameters the endpoints do not read (ui_locales, login_hint, anything
 * unknown) are left alone: RFC 6749 §3.1 says to ignore them.
 *
 * Every function returns null when the parameters are acceptable, otherwise
 * a short description safe to put in `error_description`.
 */

interface Rule {
  maxLength: number;
  /** Full-match format, when the parameter has one. */
  pattern?: RegExp;
  /** Said when the pattern does not match. */
  format?: string;
}

type Params = Record<string, unknown>;

/** S256 challenge: base64url of a SHA-256 digest, always 43 characters (RFC 7636 §4.2). */
const CODE_CHALLENGE = /^[A-Za-z0-9_-]{43}$/;
/** RFC 7636 §4.1: 43 to 128 characters from the unreserved set. */
const CODE_VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;

const AUTHORIZE_CLIENT_RULES: Record<string, Rule> = {
  client_id: { maxLength: 256 },
  redirect_uri: { maxLength: 2048 },
};

const AUTHORIZE_RULES: Record<string, Rule> = {
  response_type: { maxLength: 64 },
  scope: { maxLength: 1024 },
  state: { maxLength: 4096 },
  nonce: { maxLength: 1024 },
  prompt: { maxLength: 128 },
  max_age: { maxLength: 16 },
  code_challenge: { maxLength: 43, pattern: CODE_CHALLENGE, format: '43 base64url characters' },
  code_challenge_method: { maxLength: 16 },
};

const TOKEN_RULES: Record<string, Rule> = {
  grant_type: { maxLength: 64 },
  code: { maxLength: 512 },
  redirect_uri: { maxLength: 2048 },
  code_verifier: { maxLength: 128, pattern: CODE_VERIFIER, format: '43 to 128 unreserved characters' },
  refresh_token: { maxLength: 512 },
  scope: { maxLength: 1024 },
  client_id: { maxLength: 256 },
  client_secret: { maxLength: 512 },
};

function check(params: Params, rules: Record<string, Rule>): string | null {
  for (const [name, rule] of Object.entries(rules)) {
    const value = params[name];
    // The handlers treat an empty value as absent; so does this.
    if (value === undefined || value === '') continue;
    if (Array.isArray(value)) return `${name} must not be repeated`;
    if (typeof value !== 'string') return `${name} must be a string`;
    if (value.length > rule.maxLength) return `${name} is too long`;
    if (rule.pattern && !rule.pattern.test(value)) return `${name} must be ${rule.format}`;
  }
  return null;
}

/**
 * `client_id` and `redirect_uri`, checked first: until they are known to be
 * a registered pair, an error is shown directly and never redirected.
 */
export const checkAuthorizeClientParams = (params: Params): string | null => check(params, AUTHORIZE_CLIENT_RULES);

/** The remaining /authorize parameters; a failure redirects with invalid_request. */
export const checkAuthorizeParams = (params: Params): string | null => check(params, AUTHORIZE_RULES);

/** /token body parameters, both grants. */
export const checkTokenParams = (params: Params): string | null => check(params, TOKEN_RULES);
