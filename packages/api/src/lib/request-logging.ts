import type { FastifyInstance, FastifyRequest } from 'fastify';

// ---------------------------------------------------------------------------
// Request logging with secrets removed from query strings
// ---------------------------------------------------------------------------

const REDACTED = '[REDACTED]';
const SLOW_REQUEST_MS = 1000;

/**
 * Query parameters whose VALUES must never reach the logs: OAuth
 * authorization codes and state, tokens, and client secrets. Matched on the
 * whole key, case-insensitively, so every entry is lowercase.
 */
const SECRET_QUERY_KEYS: ReadonlySet<string> = new Set([
  'code',
  'state',
  'id_token',
  'access_token',
  'refresh_token',
  'token',
  'client_secret',
  // Audit 2026-10 FINDING-013.
  'code_verifier',
  'id_token_hint',
  'client_assertion',
  // OAuth start from the hosted approval page: whoever holds it can approve
  // that sign-in. Stored lowercase: keys are compared lowercased.
  'authsessiontoken',
  // OIDC /authorize: the RP's replay-protection value and a user identifier.
  'nonce',
  'login_hint',
]);

/**
 * Routes that carry a bearer secret in the path: whoever holds the segment
 * can claim the ephemeral session, verify the address, accept the invitation
 * or approve the sign-in. Each pattern captures what precedes and what
 * follows the secret segment. Public identifiers (QR tokens, session ids)
 * are deliberately not listed.
 */
const SECRET_PATH_PATTERNS: readonly RegExp[] = [
  /^(\/api\/v1\/ephemeral\/)[^/]+(\/claim\/?)$/,
  /^(\/api\/v1\/auth\/verify-email\/)[^/]+(\/?)$/,
  /^(\/api\/v1\/organizations\/invitations\/)[^/]+(\/accept\/?)$/,
  /^(\/api\/v1\/auth-sessions\/)as_[^/]+(\/(?:approve|deny)\/?)$/,
  /^(\/a\/)as_[^/]+(\/?)$/,
];

/** The path with a secret segment replaced, or the path itself. */
function redactPath(path: string): string {
  for (const pattern of SECRET_PATH_PATTERNS) {
    if (pattern.test(path)) return path.replace(pattern, `$1${REDACTED}$2`);
  }
  return path;
}

/** A raw query key, percent-decoded and lowercased for comparison. */
function normalizeKey(rawKey: string): string {
  let key = rawKey;
  try {
    key = decodeURIComponent(rawKey.replace(/\+/g, ' '));
  } catch {
    // Malformed encoding: compare the raw key.
  }
  return key.toLowerCase();
}

function isSecretKey(rawKey: string): boolean {
  return SECRET_QUERY_KEYS.has(normalizeKey(rawKey));
}

/**
 * `returnTo` carries a whole relative URL; on the OP host that is the
 * encoded /authorize request, with the RP's state and nonce in it.
 */
const NESTED_URL_KEY = 'returnto';

/** The raw query string with each secret key's value replaced; order and encoding kept. */
function redactQueryString(query: string, redactNested: boolean): string {
  return query
    .split('&')
    .map((pair) => {
      const separator = pair.indexOf('=');
      if (separator === -1 || separator === pair.length - 1) return pair;
      const key = pair.slice(0, separator);
      if (isSecretKey(key)) return `${key}=${REDACTED}`;
      if (redactNested && normalizeKey(key) === NESTED_URL_KEY) {
        return `${key}=${redactEncodedReturnTo(pair.slice(separator + 1))}`;
      }
      return pair;
    })
    .join('&');
}

/**
 * A decoded relative URL (`/path?query`) with its secret query values
 * replaced, or null when it is not one: absolute or protocol-relative URLs,
 * and values without a query string, are left alone. One level deep only.
 */
function redactRelativeUrlQuery(value: string): string | null {
  if (!value.startsWith('/') || value.startsWith('//')) return null;
  const queryStart = value.indexOf('?');
  if (queryStart === -1) return null;
  return `${value.slice(0, queryStart)}?${redactQueryString(value.slice(queryStart + 1), false)}`;
}

/** An encoded `returnTo` value with nested secrets redacted; unchanged if it cannot be parsed. */
function redactEncodedReturnTo(rawValue: string): string {
  try {
    const decoded = decodeURIComponent(rawValue.replace(/\+/g, ' '));
    const redacted = redactRelativeUrlQuery(decoded);
    // Nothing secret inside: keep the value byte-for-byte as received.
    return redacted === null || redacted === decoded ? rawValue : encodeURIComponent(redacted);
  } catch {
    return rawValue;
  }
}

/**
 * The URL with secrets replaced by `[REDACTED]`: the values of secret query
 * parameters, the secret segment of the paths listed above, and secret query
 * values inside a relative `returnTo` URL. Everything else, including
 * parameter order, is left exactly as received.
 */
export function redactUrl(url: string): string {
  const queryStart = url.indexOf('?');
  if (queryStart === -1) return redactPath(url);

  const query = redactQueryString(url.slice(queryStart + 1), true);
  return `${redactPath(url.slice(0, queryStart))}?${query}`;
}

/**
 * Route parameters for a log line: `token` is replaced when the URL is one
 * whose path carries a secret, since that parameter is the secret.
 */
export function redactParams<T>(params: T, url: string): T {
  if (params === null || typeof params !== 'object') return params;
  const path = url.split('?')[0];
  if (redactPath(path) === path || !('token' in params)) return params;
  return { ...params, token: REDACTED };
}

/** A copy of a parsed query object with secret values replaced, including inside `returnTo`. */
export function redactQuery<T>(query: T): T {
  if (query === null || typeof query !== 'object') return query;
  return Object.fromEntries(
    Object.entries(query).map(([key, value]) => {
      const normalized = key.toLowerCase();
      if (SECRET_QUERY_KEYS.has(normalized)) return [key, REDACTED];
      // Parsed values are already decoded, so no re-encoding here.
      if (normalized === NESTED_URL_KEY && typeof value === 'string') {
        return [key, redactRelativeUrlQuery(value) ?? value];
      }
      return [key, value];
    }),
  ) as T;
}

/**
 * Fastify's default `req` serializer with the URL redacted. It serializes
 * anything logged under the `req` key: the request Fastify logs for
 * "incoming request", and the plain object the error handler logs.
 */
export const requestLogSerializers = {
  req(request: FastifyRequest) {
    const version = request.headers?.['accept-version'];
    return {
      method: request.method,
      url: typeof request.url === 'string' ? redactUrl(request.url) : request.url,
      version: Array.isArray(version) ? version.join(',') : version,
      host: request.host,
      remoteAddress: request.ip,
      remotePort: request.socket?.remotePort,
    };
  },
};

/**
 * Request / response lifecycle hooks for observability, plus the not-found
 * handler. Bodies are never logged.
 */
export function registerRequestLogHooks(app: FastifyInstance): void {
  app.addHook('onRequest', (request, _reply, done) => {
    const url = redactUrl(request.url);
    request.log.info(
      {
        method: request.method,
        url,
        orgId: request.user?.orgId,
      },
      `${request.method} ${url}`,
    );
    done();
  });

  app.addHook('onResponse', (request, reply, done) => {
    const elapsed = reply.elapsedTime;
    // Only log non-2xx responses and requests that took longer than 1 second,
    // to keep steady-state logs clean.
    if (reply.statusCode >= 400 || elapsed > SLOW_REQUEST_MS) {
      const url = redactUrl(request.url);
      request.log.warn(
        {
          method: request.method,
          url,
          statusCode: reply.statusCode,
          responseTime: Math.round(elapsed),
          userId: request.user?.id,
          orgId: request.user?.orgId,
        },
        `${request.method} ${url} → ${reply.statusCode} (${Math.round(elapsed)}ms)`,
      );
    }
    done();
  });

  // Fastify's built-in 404 handler logs the raw URL. Same response, redacted log line.
  app.setNotFoundHandler((request, reply) => {
    const { method, url } = request.raw;
    request.log.info(`Route ${method}:${redactUrl(url ?? '')} not found`);
    return reply.status(404).send({
      message: `Route ${method}:${url} not found`,
      error: 'Not Found',
      statusCode: 404,
    });
  });
}
