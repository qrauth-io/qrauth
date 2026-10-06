import type { FastifyInstance, FastifyRequest } from 'fastify';

// ---------------------------------------------------------------------------
// Request logging with secrets removed from query strings
// ---------------------------------------------------------------------------

const REDACTED = '[REDACTED]';
const SLOW_REQUEST_MS = 1000;

/**
 * Query parameters whose VALUES must never reach the logs: OAuth
 * authorization codes and state, tokens, and client secrets. Matched on the
 * whole key, case-insensitively.
 */
const SECRET_QUERY_KEYS: ReadonlySet<string> = new Set([
  'code',
  'state',
  'id_token',
  'access_token',
  'refresh_token',
  'token',
  'client_secret',
]);

function isSecretKey(rawKey: string): boolean {
  let key = rawKey;
  try {
    key = decodeURIComponent(rawKey.replace(/\+/g, ' '));
  } catch {
    // Malformed encoding: compare the raw key.
  }
  return SECRET_QUERY_KEYS.has(key.toLowerCase());
}

/**
 * The URL with the values of secret query parameters replaced by
 * `[REDACTED]`. The path, the parameter order and every other parameter are
 * left exactly as received.
 */
export function redactUrl(url: string): string {
  const queryStart = url.indexOf('?');
  if (queryStart === -1) return url;

  const query = url.slice(queryStart + 1);
  const redacted = query
    .split('&')
    .map((pair) => {
      const separator = pair.indexOf('=');
      if (separator === -1 || separator === pair.length - 1) return pair;
      const key = pair.slice(0, separator);
      return isSecretKey(key) ? `${key}=${REDACTED}` : pair;
    })
    .join('&');

  return `${url.slice(0, queryStart + 1)}${redacted}`;
}

/** A copy of a parsed query object with secret values replaced. */
export function redactQuery<T>(query: T): T {
  if (query === null || typeof query !== 'object') return query;
  return Object.fromEntries(
    Object.entries(query).map(([key, value]) => [key, SECRET_QUERY_KEYS.has(key.toLowerCase()) ? REDACTED : value]),
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
